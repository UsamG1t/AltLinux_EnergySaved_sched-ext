/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <math.h>
#include <scx/common.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "scx_stairs.bpf.skel.h"

#define ISOLATED_START 6
#define ISOLATED_END 9
#define NR_ISOLATED_CPUS (ISOLATED_END - ISOLATED_START + 1)
#define STAIRS_COMM_LEN 16
#define MAX_TIME_IN_STATE_STEPS 64

#define LOG_DIR "/tmp/scx_stairs"
#define LOG_CSV_PATH LOG_DIR "/latest.csv"
#define LOG_META_PATH LOG_DIR "/latest.meta"
#define CPUFREQ_BOOST_PATH "/sys/devices/system/cpu/cpufreq/boost"

static int isolated_cpus[NR_ISOLATED_CPUS];

const char help_fmt[] =
"A stairs sched_ext scheduler.\n"
"\n"
"Usage: %s [-f interval_sec] [-v]\n"
"\n"
"  -f <sec>      Frequency sampling period in seconds (default: 1.0)\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

struct cpu_freq_reader {
	int cpu;
	int fd;
	char path[PATH_MAX];
};

struct cpu_tis_reader {
	int cpu;
	int fd;
	size_t nr_entries;
	long freqs_khz[MAX_TIME_IN_STATE_STEPS];
	unsigned long long prev_ticks[MAX_TIME_IN_STATE_STEPS];
	bool have_prev;
	char path[PATH_MAX];
};

struct boost_state {
	bool supported;
	bool changed;
	long original_value;
};

enum stairs_debug_event {
	STAIRS_DEBUG_NONE = 0,
	STAIRS_DEBUG_VAR_RUNNING = 1,
	STAIRS_DEBUG_NONVAR_RUNNING_ZERO = 2,
	STAIRS_DEBUG_STOPPING_ZERO = 3,
	STAIRS_DEBUG_IDLE_ZERO = 4,
};

struct stairs_debug_cpu_state {
	__u64 running_var_hits;
	__u64 running_nonvar_hits;
	__u64 perf_apply_hits;
	__u64 zero_from_running_hits;
	__u64 zero_from_stopping_hits;
	__u64 zero_from_idle_hits;
	__u32 last_event;
	__u32 last_perf;
	__u32 last_var_step_idx;
	__u32 last_var_freq_khz;
	__u32 last_var_pid;
	__u32 last_var_tgid;
	char last_var_comm[STAIRS_COMM_LEN];
	__u32 last_actor_pid;
	__u32 last_actor_tgid;
	char last_actor_comm[STAIRS_COMM_LEN];
};

static bool verbose;
static volatile sig_atomic_t exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int stairs)
{
	exit_req = 1;
}

static const char *debug_event_name(__u32 event)
{
	switch (event) {
	case STAIRS_DEBUG_VAR_RUNNING:
		return "var";
	case STAIRS_DEBUG_NONVAR_RUNNING_ZERO:
		return "run0";
	case STAIRS_DEBUG_STOPPING_ZERO:
		return "stop0";
	case STAIRS_DEBUG_IDLE_ZERO:
		return "idle0";
	default:
		return "-";
	}
}

static void format_task_comm(const char src[STAIRS_COMM_LEN], char *dst, size_t size)
{
	size_t i;

	if (!size)
		return;

	for (i = 0; i + 1 < size && i < STAIRS_COMM_LEN && src[i]; i++)
		dst[i] = src[i];
	dst[i] = '\0';

	if (!dst[0]) {
		dst[0] = '-';
		dst[1] = '\0';
	}
}

static void init_isolated_cpus(void)
{
	int i;

	for (i = 0; i < NR_ISOLATED_CPUS; i++)
		isolated_cpus[i] = ISOLATED_START + i;
}

static void init_monitor_reader_state(struct cpu_tis_reader *tis_readers,
				      struct cpu_freq_reader *scaling_readers,
				      struct cpu_freq_reader *avg_readers)
{
	int i;

	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		tis_readers[i].fd = -1;
		tis_readers[i].nr_entries = 0;
		tis_readers[i].have_prev = false;
		tis_readers[i].path[0] = '\0';
		scaling_readers[i].fd = -1;
		scaling_readers[i].path[0] = '\0';
		avg_readers[i].fd = -1;
		avg_readers[i].path[0] = '\0';
	}
}

static __u64 timespec_to_ns(const struct timespec *ts)
{
	return (__u64)ts->tv_sec * 1000000000ULL + (__u64)ts->tv_nsec;
}

static struct timespec ns_to_timespec(__u64 ns)
{
	struct timespec ts = {
		.tv_sec = ns / 1000000000ULL,
		.tv_nsec = ns % 1000000000ULL,
	};

	return ts;
}

static int monotonic_now(struct timespec *ts)
{
	if (clock_gettime(CLOCK_MONOTONIC, ts) < 0) {
		perror("clock_gettime(CLOCK_MONOTONIC)");
		return -errno;
	}

	return 0;
}

static int sleep_until_ns(__u64 deadline_ns)
{
	struct timespec ts = ns_to_timespec(deadline_ns);
	int ret;

	while (!exit_req) {
		ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
		if (!ret)
			return 0;
		if (ret != EINTR) {
			errno = ret;
			perror("clock_nanosleep");
			return -ret;
		}
	}

	return 0;
}

static int parse_interval(const char *arg, double *value)
{
	char *endp;
	double parsed;

	errno = 0;
	parsed = strtod(arg, &endp);
	if (errno || endp == arg || *endp != '\0' || parsed <= 0.0 ||
	    !isfinite(parsed))
		return -EINVAL;

	*value = parsed;
	return 0;
}

static int ensure_log_dir(void)
{
	if (mkdir(LOG_DIR, 0755) < 0 && errno != EEXIST) {
		perror("mkdir(" LOG_DIR ")");
		return -errno;
	}

	return 0;
}

static FILE *open_log_file(const char *path)
{
	FILE *file = fopen(path, "w");

	if (!file) {
		perror(path);
		return NULL;
	}

	setvbuf(file, NULL, _IOLBF, 0);
	return file;
}

static int read_long_file(const char *path, long *value)
{
	char buf[64];
	char *endp;
	ssize_t nr_read;
	long parsed;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	nr_read = pread(fd, buf, sizeof(buf) - 1, 0);
	close(fd);
	if (nr_read <= 0)
		return nr_read ? -errno : -EIO;

	buf[nr_read] = '\0';
	errno = 0;
	parsed = strtol(buf, &endp, 10);
	if (errno || endp == buf)
		return -EINVAL;

	*value = parsed;
	return 0;
}

static int write_long_file(const char *path, long value)
{
	char buf[32];
	int fd;
	int len;
	ssize_t written;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	len = snprintf(buf, sizeof(buf), "%ld\n", value);
	written = write(fd, buf, len);
	close(fd);

	if (written != len)
		return written < 0 ? -errno : -EIO;

	return 0;
}

static int disable_boost(struct boost_state *boost)
{
	int ret;

	memset(boost, 0, sizeof(*boost));

	ret = read_long_file(CPUFREQ_BOOST_PATH, &boost->original_value);
	if (ret == -ENOENT)
		return 0;
	if (ret < 0) {
		fprintf(stderr, "Failed to read %s\n", CPUFREQ_BOOST_PATH);
		return ret;
	}

	boost->supported = true;
	if (!boost->original_value)
		return 0;

	ret = write_long_file(CPUFREQ_BOOST_PATH, 0);
	if (ret < 0) {
		fprintf(stderr, "Failed to disable boost via %s\n",
			CPUFREQ_BOOST_PATH);
		return ret;
	}

	boost->changed = true;
	return 0;
}

static void restore_boost(const struct boost_state *boost)
{
	if (!boost->supported || !boost->changed)
		return;

	if (write_long_file(CPUFREQ_BOOST_PATH, boost->original_value) < 0)
		fprintf(stderr, "Warning: failed to restore boost to %ld\n",
			boost->original_value);
}

static int write_meta_file(double interval_sec, const struct boost_state *boost)
{
	FILE *meta;
	time_t now;

	meta = open_log_file(LOG_META_PATH);
	if (!meta)
		return -errno;

	now = time(NULL);
	fprintf(meta, "cpus=6,7,8,9\n");
	fprintf(meta, "interval_sec=%.6f\n", interval_sec);
	fprintf(meta, "csv_path=%s\n", LOG_CSV_PATH);
	fprintf(meta, "metrics=policy_mhz,scaling_cur_mhz,cpuinfo_avg_mhz\n");
	fprintf(meta,
		"debug_metrics=last_event,last_perf,last_var_step_idx,last_var_freq_khz,last_var_pid,running_var_hits,running_nonvar_hits,perf_apply_hits,zero_from_running_hits,zero_from_stopping_hits,zero_from_idle_hits\n");
	fprintf(meta, "boost_supported=%d\n", boost->supported ? 1 : 0);
	fprintf(meta, "boost_original=%ld\n",
		boost->supported ? boost->original_value : -1L);
	fprintf(meta, "boost_active_during_run=0\n");
	fprintf(meta, "started_at=%lld\n", (long long)now);
	fclose(meta);
	return 0;
}

static int open_cpu_freq_reader_with_candidates(struct cpu_freq_reader *reader,
						int cpu,
						const char *const *candidates,
						size_t nr_candidates)
{
	char path[PATH_MAX];
	size_t i;
	int fd;

	reader->cpu = cpu;
	reader->fd = -1;
	reader->path[0] = '\0';

	for (i = 0; i < nr_candidates; i++) {
		snprintf(path, sizeof(path),
			 "/sys/devices/system/cpu/cpu%d/cpufreq/%s",
			 cpu, candidates[i]);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			continue;

		reader->fd = fd;
		snprintf(reader->path, sizeof(reader->path), "%s", path);
		return 0;
	}

	fprintf(stderr, "Could not open cpufreq source for cpu%d\n", cpu);
	return -ENOENT;
}

static int open_scaling_freq_reader(struct cpu_freq_reader *reader, int cpu)
{
	static const char *const candidates[] = {
		"scaling_cur_freq",
		"cpuinfo_cur_freq",
	};

	return open_cpu_freq_reader_with_candidates(reader, cpu, candidates,
						    sizeof(candidates) /
							    sizeof(candidates[0]));
}

static int open_avg_freq_reader(struct cpu_freq_reader *reader, int cpu)
{
	static const char *const candidates[] = {
		"cpuinfo_avg_freq",
	};

	return open_cpu_freq_reader_with_candidates(reader, cpu, candidates,
						    sizeof(candidates) /
							    sizeof(candidates[0]));
}

static int open_tis_reader(struct cpu_tis_reader *reader, int cpu)
{
	snprintf(reader->path, sizeof(reader->path),
		 "/sys/devices/system/cpu/cpufreq/policy%d/stats/time_in_state",
		 cpu);

	reader->cpu = cpu;
	reader->fd = open(reader->path, O_RDONLY | O_CLOEXEC);
	reader->nr_entries = 0;
	reader->have_prev = false;
	if (reader->fd >= 0)
		return 0;

	fprintf(stderr, "Could not open %s\n", reader->path);
	return -errno;
}

static int read_cpu_freq_khz(const struct cpu_freq_reader *reader, long *freq_khz)
{
	char buf[64];
	char *endp;
	ssize_t nr_read;
	long parsed;

	if (reader->fd < 0)
		return -ENOENT;

	nr_read = pread(reader->fd, buf, sizeof(buf) - 1, 0);
	if (nr_read <= 0)
		return nr_read ? -errno : -EIO;

	buf[nr_read] = '\0';
	errno = 0;
	parsed = strtol(buf, &endp, 10);
	if (errno || endp == buf)
		return -EINVAL;

	*freq_khz = parsed;
	return 0;
}

static void close_cpu_freq_readers(struct cpu_freq_reader *readers)
{
	int i;

	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		if (readers[i].fd >= 0) {
			close(readers[i].fd);
			readers[i].fd = -1;
		}
	}
}

static void close_tis_readers(struct cpu_tis_reader *readers)
{
	int i;

	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		if (readers[i].fd >= 0) {
			close(readers[i].fd);
			readers[i].fd = -1;
		}
	}
}

static int parse_tis_snapshot(char *buf, long *freqs_khz,
			      unsigned long long *ticks, size_t *nr_entries)
{
	char *line;
	char *saveptr = NULL;
	size_t count = 0;

	for (line = strtok_r(buf, "\n", &saveptr); line;
	     line = strtok_r(NULL, "\n", &saveptr)) {
		char *endp;
		long freq_khz;
		unsigned long long tick_count;

		while (*line == ' ' || *line == '\t')
			line++;
		if (!*line)
			continue;

		errno = 0;
		freq_khz = strtol(line, &endp, 10);
		if (errno || endp == line)
			return -EINVAL;

		while (*endp == ' ' || *endp == '\t')
			endp++;

		errno = 0;
		tick_count = strtoull(endp, &endp, 10);
		if (errno)
			return -EINVAL;
		if (count >= MAX_TIME_IN_STATE_STEPS)
			return -E2BIG;

		freqs_khz[count] = freq_khz;
		ticks[count] = tick_count;
		count++;
	}

	if (!count)
		return -EINVAL;

	*nr_entries = count;
	return 0;
}

static int sample_policy_freq_mhz(struct cpu_tis_reader *reader, bool *valid,
				  double *policy_mhz)
{
	char buf[8192];
	long freqs_khz[MAX_TIME_IN_STATE_STEPS];
	unsigned long long ticks[MAX_TIME_IN_STATE_STEPS];
	size_t nr_entries;
	size_t i;
	ssize_t nr_read;
	size_t best_idx = 0;
	unsigned long long best_delta = 0;

	*valid = false;
	if (reader->fd < 0)
		return -ENOENT;

	nr_read = pread(reader->fd, buf, sizeof(buf) - 1, 0);
	if (nr_read <= 0)
		return nr_read ? -errno : -EIO;

	buf[nr_read] = '\0';
	if (parse_tis_snapshot(buf, freqs_khz, ticks, &nr_entries) < 0)
		return -EINVAL;

	if (!reader->have_prev || reader->nr_entries != nr_entries) {
		reader->nr_entries = nr_entries;
		for (i = 0; i < nr_entries; i++) {
			reader->freqs_khz[i] = freqs_khz[i];
			reader->prev_ticks[i] = ticks[i];
		}
		reader->have_prev = true;
		return 0;
	}

	for (i = 0; i < nr_entries; i++) {
		unsigned long long delta = 0;

		if (reader->prev_ticks[i] <= ticks[i])
			delta = ticks[i] - reader->prev_ticks[i];

		reader->freqs_khz[i] = freqs_khz[i];
		reader->prev_ticks[i] = ticks[i];

		if (delta <= best_delta)
			continue;

		best_delta = delta;
		best_idx = i;
	}

	if (!best_delta)
		return 0;

	*valid = true;
	*policy_mhz = (double)reader->freqs_khz[best_idx] / 1000.0;
	return 0;
}

static int read_debug_states(struct scx_stairs *skel,
			     struct stairs_debug_cpu_state *states)
{
	int map_fd = bpf_map__fd(skel->maps.debug_cpu_state);
	int i;

	memset(states, 0, sizeof(*states) * NR_ISOLATED_CPUS);

	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		__u32 key = i;
		int ret;

		ret = bpf_map_lookup_elem(map_fd, &key, &states[i]);
		if (ret < 0)
			return -errno;

		states[i].last_var_comm[STAIRS_COMM_LEN - 1] = '\0';
		states[i].last_actor_comm[STAIRS_COMM_LEN - 1] = '\0';
	}

	return 0;
}

static void print_sample(double elapsed_sec, const bool *scaling_valid,
			 const double *scaling_mhz, const bool *avg_valid,
			 const double *avg_mhz, const bool *policy_valid,
			 const double *policy_mhz)
{
	int i;

	printf("t=%8.3fs", elapsed_sec);
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		if (policy_valid[i] && scaling_valid[i] && avg_valid[i]) {
			printf(" cpu%d=%8.3f|%8.3f/%8.3fMHz", isolated_cpus[i],
			       policy_mhz[i], scaling_mhz[i], avg_mhz[i]);
		} else if (scaling_valid[i] && avg_valid[i]) {
			printf(" cpu%d=%8s|%8.3f/%8.3fMHz", isolated_cpus[i], "n/a",
			       scaling_mhz[i], avg_mhz[i]);
		} else if (policy_valid[i] && scaling_valid[i]) {
			printf(" cpu%d=%8.3f|%8.3f/%8sMHz", isolated_cpus[i],
			       policy_mhz[i], scaling_mhz[i], "n/a");
		} else if (policy_valid[i] && avg_valid[i]) {
			printf(" cpu%d=%8.3f|%8s/%8.3fMHz", isolated_cpus[i],
			       policy_mhz[i], "n/a", avg_mhz[i]);
		} else if (policy_valid[i]) {
			printf(" cpu%d=%8.3f|%8s/%8sMHz", isolated_cpus[i],
			       policy_mhz[i], "n/a", "n/a");
		} else if (scaling_valid[i]) {
			printf(" cpu%d=%8s|%8.3f/%8sMHz", isolated_cpus[i], "n/a",
			       scaling_mhz[i], "n/a");
		} else if (avg_valid[i]) {
			printf(" cpu%d=%8s|%8s/%8.3fMHz", isolated_cpus[i], "n/a",
			       "n/a", avg_mhz[i]);
		} else {
			printf(" cpu%d=%8s|%8s/%8sMHz", isolated_cpus[i], "n/a",
			       "n/a", "n/a");
		}
	}
	printf("\n");
}

static void print_debug_sample(const struct stairs_debug_cpu_state *states)
{
	int i;

	printf("dbg:");
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		char last_var_comm[STAIRS_COMM_LEN];
		char last_actor_comm[STAIRS_COMM_LEN];

		format_task_comm(states[i].last_var_comm, last_var_comm,
				 sizeof(last_var_comm));
		format_task_comm(states[i].last_actor_comm, last_actor_comm,
				 sizeof(last_actor_comm));

		printf(" cpu%d[ev=%s perf=%u step=%u freq=%u pid=%u var=%llu oth=%llu set=%llu z=%llu/%llu/%llu last_var=%s actor=%s/%u]",
		       isolated_cpus[i], debug_event_name(states[i].last_event),
		       states[i].last_perf, states[i].last_var_step_idx,
		       states[i].last_var_freq_khz, states[i].last_var_pid,
		       (unsigned long long)states[i].running_var_hits,
		       (unsigned long long)states[i].running_nonvar_hits,
		       (unsigned long long)states[i].perf_apply_hits,
		       (unsigned long long)states[i].zero_from_running_hits,
		       (unsigned long long)states[i].zero_from_stopping_hits,
		       (unsigned long long)states[i].zero_from_idle_hits,
		       last_var_comm, last_actor_comm,
		       states[i].last_actor_pid);
	}
	printf("\n");
}

static void write_csv_sample(FILE *csv, double elapsed_sec,
			     const bool *scaling_valid,
			     const double *scaling_mhz,
			     const bool *avg_valid,
			     const double *avg_mhz,
			     const bool *policy_valid,
			     const double *policy_mhz,
			     const struct stairs_debug_cpu_state *debug_states)
{
	int i;

	fprintf(csv, "%.6f", elapsed_sec);
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		if (policy_valid[i])
			fprintf(csv, ",%.6f", policy_mhz[i]);
		else
			fprintf(csv, ",nan");
		if (scaling_valid[i])
			fprintf(csv, ",%.6f", scaling_mhz[i]);
		else
			fprintf(csv, ",nan");
		if (avg_valid[i])
			fprintf(csv, ",%.6f", avg_mhz[i]);
		else
			fprintf(csv, ",nan");
		fprintf(csv, ",%u,%u,%u,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu",
			debug_states[i].last_event,
			debug_states[i].last_perf,
			debug_states[i].last_var_step_idx,
			debug_states[i].last_var_freq_khz,
			debug_states[i].last_var_pid,
			(unsigned long long)debug_states[i].running_var_hits,
			(unsigned long long)debug_states[i].running_nonvar_hits,
			(unsigned long long)debug_states[i].perf_apply_hits,
			(unsigned long long)debug_states[i].zero_from_running_hits,
			(unsigned long long)debug_states[i].zero_from_stopping_hits,
			(unsigned long long)debug_states[i].zero_from_idle_hits);
	}
	fprintf(csv, "\n");
}

static int init_monitor_readers(struct cpu_tis_reader *tis_readers,
				struct cpu_freq_reader *scaling_readers,
				struct cpu_freq_reader *avg_readers)
{
	int i;
	int ret;

	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		tis_readers[i].fd = -1;
		scaling_readers[i].fd = -1;
		avg_readers[i].fd = -1;

		ret = open_tis_reader(&tis_readers[i], isolated_cpus[i]);
		if (ret < 0) {
			close_tis_readers(tis_readers);
			close_cpu_freq_readers(scaling_readers);
			close_cpu_freq_readers(avg_readers);
			return ret;
		}

		ret = open_scaling_freq_reader(&scaling_readers[i],
					       isolated_cpus[i]);
		if (ret < 0) {
			close_tis_readers(tis_readers);
			close_cpu_freq_readers(scaling_readers);
			close_cpu_freq_readers(avg_readers);
			return ret;
		}

		ret = open_avg_freq_reader(&avg_readers[i], isolated_cpus[i]);
		if (ret < 0)
			fprintf(stderr,
				"Warning: cpu%d average-frequency source is unavailable\n",
				isolated_cpus[i]);
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct scx_stairs *skel = NULL;
	struct bpf_link *link = NULL;
	struct cpu_tis_reader tis_readers[NR_ISOLATED_CPUS] = {};
	struct cpu_freq_reader scaling_readers[NR_ISOLATED_CPUS] = {};
	struct cpu_freq_reader avg_readers[NR_ISOLATED_CPUS] = {};
	struct boost_state boost = {};
	struct timespec start_ts;
	FILE *csv = NULL;
	double sample_interval_sec = 1.0;
	__u32 opt;
	__u64 ecode;
	__u64 next_sample_ns;
	__u64 interval_ns;
	int ret;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	setvbuf(stdout, NULL, _IOLBF, 0);
	init_isolated_cpus();
	init_monitor_reader_state(tis_readers, scaling_readers, avg_readers);

	while ((opt = getopt(argc, argv, "f:vh")) != -1) {
		switch (opt) {
		case 'f':
			ret = parse_interval(optarg, &sample_interval_sec);
			if (ret < 0) {
				fprintf(stderr,
					"Invalid sampling interval '%s'\n",
					optarg);
				return 1;
			}
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	ret = disable_boost(&boost);
	if (ret < 0)
		return 1;

restart:
	skel = SCX_OPS_OPEN(stairs_ops, scx_stairs);
	SCX_OPS_LOAD(skel, stairs_ops, scx_stairs, uei);
	link = SCX_OPS_ATTACH(skel, stairs_ops, scx_stairs);

	ret = ensure_log_dir();
	if (ret < 0)
		goto out;

	ret = write_meta_file(sample_interval_sec, &boost);
	if (ret < 0)
		goto out;

	csv = open_log_file(LOG_CSV_PATH);
	if (!csv) {
		ret = -errno;
		goto out;
	}

		fprintf(csv,
			"elapsed_sec,"
			"cpu6_policy_mhz,cpu6_scaling_mhz,cpu6_avg_mhz,cpu6_dbg_last_event,cpu6_dbg_last_perf,cpu6_dbg_last_step,cpu6_dbg_last_freq_khz,cpu6_dbg_last_var_pid,cpu6_dbg_var_hits,cpu6_dbg_other_hits,cpu6_dbg_set_hits,cpu6_dbg_zero_run_hits,cpu6_dbg_zero_stop_hits,cpu6_dbg_zero_idle_hits,"
			"cpu7_policy_mhz,cpu7_scaling_mhz,cpu7_avg_mhz,cpu7_dbg_last_event,cpu7_dbg_last_perf,cpu7_dbg_last_step,cpu7_dbg_last_freq_khz,cpu7_dbg_last_var_pid,cpu7_dbg_var_hits,cpu7_dbg_other_hits,cpu7_dbg_set_hits,cpu7_dbg_zero_run_hits,cpu7_dbg_zero_stop_hits,cpu7_dbg_zero_idle_hits,"
			"cpu8_policy_mhz,cpu8_scaling_mhz,cpu8_avg_mhz,cpu8_dbg_last_event,cpu8_dbg_last_perf,cpu8_dbg_last_step,cpu8_dbg_last_freq_khz,cpu8_dbg_last_var_pid,cpu8_dbg_var_hits,cpu8_dbg_other_hits,cpu8_dbg_set_hits,cpu8_dbg_zero_run_hits,cpu8_dbg_zero_stop_hits,cpu8_dbg_zero_idle_hits,"
			"cpu9_policy_mhz,cpu9_scaling_mhz,cpu9_avg_mhz,cpu9_dbg_last_event,cpu9_dbg_last_perf,cpu9_dbg_last_step,cpu9_dbg_last_freq_khz,cpu9_dbg_last_var_pid,cpu9_dbg_var_hits,cpu9_dbg_other_hits,cpu9_dbg_set_hits,cpu9_dbg_zero_run_hits,cpu9_dbg_zero_stop_hits,cpu9_dbg_zero_idle_hits\n");

	ret = init_monitor_readers(tis_readers, scaling_readers, avg_readers);
	if (ret < 0)
		goto out;

	ret = monotonic_now(&start_ts);
	if (ret < 0)
		goto out;

	interval_ns = (__u64)(sample_interval_sec * 1000000000.0);
	next_sample_ns = timespec_to_ns(&start_ts);

	if (boost.supported)
		printf("Boost is disabled for this run (original=%ld)\n",
		       boost.original_value);
	printf("Monitoring isolated CPUs 6-9 every %.3f s\n", sample_interval_sec);
	printf("Sample format: policy|scaling_cur/cpuinfo_avg MHz\n");
	printf("Logging samples to %s\n", LOG_CSV_PATH);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		bool policy_valid[NR_ISOLATED_CPUS] = {};
		bool scaling_valid[NR_ISOLATED_CPUS] = {};
		bool avg_valid[NR_ISOLATED_CPUS] = {};
		double policy_mhz[NR_ISOLATED_CPUS] = {};
		double scaling_mhz[NR_ISOLATED_CPUS] = {};
		double avg_mhz[NR_ISOLATED_CPUS] = {};
		struct stairs_debug_cpu_state debug_states[NR_ISOLATED_CPUS] = {};
			struct timespec now_ts;
			double elapsed_sec;
			int i;

		ret = monotonic_now(&now_ts);
		if (ret < 0)
			goto out;

		elapsed_sec =
			(double)(timespec_to_ns(&now_ts) - timespec_to_ns(&start_ts)) /
			1000000000.0;

		for (i = 0; i < NR_ISOLATED_CPUS; i++) {
			long freq_khz;

			ret = sample_policy_freq_mhz(&tis_readers[i], &policy_valid[i],
						    &policy_mhz[i]);
			if (ret < 0)
				goto out;

			ret = read_cpu_freq_khz(&scaling_readers[i], &freq_khz);
			if (ret >= 0) {
				scaling_valid[i] = true;
				scaling_mhz[i] = (double)freq_khz / 1000.0;
			}

			ret = read_cpu_freq_khz(&avg_readers[i], &freq_khz);
			if (ret >= 0) {
				avg_valid[i] = true;
				avg_mhz[i] = (double)freq_khz / 1000.0;
				}
			}

		ret = read_debug_states(skel, debug_states);
		if (ret < 0)
			goto out;

		print_sample(elapsed_sec, scaling_valid, scaling_mhz, avg_valid,
			     avg_mhz, policy_valid, policy_mhz);
		print_debug_sample(debug_states);
		write_csv_sample(csv, elapsed_sec, scaling_valid, scaling_mhz,
				 avg_valid, avg_mhz, policy_valid, policy_mhz,
				 debug_states);

		next_sample_ns += interval_ns;
		ret = sleep_until_ns(next_sample_ns);
		if (ret < 0)
			goto out;
	}

out:
	close_tis_readers(tis_readers);
	close_cpu_freq_readers(scaling_readers);
	close_cpu_freq_readers(avg_readers);
	if (csv)
		fclose(csv);
	if (link)
		bpf_link__destroy(link);
	ecode = skel ? UEI_REPORT(skel, uei) : 0;
	if (skel)
		scx_stairs__destroy(skel);

	if (!ret && UEI_ECODE_RESTART(ecode)) {
		memset(tis_readers, 0, sizeof(tis_readers));
		memset(scaling_readers, 0, sizeof(scaling_readers));
		memset(avg_readers, 0, sizeof(avg_readers));
		init_monitor_reader_state(tis_readers, scaling_readers,
					 avg_readers);
		csv = NULL;
		link = NULL;
		skel = NULL;
		exit_req = 0;
		goto restart;
	}

	restore_boost(&boost);
	return ret < 0 ? 1 : 0;
}
