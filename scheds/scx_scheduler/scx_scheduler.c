/* SPDX-License-Identifier: GPL-2.0 */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/limits.h>
#include <math.h>
#include <scx/common.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "scx_scheduler.bpf.skel.h"
#include "scx_scheduler_sched.h"

#define ISOLATED_START 6
#define ISOLATED_END 9
#define NR_ISOLATED_CPUS (ISOLATED_END - ISOLATED_START + 1)
#define MAX_TIME_IN_STATE_STEPS 64

#define LOG_DIR "results/scx_scheduler"
#define LOG_CSV_PATH LOG_DIR "/latest.csv"
#define LOG_DBG_PATH LOG_DIR "/dbg.log"
#define CPUFREQ_BOOST_PATH "/sys/devices/system/cpu/cpufreq/boost"

struct cpu_freq_reader {
	int cpu;
	int fd;
	char path[PATH_MAX];
};

struct cpu_tis_reader {
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

static const char *debug_event_name(__u32 event)
{
	switch (event) {
	case SCHEDULER_DEBUG_PLANNED_RUNNING:
		return "plan";
	case SCHEDULER_DEBUG_UNPLANNED_RUNNING_KEEP:
		return "runhold";
	case SCHEDULER_DEBUG_UNPLANNED_RUNNING_ZERO:
		return "run0";
	case SCHEDULER_DEBUG_STOPPING_ZERO:
		return "stop0";
	case SCHEDULER_DEBUG_IDLE_ZERO:
		return "idle0";
	default:
		return "-";
	}
}

static void format_task_comm(const char src[SCHEDULER_TASK_COMM_LEN], char *dst,
			     size_t size)
{
	size_t i;

	if (!size)
		return;

	for (i = 0; i + 1 < size && i < SCHEDULER_TASK_COMM_LEN && src[i]; i++)
		dst[i] = src[i];
	dst[i] = '\0';

	if (!dst[0]) {
		dst[0] = '-';
		dst[1] = '\0';
	}
}

struct parsed_schedule {
	__u64 deadline_ms;
	__u32 declared_nr_tasks;
	bool have_deadline;
	bool have_nr_tasks;
	struct schedule_task_plan *plans;
	size_t nr_plans;
	size_t cap_plans;
};

static int isolated_cpus[NR_ISOLATED_CPUS];
static volatile sig_atomic_t exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sigint_handler(int sig)
{
	exit_req = 1;
}

static void init_isolated_cpus(void)
{
	int i;

	for (i = 0; i < NR_ISOLATED_CPUS; i++)
		isolated_cpus[i] = ISOLATED_START + i;
}

static void init_tis_readers(struct cpu_tis_reader *readers)
{
	int i;

	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		readers[i].fd = -1;
		readers[i].nr_entries = 0;
		readers[i].have_prev = false;
		readers[i].path[0] = '\0';
	}
}

static void init_cpu_freq_readers(struct cpu_freq_reader *readers)
{
	int i;

	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		readers[i].cpu = isolated_cpus[i];
		readers[i].fd = -1;
		readers[i].path[0] = '\0';
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

static int parse_interval(const char *arg, double *interval_sec)
{
	char *endp;
	double value;

	errno = 0;
	value = strtod(arg, &endp);
	if (errno || endp == arg || *endp != '\0' || value <= 0.0 ||
	    !isfinite(value))
		return -EINVAL;

	*interval_sec = value;
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

static int open_tis_reader(struct cpu_tis_reader *reader, int cpu)
{
	snprintf(reader->path, sizeof(reader->path),
		 "/sys/devices/system/cpu/cpufreq/policy%d/stats/time_in_state",
		 cpu);

	reader->fd = open(reader->path, O_RDONLY | O_CLOEXEC);
	reader->nr_entries = 0;
	reader->have_prev = false;
	if (reader->fd >= 0)
		return 0;

	if (errno == ENOENT) {
		fprintf(stderr,
			"Warning: %s is unavailable, policy MHz samples for CPU%d will be None\n",
			reader->path, cpu);
		return 0;
	}

	fprintf(stderr, "Could not open %s\n", reader->path);
	return -errno;
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

static int open_all_tis_readers(struct cpu_tis_reader *readers)
{
	int i;
	int ret;

	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		ret = open_tis_reader(&readers[i], isolated_cpus[i]);
		if (ret < 0) {
			close_tis_readers(readers);
			return ret;
		}
	}

	return 0;
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
	size_t best_idx = 0;
	unsigned long long best_delta = 0;
	ssize_t nr_read;

	*valid = false;
	*policy_mhz = 0.0;
	if (reader->fd < 0)
		return 0;

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

static int sample_cpu_freq_mhz(const struct cpu_freq_reader *reader, bool *valid,
			       double *freq_mhz)
{
	long freq_khz;
	int ret;

	*valid = false;
	*freq_mhz = 0.0;

	ret = read_cpu_freq_khz(reader, &freq_khz);
	if (ret == -ENOENT)
		return 0;
	if (ret < 0)
		return ret;

	*valid = true;
	*freq_mhz = (double)freq_khz / 1000.0;
	return 0;
}

static int read_debug_states(struct scx_scheduler *skel,
			     struct scheduler_debug_cpu_state *states)
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

		states[i].last_plan_comm[SCHEDULER_TASK_COMM_LEN - 1] = '\0';
		states[i].last_actor_comm[SCHEDULER_TASK_COMM_LEN - 1] = '\0';
	}

	return 0;
}

static void write_csv_header(FILE *csv)
{
	int i;

	fprintf(csv, "elapsed_sec");
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		fprintf(csv, ",cpu%d_policy_mhz", isolated_cpus[i]);
		fprintf(csv, ",cpu%d_scaling_mhz", isolated_cpus[i]);
		fprintf(csv, ",cpu%d_avg_mhz", isolated_cpus[i]);
		fprintf(csv,
			",cpu%d_dbg_last_event,cpu%d_dbg_last_perf,cpu%d_dbg_last_plan_task_id,cpu%d_dbg_last_step,cpu%d_dbg_last_freq_khz,cpu%d_dbg_last_plan_pid,cpu%d_dbg_last_actor_pid,cpu%d_dbg_plan_hits,cpu%d_dbg_unplanned_hits,cpu%d_dbg_keep_run_hits,cpu%d_dbg_set_hits,cpu%d_dbg_zero_run_hits,cpu%d_dbg_zero_stop_hits,cpu%d_dbg_zero_idle_hits",
			isolated_cpus[i], isolated_cpus[i], isolated_cpus[i],
			isolated_cpus[i], isolated_cpus[i], isolated_cpus[i],
			isolated_cpus[i], isolated_cpus[i], isolated_cpus[i],
			isolated_cpus[i], isolated_cpus[i], isolated_cpus[i],
			isolated_cpus[i], isolated_cpus[i]);
	}
	fprintf(csv, "\n");
}

static void write_csv_freq_field(FILE *csv, bool valid, double freq_mhz)
{
	if (valid)
		fprintf(csv, ",%.6f", freq_mhz);
	else
		fprintf(csv, ",None");
}

static void write_csv_sample(FILE *csv, double elapsed_sec,
			     const bool *policy_valid,
			     const double *policy_mhz,
			     const bool *scaling_valid,
			     const double *scaling_mhz,
			     const bool *avg_valid,
			     const double *avg_mhz,
			     const struct scheduler_debug_cpu_state *debug_states)
{
	int i;

	fprintf(csv, "%.6f", elapsed_sec);
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		write_csv_freq_field(csv, policy_valid[i], policy_mhz[i]);
		write_csv_freq_field(csv, scaling_valid[i], scaling_mhz[i]);
		write_csv_freq_field(csv, avg_valid[i], avg_mhz[i]);
		fprintf(csv, ",%u,%u,%u,%u,%u,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu",
			debug_states[i].last_event,
			debug_states[i].last_perf,
			debug_states[i].last_plan_task_id,
			debug_states[i].last_plan_step_idx,
			debug_states[i].last_plan_freq_khz,
			debug_states[i].last_plan_pid,
			debug_states[i].last_actor_pid,
			(unsigned long long)debug_states[i].running_planned_hits,
			(unsigned long long)debug_states[i].running_unplanned_hits,
			(unsigned long long)debug_states[i].keep_from_running_hits,
			(unsigned long long)debug_states[i].perf_apply_hits,
			(unsigned long long)debug_states[i].zero_from_running_hits,
			(unsigned long long)debug_states[i].zero_from_stopping_hits,
			(unsigned long long)debug_states[i].zero_from_idle_hits);
	}
	fprintf(csv, "\n");
}

static void write_sample_line(FILE *out, double elapsed_sec,
			      const bool *policy_valid,
			      const double *policy_mhz,
			      const bool *scaling_valid,
			      const double *scaling_mhz,
			      const bool *avg_valid,
			      const double *avg_mhz)
{
	int i;

	fprintf(out, "t=%8.3fs", elapsed_sec);
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		if (policy_valid[i] && scaling_valid[i] && avg_valid[i]) {
			fprintf(out, " cpu%d=%8.3f|%8.3f/%8.3fMHz", isolated_cpus[i],
				policy_mhz[i], scaling_mhz[i], avg_mhz[i]);
		} else if (scaling_valid[i] && avg_valid[i]) {
			fprintf(out, " cpu%d=%8s|%8.3f/%8.3fMHz", isolated_cpus[i],
				"n/a", scaling_mhz[i], avg_mhz[i]);
		} else if (policy_valid[i] && scaling_valid[i]) {
			fprintf(out, " cpu%d=%8.3f|%8.3f/%8sMHz", isolated_cpus[i],
				policy_mhz[i], scaling_mhz[i], "n/a");
		} else if (policy_valid[i] && avg_valid[i]) {
			fprintf(out, " cpu%d=%8.3f|%8s/%8.3fMHz", isolated_cpus[i],
				policy_mhz[i], "n/a", avg_mhz[i]);
		} else if (policy_valid[i]) {
			fprintf(out, " cpu%d=%8.3f|%8s/%8sMHz", isolated_cpus[i],
				policy_mhz[i], "n/a", "n/a");
		} else if (scaling_valid[i]) {
			fprintf(out, " cpu%d=%8s|%8.3f/%8sMHz", isolated_cpus[i],
				"n/a", scaling_mhz[i], "n/a");
		} else if (avg_valid[i]) {
			fprintf(out, " cpu%d=%8s|%8s/%8.3fMHz", isolated_cpus[i],
				"n/a", "n/a", avg_mhz[i]);
		} else {
			fprintf(out, " cpu%d=%8s|%8s/%8sMHz", isolated_cpus[i],
				"n/a", "n/a", "n/a");
		}
	}
	fprintf(out, "\n");
}

static void maybe_print_progress_timer(double elapsed_sec, int *last_sec)
{
	int sec = (int)elapsed_sec;

	if (sec == *last_sec)
		return;

	*last_sec = sec;
	printf("\rElapsed: %4d s", sec);
	fflush(stdout);
}

static void write_debug_sample_line(FILE *out,
				    const struct scheduler_debug_cpu_state *states)
{
	int i;

	fprintf(out, "dbg:");
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		char plan_comm[SCHEDULER_TASK_COMM_LEN];
		char actor_comm[SCHEDULER_TASK_COMM_LEN];

		format_task_comm(states[i].last_plan_comm, plan_comm,
				 sizeof(plan_comm));
		format_task_comm(states[i].last_actor_comm, actor_comm,
				 sizeof(actor_comm));

		fprintf(out, " cpu%d[ev=%s perf=%u task=%u step=%u freq=%u actor=%s/%u plan=%s/%u hits=%llu/%llu keep=%llu set=%llu z=%llu/%llu/%llu]",
			isolated_cpus[i], debug_event_name(states[i].last_event),
			states[i].last_perf, states[i].last_plan_task_id,
			states[i].last_plan_step_idx,
			states[i].last_plan_freq_khz, actor_comm,
			states[i].last_actor_pid, plan_comm,
			states[i].last_plan_pid,
			(unsigned long long)states[i].running_planned_hits,
			(unsigned long long)states[i].running_unplanned_hits,
			(unsigned long long)states[i].keep_from_running_hits,
			(unsigned long long)states[i].perf_apply_hits,
			(unsigned long long)states[i].zero_from_running_hits,
			(unsigned long long)states[i].zero_from_stopping_hits,
			(unsigned long long)states[i].zero_from_idle_hits);
	}
	fprintf(out, "\n");
}

static void set_fail_stage(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, size, fmt, args);
	va_end(args);
}

static int init_monitor_readers(struct cpu_tis_reader *tis_readers,
				struct cpu_freq_reader *scaling_readers,
				struct cpu_freq_reader *avg_readers)
{
	int i;
	int ret;

	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
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
			fprintf(stderr,
				"Warning: cpu%d scaling-current source is unavailable\n",
				isolated_cpus[i]);
		}

		ret = open_avg_freq_reader(&avg_readers[i], isolated_cpus[i]);
		if (ret < 0) {
			fprintf(stderr,
				"Warning: cpu%d average-frequency source is unavailable\n",
				isolated_cpus[i]);
		}
	}

	return 0;
}

static bool is_dec_char(char c)
{
	return c >= '0' && c <= '9';
}

static char *trim_whitespace(char *str)
{
	char *end;

	while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r')
		str++;

	if (!*str)
		return str;

	end = str + strlen(str) - 1;
	while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' ||
			      *end == '\r')) {
		*end = '\0';
		end--;
	}

	return str;
}

static void strip_comment(char *line)
{
	char *comment = strchr(line, '#');

	if (comment)
		*comment = '\0';
}

static bool is_isolated_cpu_id(__u32 cpu)
{
	return cpu >= ISOLATED_START && cpu <= ISOLATED_END;
}

static int parse_prefixed_u64(const char *line, const char *prefix, __u64 *value)
{
	const char *p = line;
	size_t prefix_len = strlen(prefix);
	char *endp;
	unsigned long long parsed;

	if (strncmp(p, prefix, prefix_len))
		return 0;
	p += prefix_len;

	while (*p == ':' || *p == '=' || *p == ' ' || *p == '\t')
		p++;
	if (!is_dec_char(*p))
		return -EINVAL;

	errno = 0;
	parsed = strtoull(p, &endp, 10);
	if (errno || endp == p)
		return -EINVAL;
	while (*endp == ' ' || *endp == '\t')
		endp++;
	if (*endp != '\0')
		return -EINVAL;

	*value = parsed;
	return 1;
}

static int parse_prefixed_u32(const char *line, const char *prefix, __u32 *value)
{
	__u64 parsed = 0;
	int ret;

	ret = parse_prefixed_u64(line, prefix, &parsed);
	if (ret <= 0)
		return ret;
	if (parsed > UINT_MAX)
		return -ERANGE;

	*value = (__u32)parsed;
	return 1;
}

static int parse_schedule_plan_line(const char *line, struct schedule_task_plan *plan)
{
	unsigned long long task_id;
	unsigned long long runtime_ms;
	unsigned long long ready_ms;
	unsigned long long cpu;
	unsigned long long freq_step_idx;
	unsigned long long freq_khz;
	unsigned long long perf_target;
	unsigned long long order;
	unsigned long long start_ns;
	unsigned long long duration_ns;
	char extra;
	int matched;

	if (!is_dec_char(line[0]))
		return 0;

	matched = sscanf(line,
			 "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %c",
			 &task_id, &runtime_ms, &ready_ms, &cpu, &freq_step_idx,
			 &freq_khz, &perf_target, &order, &start_ns, &duration_ns,
			 &extra);
	if (matched != 10)
		return -EINVAL;

	if (task_id > UINT_MAX || runtime_ms > UINT_MAX || ready_ms > UINT_MAX ||
	    cpu > UINT_MAX || freq_step_idx > UINT_MAX || freq_khz > UINT_MAX ||
	    perf_target > UINT_MAX || order > UINT_MAX)
		return -ERANGE;

	plan->task_id = (__u32)task_id;
	plan->runtime_ms = (__u32)runtime_ms;
	plan->ready_ms = (__u32)ready_ms;
	plan->cpu = (__u32)cpu;
	plan->freq_step_idx = (__u32)freq_step_idx;
	plan->freq_khz = (__u32)freq_khz;
	plan->perf_target = (__u32)perf_target;
	plan->order = (__u32)order;
	plan->start_ns = (__u64)start_ns;
	plan->duration_ns = (__u64)duration_ns;
	return 1;
}

static int add_schedule_plan(struct parsed_schedule *schedule,
			     const struct schedule_task_plan *plan)
{
	struct schedule_task_plan *new_plans;

	if (schedule->nr_plans >= SCHEDULER_MAX_TASKS)
		return -E2BIG;

	if (schedule->nr_plans == schedule->cap_plans) {
		size_t new_cap = schedule->cap_plans ? schedule->cap_plans * 2 : 16;

		new_plans = realloc(schedule->plans, new_cap * sizeof(*new_plans));
		if (!new_plans)
			return -ENOMEM;

		schedule->plans = new_plans;
		schedule->cap_plans = new_cap;
	}

	schedule->plans[schedule->nr_plans++] = *plan;
	return 0;
}

static void free_parsed_schedule(struct parsed_schedule *schedule)
{
	free(schedule->plans);
	schedule->plans = NULL;
	schedule->nr_plans = 0;
	schedule->cap_plans = 0;
	schedule->deadline_ms = 0;
	schedule->declared_nr_tasks = 0;
	schedule->have_deadline = false;
	schedule->have_nr_tasks = false;
}

static int parse_schedule_file(const char *path, struct parsed_schedule *schedule)
{
	FILE *file;
	char line[512];
	int line_no = 0;
	int ret = 0;

	memset(schedule, 0, sizeof(*schedule));

	file = fopen(path, "r");
	if (!file) {
		perror(path);
		return -errno;
	}

	while (fgets(line, sizeof(line), file)) {
		char *trimmed;
		struct schedule_task_plan plan = {};

		line_no++;
		strip_comment(line);
		trimmed = trim_whitespace(line);
		if (!*trimmed)
			continue;

		ret = parse_prefixed_u64(trimmed, "deadline_ms",
					 &schedule->deadline_ms);
		if (ret < 0) {
			fprintf(stderr, "%s:%d: invalid deadline_ms line\n", path,
				line_no);
			goto err;
		}
		if (ret > 0) {
			schedule->have_deadline = true;
			continue;
		}

		ret = parse_prefixed_u32(trimmed, "nr_tasks",
					 &schedule->declared_nr_tasks);
		if (ret < 0) {
			fprintf(stderr, "%s:%d: invalid nr_tasks line\n", path,
				line_no);
			goto err;
		}
		if (ret > 0) {
			schedule->have_nr_tasks = true;
			continue;
		}

		ret = parse_schedule_plan_line(trimmed, &plan);
		if (ret < 0) {
			fprintf(stderr, "%s:%d: invalid plan line\n", path,
				line_no);
			goto err;
		}
		if (!ret) {
			fprintf(stderr, "%s:%d: unknown line format\n", path,
				line_no);
			ret = -EINVAL;
			goto err;
		}

		ret = add_schedule_plan(schedule, &plan);
		if (ret < 0)
			goto err;
	}

	fclose(file);
	return 0;

err:
	fclose(file);
	free_parsed_schedule(schedule);
	return ret;
}

static bool task_name_fits(__u32 task_id)
{
	char short_name[SCHEDULER_TASK_COMM_LEN];
	int len;

	len = snprintf(short_name, sizeof(short_name), "task%u", task_id);
	return len >= 0 && len < SCHEDULER_TASK_COMM_LEN;
}

static int compare_plan_task_id(const void *a, const void *b)
{
	const struct schedule_task_plan *pa = a;
	const struct schedule_task_plan *pb = b;

	if (pa->task_id < pb->task_id)
		return -1;
	if (pa->task_id > pb->task_id)
		return 1;
	return 0;
}

static int compare_plan_cpu_order(const void *a, const void *b)
{
	const struct schedule_task_plan *pa = a;
	const struct schedule_task_plan *pb = b;

	if (pa->cpu < pb->cpu)
		return -1;
	if (pa->cpu > pb->cpu)
		return 1;
	if (pa->order < pb->order)
		return -1;
	if (pa->order > pb->order)
		return 1;
	return 0;
}

static int validate_parsed_schedule(struct parsed_schedule *schedule)
{
	__u64 deadline_ns;
	size_t i;

	if (!schedule->have_deadline || !schedule->deadline_ms) {
		fprintf(stderr, "static schedule is missing deadline_ms\n");
		return -EINVAL;
	}
	if (!schedule->nr_plans) {
		fprintf(stderr, "static schedule does not contain any tasks\n");
		return -EINVAL;
	}
	if (schedule->have_nr_tasks &&
	    schedule->declared_nr_tasks != schedule->nr_plans) {
		fprintf(stderr,
			"static schedule declares %u tasks, but contains %zu entries\n",
			schedule->declared_nr_tasks, schedule->nr_plans);
		return -EINVAL;
	}

	deadline_ns = schedule->deadline_ms * 1000000ULL;
	qsort(schedule->plans, schedule->nr_plans, sizeof(*schedule->plans),
	      compare_plan_task_id);

	for (i = 0; i < schedule->nr_plans; i++) {
		const struct schedule_task_plan *plan = &schedule->plans[i];
		__u64 ready_ns = (__u64)plan->ready_ms * 1000000ULL;

		if (!plan->task_id) {
			fprintf(stderr, "task id 0 is not allowed in static schedule\n");
			return -EINVAL;
		}
		if (!task_name_fits(plan->task_id)) {
			fprintf(stderr, "task%u does not fit in comm length\n",
				plan->task_id);
			return -ENAMETOOLONG;
		}
		if (!plan->runtime_ms || !plan->duration_ns) {
			fprintf(stderr,
				"task%u has zero runtime or zero duration in static schedule\n",
				plan->task_id);
			return -EINVAL;
		}
		if (!is_isolated_cpu_id(plan->cpu)) {
			fprintf(stderr, "task%u targets non-isolated CPU%u\n",
				plan->task_id, plan->cpu);
			return -EINVAL;
		}
		if (!plan->freq_step_idx || !plan->freq_khz || !plan->perf_target) {
			fprintf(stderr,
				"task%u has incomplete DVFS fields in static schedule\n",
				plan->task_id);
			return -EINVAL;
		}
		if (plan->ready_ms >= schedule->deadline_ms) {
			fprintf(stderr,
				"task%u ready time %u ms is not earlier than deadline %llu ms\n",
				plan->task_id, plan->ready_ms,
				(unsigned long long)schedule->deadline_ms);
			return -EINVAL;
		}
		if (plan->start_ns < ready_ns) {
			fprintf(stderr,
				"task%u starts before ready time (%llu ns < %llu ns)\n",
				plan->task_id,
				(unsigned long long)plan->start_ns,
				(unsigned long long)ready_ns);
			return -EINVAL;
		}
		if (plan->start_ns + plan->duration_ns > deadline_ns) {
			fprintf(stderr,
				"task%u exceeds deadline in static schedule\n",
				plan->task_id);
			return -ERANGE;
		}
		if (i > 0 && schedule->plans[i - 1].task_id == plan->task_id) {
			fprintf(stderr, "duplicate task id %u in static schedule\n",
				plan->task_id);
			return -EINVAL;
		}
	}

	return 0;
}

static void print_schedule_summary(const struct schedule_task_plan *plans,
				   size_t nr_plans,
				   const struct schedule_control *control)
{
	struct schedule_task_plan *sorted;
	size_t i;

	sorted = malloc(nr_plans * sizeof(*sorted));
	if (!sorted)
		return;

	memcpy(sorted, plans, nr_plans * sizeof(*sorted));
	qsort(sorted, nr_plans, sizeof(*sorted), compare_plan_cpu_order);

	printf("Loaded static schedule for %u tasks, deadline %.3f ms\n",
	       control->nr_tasks, (double)control->deadline_ns / 1000000.0);

	for (i = 0; i < nr_plans; i++) {
		const struct schedule_task_plan *plan = &sorted[i];

		if (i == 0 || sorted[i - 1].cpu != plan->cpu)
			printf("CPU%u\n", plan->cpu);

		printf("  order=%u task%u runtime=%u ready=%.3fms start=%.3fms duration=%.3fms step=%u freq=%u\n",
		       plan->order, plan->task_id, plan->runtime_ms,
		       (double)plan->ready_ms, (double)plan->start_ns / 1000000.0,
		       (double)plan->duration_ns / 1000000.0, plan->freq_step_idx,
		       plan->freq_khz);
	}

	free(sorted);
}

static int load_schedule_maps(struct scx_scheduler *skel,
			      const struct schedule_control *control,
			      const struct schedule_task_plan *plans,
			      size_t nr_plans)
{
	int task_plans_fd;
	int control_fd;
	__u32 key0 = 0;
	size_t i;

	task_plans_fd = bpf_map__fd(skel->maps.task_plans);
	control_fd = bpf_map__fd(skel->maps.schedule_control);

	if (bpf_map_update_elem(control_fd, &key0, control, BPF_ANY) < 0)
		return -errno;

	for (i = 0; i < nr_plans; i++) {
		__u32 key = plans[i].task_id;

		if (bpf_map_update_elem(task_plans_fd, &key, &plans[i], BPF_ANY) < 0)
			return -errno;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct scx_scheduler *skel = NULL;
	struct bpf_link *link = NULL;
	struct cpu_tis_reader tis_readers[NR_ISOLATED_CPUS];
	struct cpu_freq_reader scaling_readers[NR_ISOLATED_CPUS];
	struct cpu_freq_reader avg_readers[NR_ISOLATED_CPUS];
	struct boost_state boost = {};
	struct parsed_schedule schedule = {};
	struct schedule_control control = {};
	struct timespec start_ts;
	FILE *csv = NULL;
	FILE *dbg = NULL;
	double sample_interval_sec = 1.0;
	const char *schedule_path = NULL;
	__u64 ecode;
	__u64 interval_ns;
	__u64 next_sample_ns;
	char fail_stage[128] = "startup";
	int opt;
	int last_timer_sec = -1;
	int ret = 0;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	setvbuf(stdout, NULL, _IOLBF, 0);
	init_isolated_cpus();
	init_tis_readers(tis_readers);
	init_cpu_freq_readers(scaling_readers);
	init_cpu_freq_readers(avg_readers);

	while ((opt = getopt(argc, argv, "f:h")) != -1) {
		switch (opt) {
		case 'f':
			ret = parse_interval(optarg, &sample_interval_sec);
			if (ret < 0) {
				fprintf(stderr, "Invalid sampling interval '%s'\n",
					optarg);
				return 1;
			}
			break;
		default:
			fprintf(stderr, "Usage: %s [-f interval_sec] <schedule_file>\n",
				argv[0]);
			return opt != 'h';
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Usage: %s [-f interval_sec] <schedule_file>\n",
			argv[0]);
		return 1;
	}
	schedule_path = argv[optind];

	ret = parse_schedule_file(schedule_path, &schedule);
	if (ret < 0)
		return 1;

	ret = validate_parsed_schedule(&schedule);
	if (ret < 0) {
		set_fail_stage(fail_stage, sizeof(fail_stage),
			       "validate_parsed_schedule");
		goto out;
	}

	control.deadline_ns = schedule.deadline_ms * 1000000ULL;
	control.nr_tasks = schedule.nr_plans;
	control.reserved = 0;

	ret = disable_boost(&boost);
	if (ret < 0) {
		set_fail_stage(fail_stage, sizeof(fail_stage), "disable_boost");
		goto out;
	}

restart:
	skel = SCX_OPS_OPEN(scheduler_ops, scx_scheduler);
	SCX_OPS_LOAD(skel, scheduler_ops, scx_scheduler, uei);

	ret = load_schedule_maps(skel, &control, schedule.plans,
				 schedule.nr_plans);
	if (ret < 0) {
		set_fail_stage(fail_stage, sizeof(fail_stage), "load_schedule_maps");
		goto out;
	}

	link = SCX_OPS_ATTACH(skel, scheduler_ops, scx_scheduler);

	ret = ensure_log_dir();
	if (ret < 0) {
		set_fail_stage(fail_stage, sizeof(fail_stage), "ensure_log_dir");
		goto out;
	}

	csv = open_log_file(LOG_CSV_PATH);
	if (!csv) {
		ret = -errno;
		set_fail_stage(fail_stage, sizeof(fail_stage),
			       "open_log_file(%s)", LOG_CSV_PATH);
		goto out;
	}
	write_csv_header(csv);

	dbg = open_log_file(LOG_DBG_PATH);
	if (!dbg) {
		ret = -errno;
		set_fail_stage(fail_stage, sizeof(fail_stage),
			       "open_log_file(%s)", LOG_DBG_PATH);
		goto out;
	}

	ret = init_monitor_readers(tis_readers, scaling_readers, avg_readers);
	if (ret < 0) {
		set_fail_stage(fail_stage, sizeof(fail_stage),
			       "init_monitor_readers");
		goto out;
	}

	ret = monotonic_now(&start_ts);
	if (ret < 0) {
		set_fail_stage(fail_stage, sizeof(fail_stage),
			       "monotonic_now(start_ts)");
		goto out;
	}

	interval_ns = (__u64)(sample_interval_sec * 1000000000.0);
	next_sample_ns = timespec_to_ns(&start_ts);

	print_schedule_summary(schedule.plans, schedule.nr_plans, &control);
	if (boost.supported)
		printf("Boost is disabled for this run (original=%ld)\n",
		       boost.original_value);
	printf("Monitoring isolated CPUs %d-%d every %.3f s\n",
	       ISOLATED_START, ISOLATED_END, sample_interval_sec);
	printf("Sample format: policy|scaling_cur/cpuinfo_avg MHz\n");
	printf("Logging samples to %s\n", LOG_CSV_PATH);
	printf("Logging debug samples to %s\n", LOG_DBG_PATH);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		bool policy_valid[NR_ISOLATED_CPUS] = {};
		bool scaling_valid[NR_ISOLATED_CPUS] = {};
		bool avg_valid[NR_ISOLATED_CPUS] = {};
		double policy_mhz[NR_ISOLATED_CPUS] = {};
		double scaling_mhz[NR_ISOLATED_CPUS] = {};
		double avg_mhz[NR_ISOLATED_CPUS] = {};
		struct scheduler_debug_cpu_state debug_states[NR_ISOLATED_CPUS] = {};
		struct timespec now_ts;
		double elapsed_sec;
		int i;

		ret = monotonic_now(&now_ts);
		if (ret < 0) {
			set_fail_stage(fail_stage, sizeof(fail_stage),
				       "monotonic_now(sample)");
			goto out;
		}

		elapsed_sec =
			(double)(timespec_to_ns(&now_ts) - timespec_to_ns(&start_ts)) /
			1000000000.0;

		for (i = 0; i < NR_ISOLATED_CPUS; i++) {
			ret = sample_policy_freq_mhz(&tis_readers[i], &policy_valid[i],
						     &policy_mhz[i]);
			if (ret < 0) {
				set_fail_stage(fail_stage, sizeof(fail_stage),
					       "sample_policy_freq_mhz(cpu=%d)",
					       isolated_cpus[i]);
				goto out;
			}

			ret = sample_cpu_freq_mhz(&scaling_readers[i], &scaling_valid[i],
						  &scaling_mhz[i]);
			if (ret < 0) {
				set_fail_stage(fail_stage, sizeof(fail_stage),
					       "sample_cpu_freq_mhz(scaling,cpu=%d)",
					       isolated_cpus[i]);
				goto out;
			}

			ret = sample_cpu_freq_mhz(&avg_readers[i], &avg_valid[i],
						  &avg_mhz[i]);
			if (ret < 0) {
				set_fail_stage(fail_stage, sizeof(fail_stage),
					       "sample_cpu_freq_mhz(avg,cpu=%d)",
					       isolated_cpus[i]);
				goto out;
			}
		}

		ret = read_debug_states(skel, debug_states);
		if (ret < 0) {
			set_fail_stage(fail_stage, sizeof(fail_stage),
				       "read_debug_states");
			goto out;
		}

		write_sample_line(dbg, elapsed_sec, policy_valid, policy_mhz,
				  scaling_valid, scaling_mhz, avg_valid, avg_mhz);
		write_debug_sample_line(dbg, debug_states);
		write_csv_sample(csv, elapsed_sec, policy_valid, policy_mhz,
				 scaling_valid, scaling_mhz, avg_valid, avg_mhz,
				 debug_states);
		maybe_print_progress_timer(elapsed_sec, &last_timer_sec);

		next_sample_ns += interval_ns;
		ret = sleep_until_ns(next_sample_ns);
		if (ret < 0) {
			set_fail_stage(fail_stage, sizeof(fail_stage),
				       "sleep_until_ns");
			goto out;
		}
	}

out:
	close_tis_readers(tis_readers);
	close_cpu_freq_readers(scaling_readers);
	close_cpu_freq_readers(avg_readers);
	if (csv)
		fclose(csv);
	if (dbg)
		fclose(dbg);
	if (link)
		bpf_link__destroy(link);

	if (ret < 0)
		fprintf(stderr, "USERSPACE ERROR: stage=%s ret=%d (%s)\n",
			fail_stage, ret, strerror(-ret));

	ecode = skel ? UEI_REPORT(skel, uei) : 0;
	if (skel)
		scx_scheduler__destroy(skel);

	if (!ret && UEI_ECODE_RESTART(ecode)) {
		init_tis_readers(tis_readers);
		init_cpu_freq_readers(scaling_readers);
		init_cpu_freq_readers(avg_readers);
		last_timer_sec = -1;
		csv = NULL;
		dbg = NULL;
		link = NULL;
		skel = NULL;
		exit_req = 0;
		goto restart;
	}

	if (last_timer_sec >= 0)
		printf("\n");

	restore_boost(&boost);
	free_parsed_schedule(&schedule);
	return ret < 0 ? 1 : 0;
}
