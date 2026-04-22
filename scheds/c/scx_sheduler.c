/* SPDX-License-Identifier: GPL-2.0 */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <scx/common.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "scx_sheduler.bpf.skel.h"

#define ISOLATED_START 6
#define ISOLATED_END 9
#define NR_ISOLATED_CPUS (ISOLATED_END - ISOLATED_START + 1)
#define MAX_TIME_IN_STATE_STEPS 64

#define LOG_DIR "/tmp/scx_sheduler"
#define LOG_CSV_PATH LOG_DIR "/latest.csv"
#define CPUFREQ_BOOST_PATH "/sys/devices/system/cpu/cpufreq/boost"

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

static void write_csv_header(FILE *csv)
{
	int i;

	fprintf(csv, "elapsed_sec");
	for (i = 0; i < NR_ISOLATED_CPUS; i++)
		fprintf(csv, ",cpu%d_policy_mhz", isolated_cpus[i]);
	fprintf(csv, "\n");
}

static void write_csv_sample(FILE *csv, double elapsed_sec, const bool *valid,
			     const double *policy_mhz)
{
	int i;

	fprintf(csv, "%.6f", elapsed_sec);
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		if (valid[i])
			fprintf(csv, ",%.6f", policy_mhz[i]);
		else
			fprintf(csv, ",nan");
	}
	fprintf(csv, "\n");
}

static void print_sample(double elapsed_sec, const bool *valid,
			 const double *policy_mhz)
{
	int i;

	printf("t=%8.3fs", elapsed_sec);
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		if (valid[i])
			printf(" cpu%d=%8.3fMHz", isolated_cpus[i], policy_mhz[i]);
		else
			printf(" cpu%d=%8sMHz", isolated_cpus[i], "n/a");
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	struct scx_sheduler *skel = NULL;
	struct bpf_link *link = NULL;
	struct cpu_tis_reader tis_readers[NR_ISOLATED_CPUS];
	struct boost_state boost = {};
	struct timespec start_ts;
	FILE *csv = NULL;
	double sample_interval_sec = 1.0;
	__u64 ecode;
	__u64 interval_ns;
	__u64 next_sample_ns;
	int opt;
	int ret = 0;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	setvbuf(stdout, NULL, _IOLBF, 0);
	init_isolated_cpus();
	init_tis_readers(tis_readers);

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
			fprintf(stderr,
				"Usage: %s [-f interval_sec]\n",
				argv[0]);
			return opt != 'h';
		}
	}

	ret = disable_boost(&boost);
	if (ret < 0)
		return 1;

restart:
	skel = SCX_OPS_OPEN(sheduler_ops, scx_sheduler);
	SCX_OPS_LOAD(skel, sheduler_ops, scx_sheduler, uei);
	link = SCX_OPS_ATTACH(skel, sheduler_ops, scx_sheduler);

	ret = ensure_log_dir();
	if (ret < 0)
		goto out;

	csv = open_log_file(LOG_CSV_PATH);
	if (!csv) {
		ret = -errno;
		goto out;
	}
	write_csv_header(csv);

	ret = open_all_tis_readers(tis_readers);
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
	printf("Monitoring isolated CPUs 6-9 every %.3f s\n",
	       sample_interval_sec);
	printf("Sample format: policy MHz from time_in_state\n");
	printf("Logging samples to %s\n", LOG_CSV_PATH);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		bool valid[NR_ISOLATED_CPUS] = {};
		double policy_mhz[NR_ISOLATED_CPUS] = {};
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
			ret = sample_policy_freq_mhz(&tis_readers[i], &valid[i],
						     &policy_mhz[i]);
			if (ret < 0)
				goto out;
		}

		print_sample(elapsed_sec, valid, policy_mhz);
		write_csv_sample(csv, elapsed_sec, valid, policy_mhz);

		next_sample_ns += interval_ns;
		ret = sleep_until_ns(next_sample_ns);
		if (ret < 0)
			goto out;
	}

out:
	close_tis_readers(tis_readers);
	if (csv)
		fclose(csv);
	if (link)
		bpf_link__destroy(link);

	ecode = skel ? UEI_REPORT(skel, uei) : 0;
	if (skel)
		scx_sheduler__destroy(skel);

	if (!ret && UEI_ECODE_RESTART(ecode)) {
		init_tis_readers(tis_readers);
		csv = NULL;
		link = NULL;
		skel = NULL;
		exit_req = 0;
		goto restart;
	}

	restore_boost(&boost);
	return ret < 0 ? 1 : 0;
}
