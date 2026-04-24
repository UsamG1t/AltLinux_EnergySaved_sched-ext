/* SPDX-License-Identifier: GPL-2.0 */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
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
#include "scx_sheduler_sched.h"

#define ISOLATED_START 6
#define ISOLATED_END 9
#define NR_ISOLATED_CPUS (ISOLATED_END - ISOLATED_START + 1)
#define MAX_TIME_IN_STATE_STEPS 64
#define MAX_FREQ_KHZ 1800000U
#define MIN_FREQ_KHZ 400000U

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

struct freq_step {
	__u32 step_idx;
	__u32 freq_khz;
	__u32 perf_target;
};

struct task_input {
	__u32 task_id;
	__u32 runtime_ms;
	char comm[SHEDULER_TASK_COMM_LEN];
};

struct parsed_input {
	__u64 deadline_ms;
	struct task_input *tasks;
	size_t nr_tasks;
	size_t cap_tasks;
};

struct cpu_plan_state {
	__u32 cpu;
	__u64 load_ms;
	__u32 freq_step_idx;
	__u32 freq_khz;
	__u32 perf_target;
	__u64 current_end_ns;
	__u32 next_order;
};

static const struct freq_step freq_steps[] = {
	{ 1, 400000, 48 },
	{ 2, 600000, 165 },
	{ 3, 800000, 256 },
	{ 4, 900000, 288 },
	{ 5, 1100000, 352 },
	{ 6, 1300000, 416 },
	{ 7, 1500000, 480 },
	{ 8, 1600000, 512 },
	{ 9, 1800000, 576 },
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

static int parse_deadline_line(const char *line, __u64 *deadline_ms)
{
	const char *p = line;
	char *endp;
	unsigned long long value;

	if (is_dec_char(*p)) {
		errno = 0;
		value = strtoull(p, &endp, 10);
		if (errno || endp == p)
			return 0;
		while (*endp == ' ' || *endp == '\t')
			endp++;
		if (*endp != '\0')
			return 0;
		*deadline_ms = value;
		return 1;
	}

	if (!strncmp(p, "deadline", 8))
		p += 8;
	else if (*p == 'D')
		p += 1;
	else
		return 0;

	while (*p && *p != ':' && *p != '=' && *p != ' ' && *p != '\t')
		p++;
	while (*p == ':' || *p == '=' || *p == ' ' || *p == '\t')
		p++;
	if (!is_dec_char(*p))
		return -EINVAL;

	errno = 0;
	value = strtoull(p, &endp, 10);
	if (errno || endp == p)
		return -EINVAL;
	while (*endp == ' ' || *endp == '\t')
		endp++;
	if (*endp != '\0')
		return -EINVAL;

	*deadline_ms = value;
	return 1;
}

static int parse_task_token(const char *token, struct task_input *task)
{
	const char *p = token;
	char *endp;
	unsigned long id;
	unsigned long runtime_ms;
	int len;

	if (strncmp(p, "task", 4))
		return -EINVAL;
	p += 4;

	if (!is_dec_char(*p))
		return -EINVAL;

	errno = 0;
	id = strtoul(p, &endp, 10);
	if (errno || endp == p || *endp != '_')
		return -EINVAL;
	p = endp + 1;

	if (!is_dec_char(*p))
		return -EINVAL;

	errno = 0;
	runtime_ms = strtoul(p, &endp, 10);
	if (errno || endp == p || *endp != '\0')
		return -EINVAL;

	task->task_id = (__u32)id;
	task->runtime_ms = (__u32)runtime_ms;

	len = snprintf(task->comm, sizeof(task->comm), "task%u_%u", task->task_id,
		       task->runtime_ms);
	if (len < 0 || len >= (int)sizeof(task->comm))
		return -ENAMETOOLONG;

	return 0;
}

static int add_input_task(struct parsed_input *input, const struct task_input *task)
{
	struct task_input *new_tasks;

	if (input->nr_tasks >= SHEDULER_MAX_TASKS)
		return -E2BIG;

	if (input->nr_tasks == input->cap_tasks) {
		size_t new_cap = input->cap_tasks ? input->cap_tasks * 2 : 16;

		new_tasks = realloc(input->tasks, new_cap * sizeof(*new_tasks));
		if (!new_tasks)
			return -ENOMEM;

		input->tasks = new_tasks;
		input->cap_tasks = new_cap;
	}

	input->tasks[input->nr_tasks++] = *task;
	return 0;
}

static void free_parsed_input(struct parsed_input *input)
{
	free(input->tasks);
	input->tasks = NULL;
	input->nr_tasks = 0;
	input->cap_tasks = 0;
	input->deadline_ms = 0;
}

static int parse_schedule_file(const char *path, struct parsed_input *input)
{
	FILE *file;
	char line[256];
	int line_no = 0;
	bool have_deadline = false;

	memset(input, 0, sizeof(*input));

	file = fopen(path, "r");
	if (!file) {
		perror(path);
		return -errno;
	}

	while (fgets(line, sizeof(line), file)) {
		char *token;
		char *saveptr = NULL;
		char *trimmed;
		int deadline_ret;

		line_no++;
		strip_comment(line);
		trimmed = trim_whitespace(line);
		if (!*trimmed)
			continue;

		deadline_ret = parse_deadline_line(trimmed, &input->deadline_ms);
		if (deadline_ret < 0) {
			fprintf(stderr, "%s:%d: invalid deadline line\n", path,
				line_no);
			fclose(file);
			free_parsed_input(input);
			return deadline_ret;
		}
		if (deadline_ret > 0) {
			have_deadline = true;
			continue;
		}

		for (token = strtok_r(trimmed, " \t,;", &saveptr); token;
		     token = strtok_r(NULL, " \t,;", &saveptr)) {
			struct task_input task;
			int ret;

			ret = parse_task_token(token, &task);
			if (ret < 0) {
				fprintf(stderr, "%s:%d: invalid task token '%s'\n",
					path, line_no, token);
				fclose(file);
				free_parsed_input(input);
				return ret;
			}

			ret = add_input_task(input, &task);
			if (ret < 0) {
				fclose(file);
				free_parsed_input(input);
				return ret;
			}
		}
	}

	fclose(file);

	if (!have_deadline || !input->deadline_ms) {
		fprintf(stderr, "%s: deadline is missing\n", path);
		free_parsed_input(input);
		return -EINVAL;
	}
	if (!input->nr_tasks) {
		fprintf(stderr, "%s: task set is empty\n", path);
		free_parsed_input(input);
		return -EINVAL;
	}

	return 0;
}

static int compare_task_id(const void *a, const void *b)
{
	const struct task_input *ta = a;
	const struct task_input *tb = b;

	if (ta->task_id < tb->task_id)
		return -1;
	if (ta->task_id > tb->task_id)
		return 1;
	return 0;
}

static int compare_task_runtime_desc(const void *a, const void *b)
{
	const struct task_input *ta = a;
	const struct task_input *tb = b;

	if (ta->runtime_ms > tb->runtime_ms)
		return -1;
	if (ta->runtime_ms < tb->runtime_ms)
		return 1;
	if (ta->task_id < tb->task_id)
		return -1;
	if (ta->task_id > tb->task_id)
		return 1;
	return 0;
}

static int compare_plan_cpu_order(const void *a, const void *b)
{
	const struct sheduler_task_plan *pa = a;
	const struct sheduler_task_plan *pb = b;

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

static int validate_input_tasks(struct parsed_input *input)
{
	size_t i;

	qsort(input->tasks, input->nr_tasks, sizeof(*input->tasks), compare_task_id);

	for (i = 0; i < input->nr_tasks; i++) {
		if (!input->tasks[i].runtime_ms) {
			fprintf(stderr, "task%u has zero runtime\n",
				input->tasks[i].task_id);
			return -EINVAL;
		}
		if (i > 0 && input->tasks[i - 1].task_id == input->tasks[i].task_id) {
			fprintf(stderr, "duplicate task id %u\n",
				input->tasks[i].task_id);
			return -EINVAL;
		}
	}

	return 0;
}

static __u64 ceil_div_u64(__u64 num, __u64 den)
{
	return (num + den - 1) / den;
}

static __u64 task_duration_ns(__u32 runtime_ms, __u32 freq_khz)
{
	return ceil_div_u64((__u64)runtime_ms * MAX_FREQ_KHZ * 1000000ULL,
			    freq_khz);
}

static const struct freq_step *find_step_for_required_khz(__u32 required_khz)
{
	size_t i;

	if (required_khz < MIN_FREQ_KHZ)
		required_khz = MIN_FREQ_KHZ;

	for (i = 0; i < sizeof(freq_steps) / sizeof(freq_steps[0]); i++) {
		if (freq_steps[i].freq_khz >= required_khz)
			return &freq_steps[i];
	}

	return NULL;
}

static size_t choose_least_loaded_cpu(const struct cpu_plan_state *cpus)
{
	size_t best = 0;
	size_t i;

	for (i = 1; i < NR_ISOLATED_CPUS; i++) {
		if (cpus[i].load_ms < cpus[best].load_ms) {
			best = i;
			continue;
		}
		if (cpus[i].load_ms == cpus[best].load_ms &&
		    cpus[i].cpu < cpus[best].cpu)
			best = i;
	}

	return best;
}

static int choose_cpu_frequency(const struct sheduler_task_plan *plans,
				size_t nr_plans, struct cpu_plan_state *cpu,
				__u64 deadline_ms)
{
	const struct freq_step *step;
	size_t step_idx;

	if (!cpu->load_ms) {
		step = &freq_steps[0];
		cpu->freq_step_idx = step->step_idx;
		cpu->freq_khz = step->freq_khz;
		cpu->perf_target = step->perf_target;
		return 0;
	}

	if (cpu->load_ms > deadline_ms) {
		fprintf(stderr,
			"CPU %u load %llu ms exceeds deadline %llu ms even at max frequency\n",
			cpu->cpu, (unsigned long long)cpu->load_ms,
			(unsigned long long)deadline_ms);
		return -ERANGE;
	}

	step = find_step_for_required_khz((__u32)ceil_div_u64(
		cpu->load_ms * (__u64)MAX_FREQ_KHZ, deadline_ms));
	if (!step)
		return -ERANGE;

	for (step_idx = step->step_idx - 1;
	     step_idx < sizeof(freq_steps) / sizeof(freq_steps[0]); step_idx++) {
		__u64 total_ns = 0;
		size_t i;

		for (i = 0; i < nr_plans; i++) {
			if (plans[i].cpu != cpu->cpu)
				continue;
			total_ns += task_duration_ns(plans[i].runtime_ms,
						    freq_steps[step_idx].freq_khz);
		}

		if (total_ns <= deadline_ms * 1000000ULL) {
			cpu->freq_step_idx = freq_steps[step_idx].step_idx;
			cpu->freq_khz = freq_steps[step_idx].freq_khz;
			cpu->perf_target = freq_steps[step_idx].perf_target;
			return 0;
		}
	}

	fprintf(stderr, "CPU %u cannot fit into deadline after step rounding\n",
		cpu->cpu);
	return -ERANGE;
}

static int build_ltf_schedule(const struct parsed_input *input,
			      struct sheduler_task_plan **plans_out,
			      struct sheduler_schedule_control *control)
{
	struct task_input *sorted_tasks;
	struct sheduler_task_plan *plans;
	struct cpu_plan_state cpus[NR_ISOLATED_CPUS] = {};
	size_t i;
	int ret;

	sorted_tasks = malloc(input->nr_tasks * sizeof(*sorted_tasks));
	plans = calloc(input->nr_tasks, sizeof(*plans));
	if (!sorted_tasks || !plans) {
		free(sorted_tasks);
		free(plans);
		return -ENOMEM;
	}

	memcpy(sorted_tasks, input->tasks, input->nr_tasks * sizeof(*sorted_tasks));
	qsort(sorted_tasks, input->nr_tasks, sizeof(*sorted_tasks),
	      compare_task_runtime_desc);

	for (i = 0; i < NR_ISOLATED_CPUS; i++)
		cpus[i].cpu = isolated_cpus[i];

	for (i = 0; i < input->nr_tasks; i++) {
		size_t cpu_idx = choose_least_loaded_cpu(cpus);

		plans[i].task_id = sorted_tasks[i].task_id;
		plans[i].runtime_ms = sorted_tasks[i].runtime_ms;
		plans[i].cpu = cpus[cpu_idx].cpu;
		cpus[cpu_idx].load_ms += sorted_tasks[i].runtime_ms;
	}

	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		ret = choose_cpu_frequency(plans, input->nr_tasks, &cpus[i],
					   input->deadline_ms);
		if (ret < 0) {
			free(sorted_tasks);
			free(plans);
			return ret;
		}
	}

	for (i = 0; i < input->nr_tasks; i++) {
		size_t cpu_idx = plans[i].cpu - ISOLATED_START;
		struct cpu_plan_state *cpu = &cpus[cpu_idx];

		plans[i].freq_step_idx = cpu->freq_step_idx;
		plans[i].freq_khz = cpu->freq_khz;
		plans[i].perf_target = cpu->perf_target;
		plans[i].order = cpu->next_order++;
		plans[i].start_ns = cpu->current_end_ns;
		plans[i].duration_ns =
			task_duration_ns(plans[i].runtime_ms, cpu->freq_khz);
		cpu->current_end_ns += plans[i].duration_ns;
	}

	memset(control, 0, sizeof(*control));
	control->deadline_ns = input->deadline_ms * 1000000ULL;
	control->nr_tasks = input->nr_tasks;

	free(sorted_tasks);
	*plans_out = plans;
	return 0;
}

static void print_schedule_summary(const struct sheduler_task_plan *plans,
				   size_t nr_plans,
				   const struct sheduler_schedule_control *control)
{
	struct sheduler_task_plan *sorted;
	size_t i;

	sorted = malloc(nr_plans * sizeof(*sorted));
	if (!sorted)
		return;

	memcpy(sorted, plans, nr_plans * sizeof(*sorted));
	qsort(sorted, nr_plans, sizeof(*sorted), compare_plan_cpu_order);

	printf("Loaded LTF schedule for %u tasks, deadline %.3f ms\n",
	       control->nr_tasks, (double)control->deadline_ns / 1000000.0);

	for (i = 0; i < nr_plans; i++) {
		const struct sheduler_task_plan *plan = &sorted[i];

		if (i == 0 || sorted[i - 1].cpu != plan->cpu) {
			printf("CPU%u freq=%u kHz step=%u\n", plan->cpu,
			       plan->freq_khz, plan->freq_step_idx);
		}

		printf("  order=%u task%u_%u start=%.3fms duration=%.3fms\n",
		       plan->order, plan->task_id, plan->runtime_ms,
		       (double)plan->start_ns / 1000000.0,
		       (double)plan->duration_ns / 1000000.0);
	}

	free(sorted);
}

static int load_schedule_maps(struct scx_sheduler *skel,
			      const struct sheduler_schedule_control *control,
			      const struct sheduler_task_plan *plans,
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

static void free_plans(struct sheduler_task_plan *plans)
{
	free(plans);
}

int main(int argc, char **argv)
{
	struct scx_sheduler *skel = NULL;
	struct bpf_link *link = NULL;
	struct cpu_tis_reader tis_readers[NR_ISOLATED_CPUS];
	struct boost_state boost = {};
	struct parsed_input input = {};
	struct sheduler_task_plan *plans = NULL;
	struct sheduler_schedule_control control = {};
	struct timespec start_ts;
	FILE *csv = NULL;
	double sample_interval_sec = 1.0;
	const char *schedule_path = NULL;
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
			fprintf(stderr, "Usage: %s [-f interval_sec] <task_file>\n",
				argv[0]);
			return opt != 'h';
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Usage: %s [-f interval_sec] <task_file>\n", argv[0]);
		return 1;
	}
	schedule_path = argv[optind];

	ret = parse_schedule_file(schedule_path, &input);
	if (ret < 0)
		return 1;

	ret = validate_input_tasks(&input);
	if (ret < 0)
		goto out;

	ret = build_ltf_schedule(&input, &plans, &control);
	if (ret < 0)
		goto out;

	ret = disable_boost(&boost);
	if (ret < 0)
		goto out;

restart:
	skel = SCX_OPS_OPEN(sheduler_ops, scx_sheduler);
	SCX_OPS_LOAD(skel, sheduler_ops, scx_sheduler, uei);

	ret = load_schedule_maps(skel, &control, plans, input.nr_tasks);
	if (ret < 0)
		goto out;

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

	print_schedule_summary(plans, input.nr_tasks, &control);
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
	free_plans(plans);
	free_parsed_input(&input);
	return ret < 0 ? 1 : 0;
}
