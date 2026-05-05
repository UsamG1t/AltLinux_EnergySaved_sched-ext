#include <errno.h>
#include <libgen.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_WORK_UNITS_PER_MS 233ULL
#define DEFAULT_ROUNDS_PER_UNIT 256UL

static volatile uint64_t global_sink;

struct task_name {
	unsigned long task_id;
	unsigned long runtime_ms;
	bool has_runtime_in_name;
};

static int parse_ulong_env(const char *name, unsigned long long *value)
{
	const char *env;
	char *endp;
	unsigned long long parsed;

	env = getenv(name);
	if (!env || !*env)
		return 0;

	errno = 0;
	parsed = strtoull(env, &endp, 10);
	if (errno || endp == env || *endp != '\0')
		return -EINVAL;

	*value = parsed;
	return 1;
}

static bool is_dec_char(char c)
{
	return c >= '0' && c <= '9';
}

static int parse_task_name(const char *argv0, struct task_name *task)
{
	char local_path[PATH_MAX];
	char *base;
	char *p;
	char *endp;

	if (snprintf(local_path, sizeof(local_path), "%s", argv0) >=
	    (int)sizeof(local_path))
		return -ENAMETOOLONG;

	base = basename(local_path);
	if (strncmp(base, "task", 4))
		return -EINVAL;
	p = base + 4;

	if (!is_dec_char(*p))
		return -EINVAL;

	errno = 0;
	task->task_id = strtoul(p, &endp, 10);
	if (errno || endp == p)
		return -EINVAL;

	if (*endp == '\0') {
		task->runtime_ms = 0;
		task->has_runtime_in_name = false;
		return 0;
	}
	if (*endp != '_')
		return -EINVAL;
	p = endp + 1;

	if (!is_dec_char(*p))
		return -EINVAL;

	errno = 0;
	task->runtime_ms = strtoul(p, &endp, 10);
	if (errno || endp == p || *endp != '\0')
		return -EINVAL;

	task->has_runtime_in_name = true;

	return 0;
}

static int parse_runtime_arg(const char *arg, unsigned long *runtime_ms)
{
	char *endp;
	unsigned long parsed;

	if (!arg || !*arg || !is_dec_char(*arg))
		return -EINVAL;

	errno = 0;
	parsed = strtoul(arg, &endp, 10);
	if (errno || endp == arg || *endp != '\0')
		return -EINVAL;

	*runtime_ms = parsed;
	return 0;
}

static inline uint64_t rotl64(uint64_t value, unsigned int shift)
{
	return (value << shift) | (value >> (64 - shift));
}

static void run_workload(unsigned long long work_units,
			 unsigned long long rounds_per_unit)
{
	unsigned long long unit;
	uint64_t a0 = 0x243f6a8885a308d3ULL;
	uint64_t a1 = 0x13198a2e03707344ULL;
	uint64_t a2 = 0xa4093822299f31d0ULL;
	uint64_t a3 = 0x082efa98ec4e6c89ULL;
	uint64_t a4 = 0x452821e638d01377ULL;
	uint64_t a5 = 0xbe5466cf34e90c6cULL;
	uint64_t a6 = 0xc0ac29b7c97c50ddULL;
	uint64_t a7 = 0x3f84d5b5b5470917ULL;

	for (unit = 0; unit < work_units; unit++) {
		unsigned long long round;
		uint64_t seed = 0x9e3779b97f4a7c15ULL * (unit + 1);

		for (round = 0; round < rounds_per_unit; round++) {
			seed += 0x9e3779b97f4a7c15ULL;

			a0 = a0 * 0xbf58476d1ce4e5b9ULL + rotl64(seed ^ a4, 7);
			a1 = a1 * 0x94d049bb133111ebULL + rotl64(seed + a5, 11);
			a2 = a2 * 0xd6e8feb86659fd93ULL + rotl64(seed ^ a6, 13);
			a3 = a3 * 0xa0761d6478bd642fULL + rotl64(seed + a7, 17);
			a4 = a4 * 0xe7037ed1a0b428dbULL + rotl64(seed ^ a0, 19);
			a5 = a5 * 0x8ebc6af09c88c6e3ULL + rotl64(seed + a1, 23);
			a6 = a6 * 0x589965cc75374cc3ULL + rotl64(seed ^ a2, 29);
			a7 = a7 * 0x1d8e4e27c47d124fULL + rotl64(seed + a3, 31);
		}
	}

	global_sink = a0 ^ a1 ^ a2 ^ a3 ^ a4 ^ a5 ^ a6 ^ a7;
}

int main(int argc, char **argv)
{
	struct task_name task;
	unsigned long long work_units_per_ms = DEFAULT_WORK_UNITS_PER_MS;
	unsigned long long rounds_per_unit = DEFAULT_ROUNDS_PER_UNIT;
	unsigned long long work_units;
	int ret;

	(void)argc;

	ret = parse_task_name(argv[0], &task);
	if (ret < 0) {
		fprintf(stderr,
			"Expected executable name like task<N> or task<N>_<runtime_ms>, got '%s'\n",
			argv[0]);
		return 1;
	}

	if (!task.has_runtime_in_name) {
		if (argc < 2) {
			fprintf(stderr,
				"Short task name '%s' requires runtime_ms as argv[1]\n",
				argv[0]);
			return 1;
		}

		ret = parse_runtime_arg(argv[1], &task.runtime_ms);
		if (ret < 0 || !task.runtime_ms) {
			fprintf(stderr, "Invalid runtime_ms argument '%s'\n", argv[1]);
			return 1;
		}
	}

	ret = parse_ulong_env("TASK_WORK_UNITS_PER_MS", &work_units_per_ms);
	if (ret < 0) {
		fprintf(stderr, "Invalid TASK_WORK_UNITS_PER_MS\n");
		return 1;
	}

	ret = parse_ulong_env("TASK_ROUNDS_PER_UNIT", &rounds_per_unit);
	if (!ret)
		ret = parse_ulong_env("TASK_VECTOR_LEN", &rounds_per_unit);
	if (ret < 0 || !rounds_per_unit) {
		fprintf(stderr, "Invalid TASK_ROUNDS_PER_UNIT/TASK_VECTOR_LEN\n");
		return 1;
	}

	work_units = (unsigned long long)task.runtime_ms * work_units_per_ms;
	run_workload(work_units, rounds_per_unit);

	if (global_sink == 0x123456789abcdef0ULL)
		fprintf(stderr, "impossible sink value: %llu\n",
			(unsigned long long)global_sink);

	return 0;
}
