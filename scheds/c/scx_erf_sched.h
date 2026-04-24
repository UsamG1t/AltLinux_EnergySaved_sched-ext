#ifndef __SCX_ERF_SCHED_H
#define __SCX_ERF_SCHED_H

#define SHEDULER_MAX_TASKS 1024
#define SHEDULER_TASK_COMM_LEN 16

struct erf_task_plan {
	__u32 task_id;
	__u32 runtime_ms;
	__u32 ready_ms;
	__u32 cpu;
	__u32 freq_step_idx;
	__u32 freq_khz;
	__u32 perf_target;
	__u32 order;
	__u64 start_ns;
	__u64 duration_ns;
};

struct erf_schedule_control {
	__u64 deadline_ns;
	__u32 nr_tasks;
	__u32 reserved;
};

#endif
