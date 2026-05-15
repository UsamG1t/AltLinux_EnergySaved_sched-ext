#ifndef __SCX_SCHEDULER_SCHED_H
#define __SCX_SCHEDULER_SCHED_H

#define SCHEDULER_MAX_TASKS 1024
#define SCHEDULER_TASK_COMM_LEN 16

enum scheduler_debug_event {
	SCHEDULER_DEBUG_NONE = 0,
	SCHEDULER_DEBUG_PLANNED_RUNNING = 1,
	SCHEDULER_DEBUG_UNPLANNED_RUNNING_ZERO = 2,
	SCHEDULER_DEBUG_STOPPING_ZERO = 3,
	SCHEDULER_DEBUG_IDLE_ZERO = 4,
};

struct schedule_task_plan {
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

struct scheduler_debug_cpu_state {
	__u64 running_planned_hits;
	__u64 running_unplanned_hits;
	__u64 perf_apply_hits;
	__u64 zero_from_running_hits;
	__u64 zero_from_stopping_hits;
	__u64 zero_from_idle_hits;
	__u32 last_event;
	__u32 last_perf;
	__u32 last_plan_task_id;
	__u32 last_plan_step_idx;
	__u32 last_plan_freq_khz;
	__u32 last_plan_pid;
	__u32 last_plan_tgid;
	char last_plan_comm[SCHEDULER_TASK_COMM_LEN];
	__u32 last_actor_pid;
	__u32 last_actor_tgid;
	char last_actor_comm[SCHEDULER_TASK_COMM_LEN];
};

struct schedule_control {
	__u64 deadline_ns;
	__u32 nr_tasks;
	__u32 reserved;
};

#endif
