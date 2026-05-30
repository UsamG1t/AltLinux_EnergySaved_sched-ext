#ifndef __SCX_BORDERS_SCHED_H
#define __SCX_BORDERS_SCHED_H

#define BORDERS_MAX_TASKS 1024
#define BORDERS_TASK_COMM_LEN 16

enum borders_debug_event {
	BORDERS_DEBUG_NONE = 0,
	BORDERS_DEBUG_PLANNED_RUNNING = 1,
	BORDERS_DEBUG_UNPLANNED_RUNNING_KEEP = 2,
	BORDERS_DEBUG_UNPLANNED_RUNNING_ZERO = 3,
	BORDERS_DEBUG_STOPPING_ZERO = 4,
	BORDERS_DEBUG_IDLE_ZERO = 5,
};

struct borders_task_plan {
	__u32 task_id;
	__u32 runtime_ms;
	__u32 ready_ms;
	__u32 cpu;
	__u32 freq_step_idx;
	__u32 freq_khz;
	__u32 order;
	__u64 start_ns;
	__u64 duration_ns;
};

struct borders_debug_cpu_state {
	__u64 running_planned_hits;
	__u64 running_unplanned_hits;
	__u64 keep_from_running_hits;
	__u64 border_apply_hits;
	__u64 zero_from_running_hits;
	__u64 zero_from_stopping_hits;
	__u64 zero_from_idle_hits;
	__u32 last_event;
	__u32 last_border_khz;
	__u32 last_plan_task_id;
	__u32 last_plan_step_idx;
	__u32 last_plan_freq_khz;
	__u32 last_plan_pid;
	__u32 last_plan_tgid;
	char last_plan_comm[BORDERS_TASK_COMM_LEN];
	__u32 last_actor_pid;
	__u32 last_actor_tgid;
	char last_actor_comm[BORDERS_TASK_COMM_LEN];
};

struct borders_control {
	__u64 deadline_ns;
	__u32 nr_tasks;
	__u32 reserved;
};

#endif
