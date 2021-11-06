#ifndef CPUPOWER_UTILS_IDLE_MONITOR_CPUIDLE_MONITOR_H_
#define CPUPOWER_UTILS_IDLE_MONITOR_CPUIDLE_MONITOR_H_

#include <stdbool.h>

#define MONITOR_NAME_LEN 20

typedef struct cstate cstate_t;

struct cpuidle_monitor {
	/* Name must not contain whitespaces */
	char name[MONITOR_NAME_LEN];
	unsigned int name_len;
	unsigned int hw_states_num;
	cstate_t *hw_states;
	int (*start) (void);
	int (*stop) (void);
	struct cpuidle_monitor* (*do_register) (void);
	void (*unregister)(void);
	unsigned int overflow_s;
	struct {
		bool needs_root:1;
		bool per_cpu_schedule:1;
	} flags;
};

#endif /* CPUPOWER_UTILS_IDLE_MONITOR_CPUIDLE_MONITOR_H_ */
