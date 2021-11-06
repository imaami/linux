#ifndef	CPUPOWER_UTILS_IDLE_MONITOR_MPERF_MONITOR_H_
#define CPUPOWER_UTILS_IDLE_MONITOR_MPERF_MONITOR_H_

#include "cpuidle_monitor.h"

#define to_mperf_monitor(mon) \
	container_of((mon), struct mperf_monitor, cpuidle)

struct mperf_monitor {
	struct cpuidle_monitor cpuidle;
};

#endif /* CPUPOWER_UTILS_IDLE_MONITOR_MPERF_MONITOR_H_ */
