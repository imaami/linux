#ifndef	CPUPOWER_UTILS_IDLE_MONITOR_MPERF_MONITOR_H_
#define CPUPOWER_UTILS_IDLE_MONITOR_MPERF_MONITOR_H_

#include <limits.h>
#include <stddef.h>

#include "cpuidle_monitor.h"

#define MAX_CPUS 32

#define UL_BIT (CHAR_BIT * sizeof(unsigned long))
#define UL_CPUMASK_LEN(n) (((size_t)(n) + UL_BIT - 1u) / UL_BIT)
#define UL_CPUMASK(cpus) struct { unsigned long __bits[UL_CPUMASK_LEN(cpus)]; }

typedef UL_CPUMASK(MAX_CPUS) cpu_af_t;

#define to_mperf_monitor(mon) \
	container_of((mon), struct mperf_monitor, cpuidle)

struct measurement;

struct mperf_monitor {
	struct cpuidle_monitor cpuidle;
	struct measurement *stats;

#ifndef PER_CPU_THREAD
	cpu_af_t cpu_affinity;
#endif
};

#endif /* CPUPOWER_UTILS_IDLE_MONITOR_MPERF_MONITOR_H_ */
