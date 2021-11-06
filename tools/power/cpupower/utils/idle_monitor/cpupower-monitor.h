/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  (C) 2010,2011       Thomas Renninger <trenn@suse.de>, Novell Inc.
 */

#ifndef __CPUIDLE_INFO_HW__
#define __CPUIDLE_INFO_HW__

#include <stdbool.h>
#include <stdarg.h>
#include <time.h>

#include "idle_monitor/idle_monitors.h"

#define PER_CPU_TSC
//#define PER_CPU_THREAD
//#define BENCHMARK
//#define NAIVE_CPU_ORDER

#ifdef PER_CPU_THREAD
#ifndef PER_CPU_TSC
#define PER_CPU_TSC
#endif
#endif

#define MONITORS_MAX 20

/* CSTATE_NAME_LEN is limited by header field width defined
 * in cpupower-monitor.c. Header field width is defined to be
 * sum of percent width and two spaces for padding.
 */
#ifdef __powerpc__
#define CSTATE_NAME_LEN 7
#else
#define CSTATE_NAME_LEN 5
#endif
#define CSTATE_DESC_LEN 60

extern int cpu_count;

/* Hard to define the right names ...: */
enum power_range_e {
	RANGE_THREAD,	/* Lowest in topology hierarcy, AMD: core, Intel: thread
			   kernel sysfs: cpu */
	RANGE_CORE,	/* AMD: unit, Intel: core, kernel_sysfs: core_id */
	RANGE_PACKAGE,	/* Package, processor socket */
	RANGE_MACHINE,	/* Machine, platform wide */
	RANGE_MAX
};

struct cstate {
	int  id;
	enum power_range_e range;
	char name[CSTATE_NAME_LEN];
	char desc[CSTATE_DESC_LEN];

	/* either provide a percentage or a general count */
	int (*get_count_percent)(unsigned int self_id, double *percent,
				 unsigned int cpu);
	int (*get_count)(unsigned int self_id, unsigned long long *count,
			 unsigned int cpu);
};

extern struct timespec get_monitor_interval(void);

extern long long timespec_diff_us(struct timespec start, struct timespec end);

#define print_overflow_err(mes, ov) do {				\
		fprintf(stderr, gettext("Measure took %u seconds, but "	\
					"registers could overflow at "	\
					"%u seconds, results could be "	\
					"inaccurate\n"), mes, ov);	\
	} while(0)

/* Taken over from x86info project sources  -> return 0 on success */
#include <sched.h>
#include <sys/types.h>
#include <unistd.h>
static inline int bind_cpu(int cpu)
{
	cpu_set_t set;

	if (sched_getaffinity(getpid(), sizeof(set), &set) == 0) {
		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		return sched_setaffinity(getpid(), sizeof(set), &set);
	}
	return 1;
}

#ifndef BENCHMARK
extern unsigned int mperf_print_footer(void);
#endif

#endif /* __CPUIDLE_INFO_HW__ */
