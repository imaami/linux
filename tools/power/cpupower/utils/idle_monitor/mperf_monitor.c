// SPDX-License-Identifier: GPL-2.0-only
/*
 *  (C) 2010,2011       Thomas Renninger <trenn@suse.de>, Novell Inc.
 */

#if defined(__i386__) || defined(__x86_64__)

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cpufreq.h>

#include "helpers/helpers.h"
#include "idle_monitor/cpupower-monitor.h"
#include "idle_monitor/mperf_monitor.h"

#ifdef PER_CPU_THREAD
#include <pthread.h>
#include <semaphore.h>
#endif

#define MSR_APERF	0xE8
#define MSR_MPERF	0xE7

#define RDPRU ".byte 0x0f, 0x01, 0xfd"
#define RDPRU_ECX_MPERF	0
#define RDPRU_ECX_APERF	1

#define MSR_TSC	0x10

#define MSR_AMD_HWCR 0xc0010015

enum mperf_id { C0 = 0, Cx, AVG_FREQ, MPERF_CSTATE_COUNT };

static int mperf_get_count_percent(unsigned int self_id, double *percent,
				   unsigned int cpu);
static int mperf_get_count_freq(unsigned int id, unsigned long long *count,
				unsigned int cpu);
//static struct timespec time_start, time_end;
static unsigned long long time_diff;

static cstate_t mperf_cstates[MPERF_CSTATE_COUNT] = {
	[C0] = {
		.name			= "C0",
		.desc			= N_("Processor Core not idle"),
		.id			= C0,
		.range			= RANGE_THREAD,
		.get_count_percent	= mperf_get_count_percent,
	},

	[Cx] = {
		.name			= "Cx",
		.desc			= N_("Processor Core in an idle state"),
		.id			= Cx,
		.range			= RANGE_THREAD,
		.get_count_percent	= mperf_get_count_percent,
	},

	[AVG_FREQ] = {
		.name			= "Freq",
		.desc			= N_("Average Frequency (including boost) in MHz"),
		.id			= AVG_FREQ,
		.range			= RANGE_THREAD,
		.get_count		= mperf_get_count_freq,
	},
};

enum MAX_FREQ_MODE { MAX_FREQ_SYSFS, MAX_FREQ_TSC_REF };
static int max_freq_mode;
/*
 * The max frequency mperf is ticking at (in C0), either retrieved via:
 *   1) calculated after measurements if we know TSC ticks at mperf/P0 frequency
 *   2) cpufreq /sys/devices/.../cpu0/cpufreq/cpuinfo_max_freq at init time
 * 1. Is preferred as it also works without cpufreq subsystem (e.g. on Xen)
 */
static float max_frequency;

#ifndef PER_CPU_TSC
static unsigned long long tsc_at_measure_start;
static unsigned long long tsc_at_measure_end;
static unsigned long long tsc_diff;
#endif

static double avg_freq[15];

struct aperf_mperf {
	uint64_t a;
	uint64_t m;
};

struct measurement {
	struct aperf_mperf perf;
#ifdef PER_CPU_TSC
	uint64_t tsc;
#endif
	uint64_t freq;
#ifndef PER_CPU_THREAD
	cpu_af_t cpu_affinity;
#endif
	bool is_valid;
};

#ifdef PER_CPU_THREAD
struct cpu_thread {
	pthread_t id;
};
#endif

#ifndef PER_CPU_THREAD
static cpu_af_t cpu_affinity;
#endif
static struct measurement *stats;

static const int cpu_topo[32] = {
#ifndef NAIVE_CPU_ORDER
	0x00, 0x10, 0x01, 0x11, 0x02, 0x12, 0x03, 0x13,
	0x04, 0x14, 0x05, 0x15, 0x06, 0x16, 0x07, 0x17,
	0x08, 0x18, 0x09, 0x19, 0x0a, 0x1a, 0x0b, 0x1b,
	0x0c, 0x1c, 0x0d, 0x1d, 0x0e, 0x1e, 0x0f, 0x1f
#else
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
#endif
};

#ifdef PER_CPU_THREAD
static struct cpu_thread *cpu_thread;
static sem_t thd_sem[3];
#endif

/*
static __always_inline int mperf_get_tsc(unsigned long long *tsc)
{
	return read_msr(base_cpu, MSR_TSC, tsc);
}
*/

static __always_inline void mperf_rdtsc(uint64_t *tsc)
{
	unsigned long low, high;
	asm volatile("lfence; rdtsc"
		     : "=a" (low), "=d" (high));
	*tsc = (uint64_t)low | ((uint64_t)high << 32u);
}

static __always_inline void get_aperf_mperf_rdpru(struct aperf_mperf *dest)
{
	unsigned long low_a, high_a;
	unsigned long low_m, high_m;

	asm volatile(RDPRU
		     : "=a" (low_a), "=d" (high_a)
		     : "c" (RDPRU_ECX_APERF));
	asm volatile(RDPRU
		     : "=a" (low_m), "=d" (high_m)
		     : "c" (RDPRU_ECX_MPERF));

	dest->a = (uint64_t)low_a | ((uint64_t)high_a << 32u);
	dest->m = (uint64_t)low_m | ((uint64_t)high_m << 32u);
}

/*
static int get_aperf_mperf_msr(struct aperf_mperf *dest, int cpu)
{
	int ret;
	unsigned long long a = 0u, m = 0u;

	ret  = read_msr(cpu, MSR_APERF, &a);
	ret |= read_msr(cpu, MSR_MPERF, &m);

	dest->a = (uint64_t)a;
	dest->m = (uint64_t)m;

	return ret;
}
*/

static __always_inline uint64_t get_cpu_tsc_sample(unsigned int cpu
						   __attribute__((unused)))
{
#ifdef PER_CPU_TSC
	return stats[cpu].tsc;
#else
	return tsc_diff;
#endif
}

static int mperf_get_count_percent(unsigned int id, double *percent,
				   unsigned int cpu)
{
	float div, flt;

	if (!stats[cpu].is_valid)
		return -1;

	switch (max_freq_mode) {
	case MAX_FREQ_SYSFS:
		div = max_frequency * (float)time_diff;
		break;
	case MAX_FREQ_TSC_REF:
		div = (float)(get_cpu_tsc_sample(cpu));
		break;
	default:
		return -1;
	}

	flt = (100.f * (float)stats[cpu].perf.m) / div;
	*percent = (double)((id != Cx) ? flt : 100.f - flt);

	return 0;
}

static int mperf_get_count_freq(unsigned int id, unsigned long long *count,
				unsigned int cpu)
{
	if (!stats[cpu].is_valid)
		return -1;
	*count = stats[cpu].freq;
	return 0;
}

static __always_inline void mperf_init_stats_rdpru(int cpu)
{
#ifdef PER_CPU_TSC
	mperf_rdtsc(&stats[cpu].tsc);
#endif
	get_aperf_mperf_rdpru(&stats[cpu].perf);
	stats[cpu].is_valid = true;
}

static __always_inline void mperf_init_stats_rdpru_cpusched(int cpu)
{
#ifndef PER_CPU_THREAD
	if (sched_setaffinity(0, sizeof(cpu_af_t),
			      (cpu_set_t *)&stats[cpu].cpu_affinity)) {
		stats[cpu].is_valid = false;
		return;
	}
#endif

	mperf_init_stats_rdpru(cpu);
}

static __always_inline void mperf_measure_stats_rdpru(int cpu)
{
	struct aperf_mperf prev_perf = {
		.a = stats[cpu].perf.a,
		.m = stats[cpu].perf.m
	};
#ifdef PER_CPU_TSC
	uint64_t prev_tsc = stats[cpu].tsc;
#endif

	get_aperf_mperf_rdpru(&stats[cpu].perf);
#ifdef PER_CPU_TSC
	mperf_rdtsc(&stats[cpu].tsc);
#endif

	stats[cpu].perf.a -= prev_perf.a;
	stats[cpu].perf.m -= prev_perf.m;
#ifdef PER_CPU_TSC
	stats[cpu].tsc -= prev_tsc;
#endif

	stats[cpu].freq = (uint64_t)(.5f + max_frequency *
				     ((float)stats[cpu].perf.a /
				      (float)stats[cpu].perf.m));
}

static __always_inline void mperf_measure_stats_rdpru_cpusched(int cpu)
{
	if (!stats[cpu].is_valid)
		return;

#ifndef PER_CPU_THREAD
	if (sched_setaffinity(0, sizeof(cpu_af_t),
			      (cpu_set_t *)&stats[cpu].cpu_affinity)) {
		stats[cpu].is_valid = false;
		return;
	}
#endif

	mperf_measure_stats_rdpru(cpu);
}

/*
static __always_inline void mperf_init_stats_msr(int cpu)
{
	stats[cpu].is_valid = !get_aperf_mperf_msr(&stats[cpu].perf, cpu);
}

static __always_inline void mperf_init_stats_msr_cpusched(int cpu)
{
	if (bind_cpu(cpu)) {
		stats[cpu].is_valid = false;
		return;
	}

	mperf_init_stats_msr(cpu);
}

static __always_inline void mperf_measure_stats_msr(int cpu)
{
	if (!stats[cpu].is_valid)
		return;

	stats[cpu].is_valid = !get_aperf_mperf_msr(&stats[cpu].perf, cpu);
}

static __always_inline void mperf_measure_stats_msr_cpusched(int cpu)
{
	if (!stats[cpu].is_valid)
		return;

	if (bind_cpu(cpu)) {
		stats[cpu].is_valid = false;
		return;
	}

	stats[cpu].is_valid = !get_aperf_mperf_msr(&stats[cpu].perf, cpu);
}
*/
/*
static __always_inline void timespec_add_ns(struct timespec *dest,
					    unsigned long long nsec)
{
	unsigned long long sec;
	nsec += (unsigned long long)dest->tv_nsec;
	sec = nsec / 1000000000ull;
	nsec -= sec * 1000000000ull;
	dest->tv_sec += (time_t)sec;
	dest->tv_nsec = (long)nsec;
}
*/

static __always_inline void randomize_cpu_affinity(void)
{
#if 0
	cpu_af_t a = {{0u}};
	struct timespec t = {0,0};
	clock_gettime(CLOCK_REALTIME, &t);
	a.__bits[0] = (unsigned long)t.tv_nsec;
	sched_setaffinity(0, sizeof(a), (cpu_set_t *)&a);
#endif
}

static int mperf_start_rdpru_cpusched(void)
{
	union {
		int cpu;
	//	unsigned long long nsec;
	} tmp = {
		.cpu = 0
	};
#ifndef PER_CPU_TSC
	uint64_t tsc1 = 0;
	uint64_t tsc2 = 0;
#endif
/*
	struct timespec ts1 = {0,0};
	struct timespec ts2 = {0,0};
*/

	//clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
#ifndef PER_CPU_TSC
	mperf_rdtsc(&tsc1);
#endif

	for (; tmp.cpu < 32; ++tmp.cpu) {
		mperf_init_stats_rdpru_cpusched(cpu_topo[tmp.cpu]);
	}

#ifndef PER_CPU_TSC
	mperf_rdtsc(&tsc2);
#endif
	//clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	randomize_cpu_affinity();

#ifndef PER_CPU_TSC
	tsc2 -= tsc1;
	tsc1 += tsc2 >> 1u;
	tsc_at_measure_start = tsc1;
#endif
/*
	ts2.tv_sec -= ts1.tv_sec;
	tmp.nsec  = (unsigned long long)ts2.tv_sec * 1000000000ull;
	tmp.nsec += (unsigned long long)ts2.tv_nsec;
	tmp.nsec -= (unsigned long long)ts1.tv_nsec;
	timespec_add_ns(&ts1, tmp.nsec >> 1u);
	time_start.tv_sec = ts1.tv_sec;
	time_start.tv_nsec = ts1.tv_nsec;
*/
	return 0;
}

static int mperf_stop_rdpru_cpusched(void)
{
	unsigned int i = 0;
	union {
		int cpu;
		double avg;
	//	unsigned long long nsec;
	} tmp = {
		.cpu = 0u
	};
#ifndef PER_CPU_TSC
	uint64_t tsc1 = 0u;
#endif
	union {
		uint64_t acc;
#ifndef PER_CPU_TSC
		uint64_t tsc;
#endif
	} tmp2 = {
		.acc = 0u
	};
/*
	struct timespec ts1 = {0,0};
	struct timespec ts2 = {0,0};
*/

	//clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
#ifndef PER_CPU_TSC
	mperf_rdtsc(&tsc1);
#endif

	for (; tmp.cpu < 32; ++tmp.cpu) {
		mperf_measure_stats_rdpru_cpusched(cpu_topo[tmp.cpu]);
	}

#ifndef PER_CPU_TSC
	mperf_rdtsc(&tmp2.tsc);
#endif
	//clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	randomize_cpu_affinity();

#ifndef PER_CPU_TSC
	tmp2.tsc -= tsc1;
	tsc1 += tmp2.tsc >> 1u;
	tsc_at_measure_end = tsc1;
	tsc_diff = tsc_at_measure_end - tsc_at_measure_start;
	tmp2.acc = 0u;
#endif
/*
	ts2.tv_sec -= ts1.tv_sec;
	tmp.nsec  = (unsigned long long)ts2.tv_sec * 1000000000ull;
	tmp.nsec += (unsigned long long)ts2.tv_nsec;
	tmp.nsec -= (unsigned long long)ts1.tv_nsec;
	timespec_add_ns(&ts1, tmp.nsec >> 1u);
	time_end.tv_sec = ts1.tv_sec;
	time_end.tv_nsec = ts1.tv_nsec;
	time_diff = timespec_diff_us(time_start, time_end);

	if (max_freq_mode == MAX_FREQ_TSC_REF)
		max_frequency = (float)tsc_diff / (float)time_diff;
*/

	for (tmp.cpu = 0; tmp.cpu < cpu_count; ++tmp.cpu) {
		if (stats[tmp.cpu].is_valid)
			tmp2.acc += stats[tmp.cpu].freq;
	}

	tmp.avg = (double)tmp2.acc / (double)cpu_count;
	avg_freq[0] = tmp.avg;

	while (++i < sizeof(avg_freq) / sizeof(*avg_freq)) {
		tmp.avg += avg_freq[i];
		tmp.avg *= .5;
		avg_freq[i] = tmp.avg;
	}

	return 0;
}

#ifndef BENCHMARK
unsigned int mperf_print_footer(void)
{
	fprintf(stderr,
		"                  +------\n"
		"%11.1f %6.1f %6.1f\n",
		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 1u],
		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 8u],
		avg_freq[0]);
	return 2u;
}
#endif

/*
static int mperf_start_rdpru(void)
{
	int cpu;
	unsigned long long dbg;

	clock_gettime(CLOCK_REALTIME, &time_start);
	mperf_get_tsc(&tsc_at_measure_start);

	for (cpu = 0; cpu < cpu_count; cpu++)
		mperf_init_stats_rdpru(cpu);

	mperf_get_tsc(&dbg);
	dprint("TSC diff: %llu\n", dbg - tsc_at_measure_start);
	return 0;
}

static int mperf_stop_rdpru(void)
{
	unsigned long long dbg;
	int cpu;

	for (cpu = 0; cpu < cpu_count; cpu++)
		mperf_measure_stats_rdpru(cpu);

	mperf_get_tsc(&tsc_at_measure_end);
	clock_gettime(CLOCK_REALTIME, &time_end);

	mperf_get_tsc(&dbg);
	dprint("TSC diff: %llu\n", dbg - tsc_at_measure_end);

	return 0;
}

static int mperf_start_msr_cpusched(void)
{
	int cpu;
	unsigned long long dbg;

	clock_gettime(CLOCK_REALTIME, &time_start);
	mperf_get_tsc(&tsc_at_measure_start);

	for (cpu = 0; cpu < cpu_count; cpu++)
		mperf_init_stats_msr_cpusched(cpu);

	mperf_get_tsc(&dbg);
	dprint("TSC diff: %llu\n", dbg - tsc_at_measure_start);
	return 0;
}

static int mperf_stop_msr_cpusched(void)
{
	unsigned long long dbg;
	int cpu;

	for (cpu = 0; cpu < cpu_count; cpu++)
		mperf_measure_stats_msr_cpusched(cpu);

	mperf_get_tsc(&tsc_at_measure_end);
	clock_gettime(CLOCK_REALTIME, &time_end);

	mperf_get_tsc(&dbg);
	dprint("TSC diff: %llu\n", dbg - tsc_at_measure_end);

	return 0;
}

static int mperf_start_msr(void)
{
	int cpu;
	unsigned long long dbg;

	clock_gettime(CLOCK_REALTIME, &time_start);
	mperf_get_tsc(&tsc_at_measure_start);

	for (cpu = 0; cpu < cpu_count; cpu++)
		mperf_init_stats_msr(cpu);

	mperf_get_tsc(&dbg);
	dprint("TSC diff: %llu\n", dbg - tsc_at_measure_start);
	return 0;
}

static int mperf_stop_msr(void)
{
	unsigned long long dbg;
	int cpu;

	for (cpu = 0; cpu < cpu_count; cpu++)
		mperf_measure_stats_msr(cpu);

	mperf_get_tsc(&tsc_at_measure_end);
	clock_gettime(CLOCK_REALTIME, &time_end);

	mperf_get_tsc(&dbg);
	dprint("TSC diff: %llu\n", dbg - tsc_at_measure_end);

	return 0;
}
*/

/*
 * Mperf register is defined to tick at P0 (maximum) frequency
 *
 * Instead of reading out P0 which can be tricky to read out from HW,
 * we use TSC counter if it reliably ticks at P0/mperf frequency.
 *
 * Still try to fall back to:
 * /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq
 * on older Intel HW without invariant TSC feature.
 * Or on AMD machines where TSC does not tick at P0 (do not exist yet, but
 * it's still double checked (MSR_AMD_HWCR)).
 *
 * On these machines the user would still get useful mperf
 * stats when acpi-cpufreq driver is loaded.
 */
static int init_maxfreq_mode(void)
{
	int ret;
	unsigned long long hwcr;
	unsigned long min, max;

	if (!(cpupower_cpu_info.caps & (unsigned int)CPUPOWER_CAP_INV_TSC))
		goto use_sysfs;

	if (cpupower_cpu_info.vendor == X86_VENDOR_AMD ||
	    cpupower_cpu_info.vendor == X86_VENDOR_HYGON) {
		/* MSR_AMD_HWCR tells us whether TSC runs at P0/mperf
		 * freq.
		 * A test whether hwcr is accessable/available would be:
		 * (cpupower_cpu_info.family > 0x10 ||
		 *   cpupower_cpu_info.family == 0x10 &&
		 *   cpupower_cpu_info.model >= 0x2))
		 * This should be the case for all aperf/mperf
		 * capable AMD machines and is therefore safe to test here.
		 * Compare with Linus kernel git commit: acf01734b1747b1ec4
		 */
		ret = read_msr(0, MSR_AMD_HWCR, &hwcr);
		/*
		 * If the MSR read failed, assume a Xen system that did
		 * not explicitly provide access to it and assume TSC works
		*/
		if (ret != 0) {
			fprintf(stderr, "MSR read 0x%x failed - assume TSC working\n",
			        MSR_AMD_HWCR);
			max_freq_mode = MAX_FREQ_TSC_REF;
			return 0;
		}
		if (1u & (hwcr >> 24u)) {
			max_freq_mode = MAX_FREQ_TSC_REF;
			max_frequency = 3500.f;
			return 0;
		}
	} else if (cpupower_cpu_info.vendor == X86_VENDOR_INTEL) {
		/*
		 * On Intel we assume mperf (in C0) is ticking at same
		 * rate than TSC
		 */
		max_freq_mode = MAX_FREQ_TSC_REF;
		return 0;
	}
use_sysfs:
	if (cpufreq_get_hardware_limits(0, &min, &max)) {
		fprintf(stderr, "Cannot retrieve max freq from cpufreq kernel "
		       "subsystem\n");
		return -1;
	}
	max_freq_mode = MAX_FREQ_SYSFS;
	max_frequency = (float)max / 1000.f; /* Default automatically to MHz value */
	fprintf(stderr, "max_frequency from sysfs: %f\n",
		(double)max_frequency);
	return 0;
}

#ifdef PER_CPU_THREAD
static void *cpu_fn(void *arg)
{
	__attribute__((unused)) struct cpu_thread *thd = arg;
	__attribute__((unused)) intptr_t id = thd - cpu_thread;

	struct timespec interval = get_monitor_interval();

	if (sem_wait(&thd_sem[0]))
		return (void *)(intptr_t)errno;

	//mperf_init_stats_rdpru_cpusched(cpu_topo[id]);

	return NULL;
}

static bool init_semaphores(void)
{
	int i = 0;
	for (; i < sizeof(thd_sem) / sizeof(thd_sem[0]); ++i) {
		if (sem_init(&thd_sem[i], 0, 0))
			goto fail;
	}
	return true;

fail:
	fprintf(stderr, "%s: sem_init: %s\n", __func__, strerror(errno));
	while (i-- > 0)
		sem_destroy(&thd_sem[i]);
	return false;
}

static void destroy_semaphores(void)
{
	int i = 0;
	for (; i < sizeof(thd_sem) / sizeof(thd_sem[0]); ++i) {
		sem_destroy(&thd_sem[i]);
	}
}

static bool init_threads(void)
{
	int i = 0;
	int thd = 0;
	int errnum = 0;
	const char *errmsg = NULL;
	pthread_attr_t attr;
	cpu_set_t cpumask;

	if (!init_semaphores())
		return NULL;

	errnum = pthread_attr_init(&attr);
	if (errnum) {
		errmsg = "pthread_attr_init";
		goto fail1;
	}

	cpu_thread = calloc(cpu_count, sizeof(*cpu_thread));
	if (!cpu_thread) {
		errnum = errno;
		errmsg = "calloc";
		goto fail2;
	}

	CPU_ZERO(&cpumask);

	for (thd = 0; thd < cpu_count; ++thd) {
		CPU_SET(thd, &cpumask);

		errnum = pthread_attr_setaffinity_np(&attr, sizeof(cpumask),
						     &cpumask);
		if (errnum) {
			errmsg = "pthread_attr_setaffinity_np";
			goto fail3;
		}

		errnum = pthread_create(&cpu_thread[thd].id, &attr, cpu_fn,
					&cpu_thread[thd]);
		if (errnum) {
			errmsg = "pthread_create";
			goto fail3;
		}

		CPU_CLR(thd, &cpumask);
	}

	pthread_attr_destroy(&attr);

	return true;

fail3:
	for (i = 0; i < thd; ++i)
		pthread_cancel(cpu_thread[i].id);

	for (i = 0; i < thd; ++i)
		pthread_join(cpu_thread[i].id, NULL);

	free(cpu_thread);
	cpu_thread = NULL;

fail2:
	pthread_attr_destroy(&attr);

fail1:
	destroy_semaphores();

	if (errmsg)
		fprintf(stderr, "%s: %s%s%s\n", __func__, errmsg,
			errnum ? ": " : "", errnum ? strerror(errnum) : "");
	return false;

}
#endif /* PER_CPU_THREAD */

/*
 * This monitor provides:
 *
 * 1) Average frequency a CPU resided in
 *    This always works if the CPU has aperf/mperf capabilities
 *
 * 2) C0 and Cx (any sleep state) time a CPU resided in
 *    Works if mperf timer stops ticking in sleep states which
 *    seem to be the case on all current HW.
 * Both is directly retrieved from HW registers and is independent
 * from kernel statistics.
 */
struct mperf_monitor mperf_monitor;
static struct cpuidle_monitor *mperf_register(void)
{
#ifndef PER_CPU_THREAD
	int i = 0;
#endif
	int err = 0;
	const char *msg = NULL;

	if (cpu_count < 1)
		return NULL;

	if (!(cpupower_cpu_info.caps & (unsigned int)CPUPOWER_CAP_APERF))
		return NULL;

	if (init_maxfreq_mode())
		return NULL;

#ifndef PER_CPU_THREAD
	/* Save original CPU affinity mask so we can restore it after each
	 * measurement loop.
	 */
	if (sched_getaffinity(getpid(), sizeof(cpu_affinity),
			      (cpu_set_t *)&cpu_affinity)) {
		err = errno;
		msg = "sched_getaffinity";
		goto fail;
	}

	/* Clear the affinity bit of the last CPU to measure during each
	 * round. The hope is that this forces the scheduler to do some
	 * load balancing instead of always continuing to run on the last
	 * CPU in between measurements.
	 */
	CPU_CLR_S(cpu_count - 1, sizeof(cpu_affinity), &cpu_affinity);
#endif /* PER_CPU_THREAD */

	/* Free this at program termination */
	stats = calloc(cpu_count, sizeof(*stats));

	if (!stats) {
		err = errno;
		msg = "calloc";
		goto fail;
	}

#ifndef PER_CPU_THREAD
	for (; i < cpu_count; ++i) {
		CPU_SET_S(i, sizeof(cpu_af_t), &stats[i].cpu_affinity);
	}
#endif

	mperf_monitor.cpuidle.flags.per_cpu_schedule = (
		cpupower_cpu_info.vendor == X86_VENDOR_AMD
	);

#ifdef PER_CPU_THREAD
	if (!init_threads()) {
		free(stats);
		stats = NULL;
		msg = "init_threads";
		goto fail;
	}
#endif

/*
	if (mperf_monitor.cpuidle.flags.per_cpu_schedule) {
		if (!(cpupower_cpu_info.caps & CPUPOWER_CAP_AMD_RDPRU)) {
			mperf_monitor.cpuidle.start = mperf_start_msr_cpusched;
			mperf_monitor.cpuidle.stop = mperf_stop_msr_cpusched;
		}
	} else if (cpupower_cpu_info.caps & CPUPOWER_CAP_AMD_RDPRU) {
		mperf_monitor.cpuidle.start = mperf_start_rdpru;
		mperf_monitor.cpuidle.stop = mperf_stop_rdpru;
	} else {
		mperf_monitor.cpuidle.start = mperf_start_msr;
		mperf_monitor.cpuidle.stop = mperf_stop_msr;
	}
*/
	return &mperf_monitor.cpuidle;

fail:
	if (err)
		fprintf(stderr, "%s: %s: %s\n", __func__, msg, strerror(err));
	else
		fprintf(stderr, "%s: %s failed\n", __func__, msg);

	return NULL;
}

static void mperf_unregister(struct cpuidle_monitor *mon)
{
	struct mperf_monitor *mm = to_mperf_monitor(mon);
	free(stats);
#ifdef PER_CPU_THREAD
	destroy_semaphores();
	free(cpu_thread);
#endif
}

struct mperf_monitor mperf_monitor = {
	.cpuidle = {
		.name			= "Mperf",
		.name_len		= sizeof("Mperf") - 1u,
		.hw_states_num		= MPERF_CSTATE_COUNT,
		.hw_states		= mperf_cstates,
		.start			= mperf_start_rdpru_cpusched,
		.stop			= mperf_stop_rdpru_cpusched,
		.do_register		= mperf_register,
		.unregister		= mperf_unregister,
		.flags.needs_root	= true,
		.overflow_s		= 922000000 /* 922337203 seconds TSC
						       overflow at 20GHz */
	}
};
#endif /* #if defined(__i386__) || defined(__x86_64__) */
