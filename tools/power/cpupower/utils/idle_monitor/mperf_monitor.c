// SPDX-License-Identifier: GPL-2.0-only
/*
 *  (C) 2010,2011       Thomas Renninger <trenn@suse.de>, Novell Inc.
 */

#if defined(__i386__) || defined(__x86_64__)

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

#define MSR_APERF	0xE8
#define MSR_MPERF	0xE7

#define RDPRU ".byte 0x0f, 0x01, 0xfd"
#define RDPRU_ECX_MPERF	0
#define RDPRU_ECX_APERF	1

#define MSR_TSC	0x10

#define MSR_AMD_HWCR 0xc0010015

#define U64_BIT (CHAR_BIT * sizeof(uint64_t))
#define U64_CPUMASK_LEN(n) (((uint64_t)(n) + U64_BIT - UINT64_C(1)) / U64_BIT)
#define U64_CPUMASK(ncpus) struct { uint64_t __bits[U64_CPUMASK_LEN(ncpus)]; }

#define MAX_CPUS 32
typedef U64_CPUMASK(MAX_CPUS) cpu_af_t;

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

static unsigned long long tsc_at_measure_start;
static unsigned long long tsc_at_measure_end;
static unsigned long long tsc_diff;
static uint64_t acc_freq;

static double avg_freq[15];

struct aperf_mperf {
	unsigned long long aperf;
	unsigned long long mperf;
};

struct measurement {
	struct aperf_mperf previous;
	struct aperf_mperf current;
	cpu_af_t cpu_affinity;
	bool is_valid;
};

static cpu_af_t cpu_affinity;
static struct measurement *stats;

/*
static __always_inline int mperf_get_tsc(unsigned long long *tsc)
{
	return read_msr(base_cpu, MSR_TSC, tsc);
}
*/

static __always_inline void mperf_rdtsc(unsigned long long *tsc)
{
	unsigned long low, high;
	asm volatile("lfence; rdtsc"
		     : "=a" (low), "=d" (high));
	*tsc = low | (high << 32);
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

	dest->aperf = ((low_a) | (high_a) << 32);
	dest->mperf = ((low_m) | (high_m) << 32);
}

/*
static int get_aperf_mperf_msr(struct aperf_mperf *dest, int cpu)
{
	int ret;

	ret  = read_msr(cpu, MSR_APERF, &dest->aperf);
	ret |= read_msr(cpu, MSR_MPERF, &dest->mperf);

	return ret;
}
*/

static __always_inline uint64_t get_cpu_tsc_sample(unsigned int cpu
						   __attribute__((unused)))
{
	return tsc_diff;
}

static __always_inline uint64_t get_cpu_aperf_sample(unsigned int cpu)
{
	return stats[cpu].current.aperf - stats[cpu].previous.aperf;
}

static __always_inline uint64_t get_cpu_mperf_sample(unsigned int cpu)
{
	return stats[cpu].current.mperf - stats[cpu].previous.mperf;
}

static __always_inline uint64_t get_cpu_freq_sample(unsigned int cpu)
{
	return (uint64_t)(.5f + max_frequency *
			  ((float)(get_cpu_aperf_sample(cpu)) /
			   (float)(get_cpu_mperf_sample(cpu))));
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

	flt = (100.f * (float)(get_cpu_mperf_sample(cpu))) / div;
	*percent = (double)((id != Cx) ? flt : 100.f - flt);

	return 0;
}

static int mperf_get_count_freq(unsigned int id, unsigned long long *count,
				unsigned int cpu)
{
	if (!stats[cpu].is_valid)
		return -1;
	*count = get_cpu_freq_sample(cpu);
	return 0;
}

static __always_inline void mperf_init_stats_rdpru(int cpu)
{
	get_aperf_mperf_rdpru(&stats[cpu].previous);
	stats[cpu].is_valid = true;
}

static __always_inline void mperf_init_stats_rdpru_cpusched(int cpu)
{
	if (sched_setaffinity(0, sizeof(cpu_af_t),
			      (cpu_set_t *)&stats[cpu].cpu_affinity)) {
		stats[cpu].is_valid = false;
		return;
	}

	mperf_init_stats_rdpru(cpu);
}

static __always_inline void mperf_measure_stats_rdpru(int cpu)
{
	get_aperf_mperf_rdpru(&stats[cpu].current);
}

static __always_inline void mperf_measure_stats_rdpru_cpusched(int cpu)
{
	if (!stats[cpu].is_valid)
		return;

	if (sched_setaffinity(0, sizeof(cpu_af_t),
			      (cpu_set_t *)&stats[cpu].cpu_affinity)) {
		stats[cpu].is_valid = false;
		return;
	}

	mperf_measure_stats_rdpru(cpu);
}

/*
static __always_inline void mperf_init_stats_msr(int cpu)
{
	stats[cpu].is_valid = !get_aperf_mperf_msr(&stats[cpu].previous, cpu);
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

	stats[cpu].is_valid = !get_aperf_mperf_msr(&stats[cpu].current, cpu);
}

static __always_inline void mperf_measure_stats_msr_cpusched(int cpu)
{
	if (!stats[cpu].is_valid)
		return;

	if (bind_cpu(cpu)) {
		stats[cpu].is_valid = false;
		return;
	}

	stats[cpu].is_valid = !get_aperf_mperf_msr(&stats[cpu].current, cpu);
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
static int mperf_start_rdpru_cpusched(void)
{
	union {
		int cpu;
	//	unsigned long long nsec;
	} tmp = {
		.cpu = 0
	};
	unsigned long long tsc1 = 0;
	unsigned long long tsc2 = 0;
/*
	struct timespec ts1 = {0,0};
	struct timespec ts2 = {0,0};
*/
	//clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
	mperf_rdtsc(&tsc1);

	for (; tmp.cpu < 16; ++tmp.cpu) {
		mperf_init_stats_rdpru_cpusched(tmp.cpu);
		mperf_init_stats_rdpru_cpusched(tmp.cpu + 16);
	}

	mperf_rdtsc(&tsc2);
	//clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	/* restore original affinity */
	sched_setaffinity(0, sizeof(cpu_af_t), (cpu_set_t *)&cpu_affinity);

	tsc2 -= tsc1;
	tsc1 += tsc2 >> 1u;
	tsc_at_measure_start = tsc1;
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
	static unsigned int run_count = 0u;
	union {
		int cpu;
		double avg;
	//	unsigned long long nsec;
	} tmp = {
		.cpu = 0
	};
	unsigned long long tsc1 = 0;
	unsigned long long tsc2 = 0;
/*
	struct timespec ts1 = {0,0};
	struct timespec ts2 = {0,0};
*/

	//clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
	mperf_rdtsc(&tsc1);

	for (; tmp.cpu < 16; ++tmp.cpu) {
		mperf_measure_stats_rdpru_cpusched(tmp.cpu);
		mperf_measure_stats_rdpru_cpusched(tmp.cpu + 16);
	}

	mperf_rdtsc(&tsc2);
	//clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

	/* restore original affinity */
	sched_setaffinity(0, sizeof(cpu_af_t),(cpu_set_t *)&cpu_affinity);

	tsc2 -= tsc1;
	tsc1 += tsc2 >> 1u;
	tsc_at_measure_end = tsc1;
	tsc_diff = tsc_at_measure_end - tsc_at_measure_start;
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

	acc_freq = 0u;
	for (tmp.cpu = 0; tmp.cpu < cpu_count; ++tmp.cpu) {
		if (stats[tmp.cpu].is_valid)
			acc_freq += get_cpu_freq_sample(tmp.cpu);
	}

	tmp.avg = (double)acc_freq / (double)cpu_count;
	unsigned int i = 0;

	avg_freq[0] = tmp.avg;

	if (!run_count++) {
		while (++i < sizeof(avg_freq) / sizeof(*avg_freq))
			avg_freq[i] = tmp.avg;
		return 0;
	}

	while (++i < sizeof(avg_freq) / sizeof(*avg_freq)) {
		tmp.avg += avg_freq[i];
		tmp.avg *= .5;
		avg_freq[i] = tmp.avg;
	}

	return 0;
}

void mperf_print_footer(unsigned int *line_count)
{
	fprintf(stderr,
		"                  +------\n"
/*
		"%11.1f %6.1f %6.1f\n"
		"%11.1f %6.1f %6.1f\n"
		"%11.1f %6.1f %6.1f\n"
		"%11.1f %6.1f %6.1f\n"
*/
		"%11.1f %6.1f %6.1f\n",
		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 1u],
/*
		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 2u],
		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 3u],

		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 4u],
		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 5u],
		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 6u],

		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 7u],
*/
		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 8u],
/*
		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 9u],

		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 10u],
		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 11u],
		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 12u],

		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 13u],
		avg_freq[(sizeof(avg_freq) / sizeof(*avg_freq)) - 14u],
*/
		avg_freq[0]);

	//(acc_freq + (n >> 1u)) / n);
	if (line_count)
		*line_count = 2u;
	//fprintf(stderr, "tsc_diff  : %llu\n", tsc_diff);
	//if (line_count)
	//	*line_count = 1u;
}

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

	if (!(cpupower_cpu_info.caps & CPUPOWER_CAP_INV_TSC))
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
		if (1 & (hwcr >> 24)) {
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
	fprintf(stderr, "max_frequency from sysfs: %f\n", max_frequency);
	return 0;
}

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
struct cpuidle_monitor mperf_monitor;
static struct cpuidle_monitor *mperf_register(void)
{
	int i = 0;

	if (!(cpupower_cpu_info.caps & CPUPOWER_CAP_APERF))
		return NULL;

	if (init_maxfreq_mode())
		return NULL;

	/* Save original CPU affinity mask */
	if (sched_getaffinity(getpid(), sizeof(cpu_af_t),
			      (cpu_set_t *)&cpu_affinity)) {
		perror(__func__);
		return NULL;
	}

	/* Free this at program termination */
	stats = calloc(cpu_count, sizeof(*stats));

	if (!stats)
		return NULL;

	for (; i < cpu_count; ++i) {
		CPU_SET_S(i, sizeof(cpu_af_t),
			  (cpu_set_t *)&stats[i].cpu_affinity);
	}

	mperf_monitor.flags.per_cpu_schedule = (cpupower_cpu_info.vendor ==
						X86_VENDOR_AMD);
/*
	if (mperf_monitor.flags.per_cpu_schedule) {
		if (!(cpupower_cpu_info.caps & CPUPOWER_CAP_AMD_RDPRU)) {
			mperf_monitor.start = mperf_start_msr_cpusched;
			mperf_monitor.stop = mperf_stop_msr_cpusched;
		}
	} else if (cpupower_cpu_info.caps & CPUPOWER_CAP_AMD_RDPRU) {
		mperf_monitor.start = mperf_start_rdpru;
		mperf_monitor.stop = mperf_stop_rdpru;
	} else {
		mperf_monitor.start = mperf_start_msr;
		mperf_monitor.stop = mperf_stop_msr;
	}
*/
	return &mperf_monitor;
}

static void mperf_unregister(void)
{
	free(stats);
}

struct cpuidle_monitor mperf_monitor = {
	.name			= "Mperf",
	.name_len		= sizeof("Mperf") - 1u,
	.hw_states_num		= MPERF_CSTATE_COUNT,
	.hw_states		= mperf_cstates,
	.start			= mperf_start_rdpru_cpusched,
	.stop			= mperf_stop_rdpru_cpusched,
	.do_register		= mperf_register,
	.unregister		= mperf_unregister,
	.flags.needs_root	= true,
	.overflow_s		= 922000000 /* 922337203 seconds TSC overflow
					       at 20GHz */
};
#endif /* #if defined(__i386__) || defined(__x86_64__) */
