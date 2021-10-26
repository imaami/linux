// SPDX-License-Identifier: GPL-2.0-only
/*
 *  (C) 2010,2011       Thomas Renninger <trenn@suse.de>, Novell Inc.
 *
 *  Output format inspired by Len Brown's <lenb@kernel.org> turbostat tool.
 */


#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "builtin.h"
#include "helpers/helpers.h"
#include "idle_monitor/cpupower-monitor.h"
#include "idle_monitor/idle_monitors.h"

/* Define pointers to all monitors.  */
#define DEF(x) & x ## _monitor ,
struct cpuidle_monitor *all_monitors[] = {
#include "idle_monitors.def"
NULL
};

int cpu_count;

static struct cpuidle_monitor *monitors[MONITORS_MAX];
static unsigned int avail_monitors;

static char *progname;

enum operation_mode_e { list = 1, show, show_all };
static int mode;
static int interval = 1;
static char *show_monitors_param;
static struct cpupower_topology cpu_top;
static unsigned int wake_cpus;

/* ToDo: Document this in the manpage */
static char range_abbr[RANGE_MAX] = { 'T', 'C', 'P', 'M', };

long long timespec_diff_us(struct timespec start, struct timespec end)
{
	struct timespec temp;
	if ((end.tv_nsec - start.tv_nsec) < 0) {
		temp.tv_sec = end.tv_sec - start.tv_sec - 1;
		temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec - start.tv_sec;
		temp.tv_nsec = end.tv_nsec - start.tv_nsec;
	}
	return (temp.tv_sec * 1000000) + (temp.tv_nsec / 1000);
}

/*s is filled with left and right spaces
 *to make its length atleast n+1
 */
static void fill_string_with_spaces(char *s, size_t len, size_t n)
{
	fprintf(stderr, "%s(\"%s\", %zu, %zu)\n%*s", __func__,
	                s,  len, n, (int)sizeof(__func__), "=> ");

	if (len < n) {
		char *temp = malloc(n + 1u);
		for (; len < n; len++)
			s[len] = ' ';
		s[len] = '\0';
		snprintf(temp, n+1u, " %s", s);
		strcpy(s, temp);
		free(temp);
	}

	fprintf(stderr, "\"%s\"\n", s);
}

#define MAX_COL_WIDTH 6
static void print_header(int topology_depth)
{
	unsigned int mon, state, need_len;
	cstate_t s;
	char buf[128] = "";

	fill_string_with_spaces(buf, 0, topology_depth * 5 - 1);
	printf("%s|", buf);

	for (mon = 0; mon < avail_monitors; mon++) {
		need_len = monitors[mon]->hw_states_num * (MAX_COL_WIDTH + 1u)
			- 1u;
		if (mon != 0)
			printf("||");
		sprintf(buf, "%s", monitors[mon]->name);
		fill_string_with_spaces(buf, monitors[mon]->name_len, need_len);
		printf("%s", buf);
	}
	printf("\n");

	if (topology_depth > 2)
		printf(" PKG|");
	if (topology_depth > 1)
		printf("CORE|");
	if (topology_depth > 0)
		printf(" CPU|");

	for (mon = 0; mon < avail_monitors; mon++) {
		if (mon != 0)
			printf("||");
		for (state = 0; state < monitors[mon]->hw_states_num; state++) {
			if (state != 0)
				printf("|");
			s = monitors[mon]->hw_states[state];
			sprintf(buf, "%s", s.name);
			fill_string_with_spaces(buf, strlen(s.name),
						MAX_COL_WIDTH);
			printf("%s", buf);
		}
		printf(" ");
	}
	printf("\n");
}

static void print_results(int topology_depth, int cpu)
{
	unsigned int mon, state;
	int ret;
	double percent;
	unsigned long long result;
	cstate_t s;

	/* Be careful CPUs may got resorted for pkg value do not just use cpu */
	if (!bitmask_isbitset(cpus_chosen, cpu_top.core_info[cpu].cpu))
		return;
	if (!cpu_top.core_info[cpu].is_online &&
	    cpu_top.core_info[cpu].pkg == -1)
		return;

	if (topology_depth > 2)
		printf("%4d|", cpu_top.core_info[cpu].pkg);
	if (topology_depth > 1)
		printf("%4d|", cpu_top.core_info[cpu].core);
	if (topology_depth > 0)
		printf("%4d|", cpu_top.core_info[cpu].cpu);

	for (mon = 0; mon < avail_monitors; mon++) {
		if (mon != 0)
			printf("||");

		for (state = 0; state < monitors[mon]->hw_states_num; state++) {
			if (state != 0)
				printf("|");

			s = monitors[mon]->hw_states[state];

			if (s.get_count_percent) {
				ret = s.get_count_percent(s.id, &percent,
						  cpu_top.core_info[cpu].cpu);
				if (ret)
					printf("******");
				else if (percent >= 100.0)
					printf("%6.1f", percent);
				else
					printf("%6.2f", percent);
			} else if (s.get_count) {
				ret = s.get_count(s.id, &result,
						  cpu_top.core_info[cpu].cpu);
				if (ret)
					printf("******");
				else
					printf("%6llu", result);
			} else {
				printf(_("Monitor %s, Counter %s has no count "
					 "function. Implementation error\n"),
				       monitors[mon]->name, s.name);
				exit(EXIT_FAILURE);
			}
		}
	}

	/*
	 * The monitor could still provide useful data, for example
	 * AMD HW counters partly sit in PCI config space.
	 * It's up to the monitor plug-in to check .is_online, this one
	 * is just for additional info.
	 */
	if (!cpu_top.core_info[cpu].is_online &&
	    cpu_top.core_info[cpu].pkg != -1) {
		printf(_(" *is offline\n"));
		return;
	}

	printf("\n");
}


/* param: string passed by -m param (The list of monitors to show)
 *
 * Monitors must have been registered already, matching monitors
 * are picked out and available monitors array is overridden
 * with matching ones
 *
 * Monitors get sorted in the same order the user passes them
*/

static void parse_monitor_param(char *param)
{
	unsigned int num;
	int mon, hits = 0;
	char *tmp = param, *token;
	struct cpuidle_monitor *tmp_mons[MONITORS_MAX];


	for (mon = 0; mon < MONITORS_MAX; mon++, tmp = NULL) {
		token = strtok(tmp, ",");
		if (token == NULL)
			break;
		if (strlen(token) >= MONITOR_NAME_LEN) {
			printf(_("%s: max monitor name length"
				 " (%d) exceeded\n"), token, MONITOR_NAME_LEN);
			continue;
		}

		for (num = 0; num < avail_monitors; num++) {
			if (!strcmp(monitors[num]->name, token)) {
				dprint("Found requested monitor: %s\n", token);
				tmp_mons[hits] = monitors[num];
				hits++;
			}
		}
	}
	if (hits == 0) {
		printf(_("No matching monitor found in %s, "
			 "try -l option\n"), param);
		exit(EXIT_FAILURE);
	}
	/* Override detected/registerd monitors array with requested one */
	memcpy(monitors, tmp_mons,
		sizeof(struct cpuidle_monitor *) * MONITORS_MAX);
	avail_monitors = hits;
}

static void list_monitors(void)
{
	unsigned int mon, state;
	cstate_t s;

	for (mon = 0; mon < avail_monitors; mon++) {
		printf(_("Monitor \"%s\" (%u states) - Might overflow after %u "
			 "s\n"),
			monitors[mon]->name, monitors[mon]->hw_states_num,
			monitors[mon]->overflow_s);

		for (state = 0; state < monitors[mon]->hw_states_num; state++) {
			s = monitors[mon]->hw_states[state];
			/*
			 * ToDo show more state capabilities:
			 * percent, time (granlarity)
			 */
			printf("%s\t[%c] -> %s\n", s.name, range_abbr[s.range],
			       gettext(s.desc));
		}
	}
}

static int fork_it(char **argv)
{
	int status = 0;
	unsigned int num;
	unsigned long long timediff;
	pid_t child_pid;
	struct timespec start, end;

	child_pid = fork();
	clock_gettime(CLOCK_REALTIME, &start);

	for (num = 0; num < avail_monitors; num++)
		monitors[num]->start();

	if (!child_pid) {
		/* child */
		execvp(argv[0], argv);
	} else {
		/* parent */
		if (child_pid == -1) {
			perror("fork");
			exit(1);
		}

		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
		if (waitpid(child_pid, &status, 0) == -1) {
			perror("wait");
			exit(1);
		}
	}
	clock_gettime(CLOCK_REALTIME, &end);
	for (num = 0; num < avail_monitors; num++)
		monitors[num]->stop();

	timediff = timespec_diff_us(start, end);
	if (WIFEXITED(status))
		printf(_("%s took %.5f seconds and exited with status %d\n"),
			argv[0], timediff / (1000.0 * 1000),
			WEXITSTATUS(status));
	return 0;
}

static int do_interval_measure(const struct timespec *i)
{
	unsigned int num;
	int cpu;

	if (wake_cpus)
		for (cpu = 0; cpu < cpu_count; cpu++)
			bind_cpu(cpu);

	for (num = 0; num < avail_monitors; num++) {
		dprint("HW C-state residency monitor: %s - States: %u\n",
		       monitors[num]->name, monitors[num]->hw_states_num);
		monitors[num]->start();
	}

	if (nanosleep(i, NULL))
		return -1;

	if (wake_cpus)
		for (cpu = 0; cpu < cpu_count; cpu++)
			bind_cpu(cpu);

	for (num = 0; num < avail_monitors; num++)
		monitors[num]->stop();


	return 0;
}

static void cmdline(int argc, char *argv[])
{
	int opt;
	progname = basename(argv[0]);

	while ((opt = getopt(argc, argv, "+lci:m:")) != -1) {
		switch (opt) {
		case 'l':
			if (mode)
				print_wrong_arg_exit();
			mode = list;
			break;
		case 'i':
			/* only allow -i with -m or no option */
			if (mode && mode != show)
				print_wrong_arg_exit();
			interval = atoi(optarg);
			break;
		case 'm':
			if (mode)
				print_wrong_arg_exit();
			mode = show;
			show_monitors_param = optarg;
			break;
		case 'c':
			wake_cpus = 1;
			break;
		default:
			print_wrong_arg_exit();
		}
	}
	if (!mode)
		mode = show_all;
}

int cmd_monitor(int argc, char **argv)
{
	bool should_fork;
	unsigned int num;
	struct cpuidle_monitor *test_mon;
	int cpu, topo_depth;
	struct timespec ival_ts;
	char cursor[8];

	cmdline(argc, argv);
	cpu_count = get_cpu_topology(&cpu_top);
	if (cpu_count < 0) {
		printf(_("Cannot read number of available processors\n"));
		return EXIT_FAILURE;
	}

	if (!cpu_top.core_info[0].is_online)
		printf("WARNING: at least one cpu is offline\n");

	/* Default is: monitor all CPUs */
	if (bitmask_isallclear(cpus_chosen))
		bitmask_setall(cpus_chosen);

	dprint("System has up to %d CPU cores\n", cpu_count);

	for (num = 0; all_monitors[num]; num++) {
		dprint("Try to register: %s\n", all_monitors[num]->name);

		test_mon = all_monitors[num]->do_register();
		if (!test_mon)
			continue;

		if (!test_mon->name_len && test_mon->name[0])
			test_mon->name_len = strlen(test_mon->name);

		if (test_mon->flags.needs_root && !run_as_root) {
			fprintf(stderr, _("Available monitor %s needs "
				  "root access\n"), test_mon->name);
			continue;
		}

		monitors[avail_monitors++] = test_mon;
		dprint("%s registered\n", test_mon->name);
	}

	if (avail_monitors == 0) {
		printf(_("No HW Cstate monitors found\n"));
		return 1;
	}

	if (mode == list) {
		list_monitors();
		exit(EXIT_SUCCESS);
	}

	if (mode == show)
		parse_monitor_param(show_monitors_param);

	cpu = snprintf(cursor, sizeof(cursor), "\033[%dF", cpu_count);
	if (cpu < 0 || cpu >= (int)sizeof(cursor))
		exit(EXIT_FAILURE);
	cpu = 0;

	topo_depth = (cpu_top.pkgs > 1) ? 3 : 1;

	dprint("Packages: %d - Cores: %d - CPUs: %d\n",
	       cpu_top.pkgs, cpu_top.cores, cpu_count);

	/*
	 * if any params left, it must be a command to fork
	 */
	should_fork = !!(argc - optind);

	if (should_fork) {
		fork_it(argv + optind);
	} else {
		/* ToDo: Topology parsing needs fixing first to do
		   this more generically */
		print_header(topo_depth);

		ival_ts.tv_sec = interval / 1000;
		ival_ts.tv_nsec = (interval % 1000) * 1000000;

	measure:
		do_interval_measure(&ival_ts);
		if (cpu > 0)
			fputs(cursor, stdout);
	}

	for (cpu = 0; cpu < cpu_count; cpu++) {
		print_results(topo_depth, cpu);
	}

	if (!should_fork)
		goto measure;

	for (num = 0; num < avail_monitors; num++)
		monitors[num]->unregister();

	cpu_topology_release(cpu_top);
	return 0;
}
