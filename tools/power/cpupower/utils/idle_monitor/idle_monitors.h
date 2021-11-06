/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  (C) 2010,2011       Thomas Renninger <trenn@suse.de>, Novell Inc.
 *
 *  Based on the idea from Michael Matz <matz@suse.de>
 */

#ifndef _CPUIDLE_IDLE_MONITORS_H_
#define _CPUIDLE_IDLE_MONITORS_H_

#include "cpuidle_monitor.h"

#define DEF(name)		DEF_(name, cpuidle, )
#define DEF2(name, member)	DEF_(name, name, .member)

#define DEF_(name, type, member) extern struct type ##_monitor name ##_monitor;
#include "idle_monitors.def"
#undef DEF_
extern struct cpuidle_monitor *all_monitors[];

#endif /* _CPUIDLE_IDLE_MONITORS_H_ */
