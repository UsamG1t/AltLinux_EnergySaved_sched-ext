/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <unistd.h>

#include <time.h>

#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_dumb.bpf.skel.h"

const char help_fmt[] =
"A dumb sched_ext scheduler.\n"
"\n"
"Usage: %s [-v]\n"
"\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int dumb)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scx_dumb *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(dumb_ops, scx_dumb);

	while ((opt = getopt(argc, argv, "vh")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, dumb_ops, scx_dumb, uei);
	link = SCX_OPS_ATTACH(skel, dumb_ops, scx_dumb);

	time_t start_raw_time, now_raw_time, delta;
    struct tm* delta_info;
    char delta_buffer[80];

    time(&start_raw_time);
    time(&now_raw_time); 
	
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		delta = now_raw_time - start_raw_time;
		delta_info = localtime(&delta);
		strftime(delta_buffer, sizeof(delta_buffer), "%H:%M:%S", delta_info);
		printf("Working time is: %s\n", delta_buffer);
		fflush(stdout);
		sleep(1);

	    time(&now_raw_time);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_dumb__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
