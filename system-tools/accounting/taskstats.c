// SPDX-License-Identifier: GPL-2.0
/* getdelays.c
 *
 * Utility to get per-pid and per-tgid delay accounting statistics
 * Also illustrates usage of the taskstats interface
 *
 * Copyright (C) Shailabh Nagar, IBM Corp. 2005
 * Copyright (C) Balbir Singh, IBM Corp. 2006
 * Copyright (c) Jay Lan, SGI. 2006
 * Copyright (c) duanery 2021
 *
 * Compile with
 *	gcc -I/usr/src/linux/include getdelays.c -o getdelays
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>

#include <linux/genetlink.h>
#include <linux/taskstats.h>
#include <linux/cgroupstats.h>

/*
 * Generic macros for dealing with netlink sockets. Might be duplicated
 * elsewhere. It is recommended that commercial grade applications use
 * libnl or libnetlink and use the interfaces provided by the library
 */
#define GENLMSG_DATA(glh)	((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh)	(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na)		((void *)((char*)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD(len)	(len - NLA_HDRLEN)

#define MB (1024*1024)

#define err(code, fmt, arg...)			\
	do {					\
		fprintf(stderr, fmt, ##arg);	\
		exit(code);			\
	} while (0)

int done;
int rcvbufsz;
char name[100];
int dbg;
int print_io_accounting;
int print_mem_accounting;

#define PRINTF(fmt, arg...) {			\
	    if (dbg) {				\
		printf(fmt, ##arg);		\
	    }					\
	}

/* Maximum size of response requested or message sent */
#define MAX_MSG_SIZE	1024
/* Maximum number of cpus expected to be specified in a cpumask */
#define MAX_CPUS	32

struct msgtemplate {
	struct nlmsghdr n;
	struct genlmsghdr g;
	char buf[MAX_MSG_SIZE];
};

char cpumask[100+6*MAX_CPUS];

/*
 * Create a raw netlink socket and bind
 */
static int create_nl_socket(int protocol)
{
	int fd;
	struct sockaddr_nl local;

	fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (fd < 0)
		return -1;

	if (rcvbufsz)
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
				&rcvbufsz, sizeof(rcvbufsz)) < 0) {
			fprintf(stderr, "Unable to set socket rcv buf size to %d\n",
				rcvbufsz);
			goto error;
		}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;

	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0)
		goto error;

	return fd;
error:
	close(fd);
	return -1;
}


static int send_cmd(int sd, __u16 nlmsg_type, __u32 nlmsg_pid,
	     __u8 genl_cmd, __u16 nla_type,
	     void *nla_data, int nla_len)
{
	struct nlattr *na;
	struct sockaddr_nl nladdr;
	int r, buflen;
	char *buf;

	struct msgtemplate msg;

	msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.n.nlmsg_type = nlmsg_type;
	msg.n.nlmsg_flags = NLM_F_REQUEST;
	msg.n.nlmsg_seq = 0;
	msg.n.nlmsg_pid = nlmsg_pid;
	msg.g.cmd = genl_cmd;
	msg.g.version = 0x1;
	na = (struct nlattr *) GENLMSG_DATA(&msg);
	na->nla_type = nla_type;
	na->nla_len = nla_len + NLA_HDRLEN;
	memcpy(NLA_DATA(na), nla_data, nla_len);
	msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	buf = (char *) &msg;
	buflen = msg.n.nlmsg_len ;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	while ((r = sendto(sd, buf, buflen, 0, (struct sockaddr *) &nladdr,
			   sizeof(nladdr))) < buflen) {
		if (r > 0) {
			buf += r;
			buflen -= r;
		} else if (errno != EAGAIN)
			return -1;
	}
	return 0;
}


/*
 * Probe the controller in genetlink to find the family id
 * for the TASKSTATS family
 */
static int get_family_id(int sd)
{
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[256];
	} ans;

	int id = 0, rc;
	struct nlattr *na;
	int rep_len;

	strcpy(name, TASKSTATS_GENL_NAME);
	rc = send_cmd(sd, GENL_ID_CTRL, getpid(), CTRL_CMD_GETFAMILY,
			CTRL_ATTR_FAMILY_NAME, (void *)name,
			strlen(TASKSTATS_GENL_NAME)+1);
	if (rc < 0)
		return 0;	/* sendto() failure? */

	rep_len = recv(sd, &ans, sizeof(ans), 0);
	if (ans.n.nlmsg_type == NLMSG_ERROR ||
	    (rep_len < 0) || !NLMSG_OK((&ans.n), rep_len))
		return 0;

	na = (struct nlattr *) GENLMSG_DATA(&ans);
	na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
	if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
		id = *(__u16 *) NLA_DATA(na);
	}
	return id;
}

#if 0

#define TASKSTATS_VERSION	10
#define TS_COMM_LEN		32	/* should be >= TASK_COMM_LEN
					 * in linux/sched.h */

struct taskstats {

	/* The version number of this struct. This field is always set to
	 * TAKSTATS_VERSION, which is defined in <linux/taskstats.h>.
	 * Each time the struct is changed, the value should be incremented.
	 */
	__u16	version;
	__u32	ac_exitcode;		/* Exit status */

	/* The accounting flags of a task as defined in <linux/acct.h>
	 * Defined values are AFORK, ASU, ACOMPAT, ACORE, and AXSIG.
	 */
	__u8	ac_flag;		/* Record flags */
	__u8	ac_nice;		/* task_nice */

	/* Delay accounting fields start
	 *
	 * All values, until comment "Delay accounting fields end" are
	 * available only if delay accounting is enabled, even though the last
	 * few fields are not delays
	 *
	 * xxx_count is the number of delay values recorded
	 * xxx_delay_total is the corresponding cumulative delay in nanoseconds
	 *
	 * xxx_delay_total wraps around to zero on overflow
	 * xxx_count incremented regardless of overflow
	 */

	/* Delay waiting for cpu, while runnable
	 * count, delay_total NOT updated atomically
	 */
	__u64	cpu_count __attribute__((aligned(8)));
	__u64	cpu_delay_total;

	/* Following four fields atomically updated using task->delays->lock */

	/* Delay waiting for synchronous block I/O to complete
	 * does not account for delays in I/O submission
	 */
	__u64	blkio_count;
	__u64	blkio_delay_total;

	/* Delay waiting for page fault I/O (swap in only) */
	__u64	swapin_count;
	__u64	swapin_delay_total;

	/* cpu "wall-clock" running time
	 * On some architectures, value will adjust for cpu time stolen
	 * from the kernel in involuntary waits due to virtualization.
	 * Value is cumulative, in nanoseconds, without a corresponding count
	 * and wraps around to zero silently on overflow
	 */
	__u64	cpu_run_real_total;

	/* cpu "virtual" running time
	 * Uses time intervals seen by the kernel i.e. no adjustment
	 * for kernel's involuntary waits due to virtualization.
	 * Value is cumulative, in nanoseconds, without a corresponding count
	 * and wraps around to zero silently on overflow
	 */
	__u64	cpu_run_virtual_total;
	/* Delay accounting fields end */
	/* version 1 ends here */

	/* Basic Accounting Fields start */
	char	ac_comm[TS_COMM_LEN];	/* Command name */
	__u8	ac_sched __attribute__((aligned(8)));
					/* Scheduling discipline */
	__u8	ac_pad[3];
	__u32	ac_uid __attribute__((aligned(8)));
					/* User ID */
	__u32	ac_gid;			/* Group ID */
	__u32	ac_pid;			/* Process ID */
	__u32	ac_ppid;		/* Parent process ID */
	/* __u32 range means times from 1970 to 2106 */
	__u32	ac_btime;		/* Begin time [sec since 1970] */
	__u64	ac_etime __attribute__((aligned(8)));
					/* Elapsed time [usec] */
	__u64	ac_utime;		/* User CPU time [usec] */
	__u64	ac_stime;		/* SYstem CPU time [usec] */
	__u64	ac_minflt;		/* Minor Page Fault Count */
	__u64	ac_majflt;		/* Major Page Fault Count */
	/* Basic Accounting Fields end */

	/* Extended accounting fields start */
	/* Accumulated RSS usage in duration of a task, in MBytes-usecs.
	 * The current rss usage is added to this counter every time
	 * a tick is charged to a task's system time. So, at the end we
	 * will have memory usage multiplied by system time. Thus an
	 * average usage per system time unit can be calculated.
	 */
	__u64	coremem;		/* accumulated RSS usage in MB-usec */
	/* Accumulated virtual memory usage in duration of a task.
	 * Same as acct_rss_mem1 above except that we keep track of VM usage.
	 */
	__u64	virtmem;		/* accumulated VM  usage in MB-usec */

	/* High watermark of RSS and virtual memory usage in duration of
	 * a task, in KBytes.
	 */
	__u64	hiwater_rss;		/* High-watermark of RSS usage, in KB */
	__u64	hiwater_vm;		/* High-water VM usage, in KB */

	/* The following four fields are I/O statistics of a task. */
	__u64	read_char;		/* bytes read */
	__u64	write_char;		/* bytes written */
	__u64	read_syscalls;		/* read syscalls */
	__u64	write_syscalls;		/* write syscalls */
	/* Extended accounting fields end */

#define TASKSTATS_HAS_IO_ACCOUNTING
	/* Per-task storage I/O accounting starts */
	__u64	read_bytes;		/* bytes of read I/O */
	__u64	write_bytes;		/* bytes of write I/O */
	__u64	cancelled_write_bytes;	/* bytes of cancelled write I/O */

	__u64  nvcsw;			/* voluntary_ctxt_switches */
	__u64  nivcsw;			/* nonvoluntary_ctxt_switches */

	/* time accounting for SMT machines */
	__u64	ac_utimescaled;		/* utime scaled on frequency etc */
	__u64	ac_stimescaled;		/* stime scaled on frequency etc */
	__u64	cpu_scaled_run_real_total; /* scaled cpu_run_real_total */

	/* Delay waiting for memory reclaim */
	__u64	freepages_count;
	__u64	freepages_delay_total;

	/* Delay waiting for thrashing page */
	__u64	thrashing_count;
	__u64	thrashing_delay_total;

	/* v10: 64-bit btime to avoid overflow */
	__u64	ac_btime64;		/* 64-bit begin time */
};

#endif


// dst = src2 - src1
#define SUB(x) \
    if (src2->x >= src1->x) \
        dst->x = src2->x - src1->x; \
    else \
        dst->x = 0;
void taskstats_sub(struct taskstats *dst, struct taskstats *src1, struct taskstats *src2)
{
    memcpy(dst, src2, sizeof(struct taskstats));
    SUB(cpu_count);
    SUB(cpu_delay_total);
    SUB(blkio_count);
    SUB(blkio_delay_total);
    SUB(swapin_count);
    SUB(swapin_delay_total);
    SUB(cpu_run_real_total);
    SUB(cpu_run_virtual_total);
    SUB(ac_utime);
    SUB(ac_stime);
    SUB(ac_minflt);
    SUB(ac_majflt);
    SUB(read_char);
    SUB(write_char);
    SUB(read_syscalls);
    SUB(write_syscalls);
    SUB(read_bytes);
    SUB(write_bytes);
    SUB(cancelled_write_bytes);
    SUB(nvcsw);
    SUB(nivcsw);
    SUB(ac_utimescaled);
    SUB(ac_stimescaled);
    SUB(cpu_scaled_run_real_total);
    SUB(freepages_count);
    SUB(freepages_delay_total);
    #if TASKSTATS_VERSION == 10
    SUB(thrashing_count);
    SUB(thrashing_delay_total);
    SUB(ac_btime64);
    #endif
}

//                CPU                     |                    IO                                   |  MEM                         |
//    PID PPID USRus SYSus csw ncsw RUNdelay | r/s w/s rMB/s wMB/s rdMB/s wdMB/s IOdelay SWAPdelay  | minflt majflt FREEPAGESdelay | Command
//time      10ms/1000=0.01ms

#define FORMAT_CPU_header "%-6s %-6s %-8s %-8s %-6s %-6s %-20s"
#define FORMAT_CPU        "%-6u %-6u %-8lu %-8lu %-6lu %-6lu %-20s"
static void print_cpu_header()
{
    printf(FORMAT_CPU_header, "PID", "PPID", "USR(us)", "SYS(us)", "CSW", "NCSW", "RUNdelay(us)");
}

static void print_cpu(struct taskstats *t, long interval)
{
    char run_delay[256];
    snprintf(run_delay, sizeof(run_delay), "%lu/%lu=%lu",
                        t->cpu_delay_total/1000,
                        t->cpu_count,
                        t->cpu_count ? t->cpu_delay_total/1000/t->cpu_count : 0);
    printf(FORMAT_CPU,  t->ac_pid,
                        t->ac_ppid,
                        t->ac_utime/1000,
                        t->ac_stime/1000,
                        t->nvcsw,
                        t->nivcsw,
                        run_delay);
}

#define FORMAT_IO_header "%-6s %-6s %-6s %-6s %-6s %-6s %-16s %-16s"
#define FORMAT_IO        "%-6lu %-6lu %-6lu %-6lu %-6lu %-6lu %-16s %-16s"
static void print_io_header()
{
    printf(FORMAT_IO_header, "r/s", "w/s", "rMB/s", "wMB/s", "rdMB/s", "wdMB/s", "IOdelay(us)", "SWAPdelay(us)");
}

static void print_io(struct taskstats *t, long interval)
{
    char io_delay[128];
    char swap_delay[128];
    snprintf(io_delay, sizeof(io_delay), "%lu/%lu=%lu",
                        t->blkio_delay_total/1000,
                        t->blkio_count,
                        t->blkio_count ? t->blkio_delay_total/1000/t->blkio_count : 0);
    snprintf(swap_delay, sizeof(swap_delay), "%lu/%lu=%lu",
                        t->swapin_delay_total/1000,
                        t->swapin_count,
                        t->swapin_count ? t->swapin_delay_total/1000/t->swapin_count : 0);
    printf(FORMAT_IO,   t->read_syscalls/interval,
                        t->write_syscalls/interval,
                        t->read_char/MB/interval,
                        t->write_char/MB/interval,
                        t->read_bytes/MB/interval,
                        t->write_bytes/MB/interval,
                        io_delay,
                        swap_delay);
}

#define FORMAT_MEM_header "%-6s %-6s %-16s"
#define FORMAT_MEM        "%-6lu %-6lu %-16s"
static void print_mem_header()
{
    printf(FORMAT_MEM_header, "MINFLT", "MAJFLT", "FRPGdelay");
}
static void print_mem(struct taskstats *t, long interval)
{
    char freepages_delay[128];
    snprintf(freepages_delay, sizeof(freepages_delay), "%lu/%lu=%lu",
                        t->freepages_delay_total/1000,
                        t->freepages_count,
                        t->freepages_count ? t->freepages_delay_total/1000/t->freepages_count : 0);
    printf(FORMAT_MEM,  t->ac_minflt, t->ac_majflt, freepages_delay);
}


static void print_comm_header()
{
    printf(" %s\n", "Command");
}

static void print_comm(struct taskstats *t)
{
    printf(" %s\n", t->ac_comm);
}


static void print_cgroupstats(struct cgroupstats *c)
{
	printf("sleeping %llu, blocked %llu, running %llu, stopped %llu, "
		"uninterruptible %llu\n", (unsigned long long)c->nr_sleeping,
		(unsigned long long)c->nr_io_wait,
		(unsigned long long)c->nr_running,
		(unsigned long long)c->nr_stopped,
		(unsigned long long)c->nr_uninterruptible);
}

static void usage(void)
{
	fprintf(stderr, "taskstats [-imav] [-C container] [-w logfile] [-r bufsize] [-t tgid] [-p pid] delay counts\n");
	fprintf(stderr, "taskstats -l [-imav] -M cpumask filter\n");
	fprintf(stderr, "  -l: listen forever\n");
	fprintf(stderr, "  -i: print IO accounting\n");
    fprintf(stderr, "  -m: print MEM accounting\n");
    fprintf(stderr, "  -a: print all accounting\n");
	fprintf(stderr, "  -v: debug on\n");
	fprintf(stderr, "  -C: container path\n");
    fprintf(stderr, "  -w: write to logfile\n");
    fprintf(stderr, "  -r: recv buffer size\n");
    fprintf(stderr, "  -t: filter tgid\n");
    fprintf(stderr, "  -p: filter pid\n");
    fprintf(stderr, "  delay: delay second\n");
    fprintf(stderr, "  counts: counts\n");
    fprintf(stderr, "  filter: filter task comm\n");
}

int main(int argc, char *argv[])
{
	int c, rc, rep_len, aggr_len, len2;
	int cmd_type = TASKSTATS_CMD_ATTR_UNSPEC;
	__u16 id;
	__u32 mypid;

	struct nlattr *na;
	int nl_sd = -1;
	int len = 0;
	pid_t tid = 0;
	pid_t rtid = 0;

	int fd = 0;
	long count = 0;
	int write_file = 0;
	int maskset = 0;
	char *logfile = NULL;
	int listen = 0;
	int containerset = 0;
	char *containerpath = NULL;
	int cfd = 0;
	int forking = 0;
	sigset_t sigset;
    int interval = 1, counts = 100000000;
    char *filter = NULL;
    struct taskstats *t;
    struct taskstats dst, t1, t2;

	struct msgtemplate msg;

	while (!forking) {
		c = getopt(argc, argv, "imaC:w:r:M:t:p:c:vl");
		if (c < 0)
			break;

		switch (c) {
		case 'i':
			print_io_accounting = 1;
			break;
		case 'm':
			print_mem_accounting = 1;
			break;
        case 'a':
			print_io_accounting = 1;
            print_mem_accounting = 1;
			break;
		case 'C':
			containerset = 1;
			containerpath = optarg;
			break;
		case 'w':
			logfile = strdup(optarg);
			printf("write to file %s\n", logfile);
			write_file = 1;
			break;
		case 'r':
			rcvbufsz = atoi(optarg);
			printf("receive buf size %d\n", rcvbufsz);
			if (rcvbufsz < 0)
				err(1, "Invalid rcv buf size\n");
			break;
		case 'M':
			strncpy(cpumask, optarg, sizeof(cpumask));
			cpumask[sizeof(cpumask) - 1] = '\0';
			maskset = 1;
			printf("cpumask %s maskset %d\n", cpumask, maskset);
			break;
		case 't':
			tid = atoi(optarg);
			if (!tid)
				err(1, "Invalid tgid\n");
			cmd_type = TASKSTATS_CMD_ATTR_TGID;
			break;
		case 'p':
			tid = atoi(optarg);
			if (!tid)
				err(1, "Invalid pid\n");
			cmd_type = TASKSTATS_CMD_ATTR_PID;
			break;
		case 'c':

			/* Block SIGCHLD for sigwait() later */
			if (sigemptyset(&sigset) == -1)
				err(1, "Failed to empty sigset");
			if (sigaddset(&sigset, SIGCHLD))
				err(1, "Failed to set sigchld in sigset");
			sigprocmask(SIG_BLOCK, &sigset, NULL);

			/* fork/exec a child */
			tid = fork();
			if (tid < 0)
				err(1, "Fork failed\n");
			if (tid == 0)
				if (execvp(argv[optind - 1],
				    &argv[optind - 1]) < 0)
					exit(-1);

			/* Set the command type and avoid further processing */
			cmd_type = TASKSTATS_CMD_ATTR_PID;
			forking = 1;
			break;
		case 'v':
			printf("debug on\n");
			dbg = 1;
			break;
		case 'l':
			printf("listen forever\n");
			listen = 1;
			break;
		default:
			usage();
			exit(-1);
		}
	}

    if (!listen) {
        if (!tid && !containerset) {
            usage();
            return -1;
        }
        if (tid && containerset) {
            fprintf(stderr, "Select either -t or -C, not both\n");
            return -1;
        }
        if (argc > optind)
            interval = atoi(argv[optind]);
        if (argc > optind + 1)
            counts = atoi(argv[optind+1]);
    } else {
        if (!maskset) {
            usage();
            return -1;
        }
        if (argc > optind)
            filter = strdup(argv[optind]);
    }

	if (write_file) {
		fd = open(logfile, O_WRONLY | O_CREAT | O_TRUNC,
			  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (fd == -1) {
			perror("Cannot open output file\n");
			exit(1);
		}
	}

	nl_sd = create_nl_socket(NETLINK_GENERIC);
	if (nl_sd < 0)
		err(1, "error creating Netlink socket\n");

	mypid = getpid();
	id = get_family_id(nl_sd);
	if (!id) {
		fprintf(stderr, "Error getting family id, errno %d\n", errno);
		goto err;
	}
	PRINTF("family id %d\n", id);

	if (maskset) {
		rc = send_cmd(nl_sd, id, mypid, TASKSTATS_CMD_GET,
			      TASKSTATS_CMD_ATTR_REGISTER_CPUMASK,
			      &cpumask, strlen(cpumask) + 1);
		PRINTF("Sent register cpumask, retval %d\n", rc);
		if (rc < 0) {
			fprintf(stderr, "error sending register cpumask\n");
			goto err;
		}
	}

	/*
	 * If we forked a child, wait for it to exit. Cannot use waitpid()
	 * as all the delicious data would be reaped as part of the wait
	 */
	if (tid && forking) {
		int sig_received;
		sigwait(&sigset, &sig_received);
	}

	do {
        if (!listen) {
            if (tid) {
                rc = send_cmd(nl_sd, id, mypid, TASKSTATS_CMD_GET,
                          cmd_type, &tid, sizeof(__u32));
                PRINTF("Sent pid/tgid, retval %d\n", rc);
                if (rc < 0) {
                    fprintf(stderr, "error sending tid/tgid cmd\n");
                    goto done;
                }
            }

            if (containerset) {
                cfd = open(containerpath, O_RDONLY);
                if (cfd < 0) {
                    perror("error opening container file");
                    goto err;
                }
                rc = send_cmd(nl_sd, id, mypid, CGROUPSTATS_CMD_GET,
                          CGROUPSTATS_CMD_ATTR_FD, &cfd, sizeof(__u32));
                if (rc < 0) {
                    perror("error sending cgroupstats command");
                    goto err;
                }
            }
        }

		rep_len = recv(nl_sd, &msg, sizeof(msg), 0);
		PRINTF("received %d bytes\n", rep_len);

		if (rep_len < 0) {
			fprintf(stderr, "nonfatal reply error: errno %d\n",
				errno);
			continue;
		}
		if (msg.n.nlmsg_type == NLMSG_ERROR ||
		    !NLMSG_OK((&msg.n), rep_len)) {
			struct nlmsgerr *err = NLMSG_DATA(&msg);
			fprintf(stderr, "fatal reply error,  errno %d\n",
				err->error);
			goto done;
		}

		PRINTF("nlmsghdr size=%zu, nlmsg_len=%d, rep_len=%d\n",
		       sizeof(struct nlmsghdr), msg.n.nlmsg_len, rep_len);

		rep_len = GENLMSG_PAYLOAD(&msg.n);

		na = (struct nlattr *) GENLMSG_DATA(&msg);
		len = 0;
		while (len < rep_len) {
			len += NLA_ALIGN(na->nla_len);
			switch (na->nla_type) {
			case TASKSTATS_TYPE_AGGR_TGID:
				/* Fall through */
			case TASKSTATS_TYPE_AGGR_PID:
				aggr_len = NLA_PAYLOAD(na->nla_len);
				len2 = 0;
				/* For nested attributes, na follows */
				na = (struct nlattr *) NLA_DATA(na);
				done = 0;
				while (len2 < aggr_len) {
					switch (na->nla_type) {
					case TASKSTATS_TYPE_PID:
						rtid = *(int *) NLA_DATA(na);
						//if (print_delays)
						//	printf("PID\t%d\n", rtid);
						break;
					case TASKSTATS_TYPE_TGID:
						rtid = *(int *) NLA_DATA(na);
						//if (print_delays)
						//	printf("TGID\t%d\n", rtid);
						break;
					case TASKSTATS_TYPE_STATS:
						count++;
                        t = (struct taskstats *) NLA_DATA(na);
                        if (count == 1) {
                            print_cpu_header();
                            if (print_io_accounting)
                                print_io_header();
                            if (print_mem_accounting)
                                print_mem_header();
                            print_comm_header();
                        }
                        if (!listen) {
                            if (count > 1) {
                                t2 = *t;
                                taskstats_sub(&dst, &t1, &t2);
                                t1 = *t;
                                t = &dst;
                            } else
                                t = NULL;
                        }
                        if (t) {
                            if (!filter || strncmp(t->ac_comm, filter, strlen(filter)) == 0) {
                                print_cpu(t, interval);
                                if (print_io_accounting)
                                    print_io(t, interval);
                                if (print_mem_accounting)
                                    print_mem(t, interval);
                                print_comm(t);
                            }
                        }
						break;
					case TASKSTATS_TYPE_NULL:
						break;
					default:
						fprintf(stderr, "Unknown nested"
							" nla_type %d\n",
							na->nla_type);
						break;
					}
					len2 += NLA_ALIGN(na->nla_len);
					na = (struct nlattr *)((char *)na +
							       NLA_ALIGN(na->nla_len));
				}
				break;

			case CGROUPSTATS_TYPE_CGROUP_STATS:
				print_cgroupstats(NLA_DATA(na));
				break;
			default:
				fprintf(stderr, "Unknown nla_type %d\n",
					na->nla_type);
			case TASKSTATS_TYPE_NULL:
				break;
			}
			na = (struct nlattr *) (GENLMSG_DATA(&msg) + len);
		}

        if (!listen) {
            sleep(interval);
            if (--counts == 0)
                break;
        }
	} while (1);
done:
	if (maskset) {
		rc = send_cmd(nl_sd, id, mypid, TASKSTATS_CMD_GET,
			      TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK,
			      &cpumask, strlen(cpumask) + 1);
		printf("Sent deregister mask, retval %d\n", rc);
		if (rc < 0)
			err(rc, "error sending deregister cpumask\n");
	}
err:
	close(nl_sd);
	if (fd)
		close(fd);
	if (cfd)
		close(cfd);
	return 0;
}
