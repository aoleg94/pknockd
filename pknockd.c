#include "khash.h"
#include "kvec.h"
#include "iniparser.h"
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#define CHECK(msg, ...) do { if((__VA_ARGS__) < 0) { logf(LOG_ERR, msg " (errno %d %s)", errno, strerror(errno)); goto error; } } while(0)
#define CHECK_NULL(msg, ...) do { if((__VA_ARGS__) == 0) { logf(LOG_ERR, msg " (errno %d %s)", errno, strerror(errno)); goto error; } } while(0)
#define CHECK_MEM(...) CHECK_NULL("out of memory", __VA_ARGS__)

static int conf_usesyslog = 0;
static int usesyslog = 0;
static const char* pidfile = 0;
static const char* logfile = 0;
static const char* interface = 0;
static int min_seq_timeout = 10000;

static FILE* log = 0;
static int min_log_pri = LOG_WARNING;
static inline const char* priority_string(int pri)
{
	switch (pri) {
	case LOG_EMERG:		return "emergency";
	case LOG_ALERT:		return "alert";
	case LOG_CRIT:		return "fatal";
	case LOG_ERR:		return "error";
	case LOG_WARNING:	return "warning";
	case LOG_NOTICE:	return "notice";
	case LOG_INFO:		return "info";
	case LOG_DEBUG:		return "debug";
	}
	return "!!!BUG!!!";
}
#define logf(pri, fmt, ...) do { if(pri <= min_log_pri) {\
	if(usesyslog) syslog(pri, fmt, ##__VA_ARGS__);\
	if(!usesyslog || pri <= LOG_ERR) fprintf(log, "pknockd: %s: "fmt"\n", priority_string(pri), ##__VA_ARGS__);\
	}} while(0)

struct section
{
	const char* sequence;
	int seq[32];
	int seq_length;
	int seq_timeout;
	int cmd_timeout;
	const char* command;
	const char* stop_command;
#define start_command command
};

struct match
{
	int port;
	time_t ts;
};

#define MATCH_LIST_LENGTH 32
struct match_list
{
	struct match m[MATCH_LIST_LENGTH];
	int next;
};
#define MATCH_LIST_ROUND(at) (((unsigned)(at)) % MATCH_LIST_LENGTH)
#define MATCH_LIST_AT(ml, at) &((ml)->m[MATCH_LIST_ROUND(at)])

static inline void match_push(struct match_list* ml, int port)
{
	struct match* m = MATCH_LIST_AT(ml, ml->next);
	ml->next = MATCH_LIST_ROUND(ml->next+1);
	time(&m->ts);
	m->port = port;

#if 0
	for(int i = 0; i < MATCH_LIST_LENGTH; i++)
	{
		logf(LOG_DEBUG, "mpush: ml %d@%d ts %d", ml->m[i].port, i, (int)ml->m[i].ts);
	}
#endif
}

struct stop_callback
{
	const char* cmd;
	char ipstr[INET6_ADDRSTRLEN];
	time_t at;
};
static kvec_t(struct stop_callback) stoplist = {};

static inline int put_stop_callback(struct stop_callback* scb_in)
{
	struct stop_callback* scb;
	CHECK_MEM(scb = (kv_pushp(struct stop_callback, stoplist)));
	*scb = *scb_in;
	return 0;
error:
	return -1;
}

static inline int free_stop_callback(struct stop_callback* scb)
{
	if(kv_size(stoplist) < 1)
		return 0;
	struct stop_callback* last = &kv_pop(stoplist);
	if(scb != last)
		*scb = *last;
	return 0;
/*error:
	return -1;*/
}

KHASH_MAP_INIT_STR(cfg, struct section)
KHASH_MAP_INIT_STR(ip, struct match_list)
KHASH_MAP_INIT_INT(fd2port, int)

static kh_cfg_t* cfg;
static kh_ip_t* ip;
static kh_fd2port_t* fd2port;

static inline const char* sa_str(struct sockaddr* sa, char buf[INET6_ADDRSTRLEN])
{
	struct sockaddr_in* sin = (struct sockaddr_in*)sa;
	struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sa;
	void* src = NULL;
	switch(sa->sa_family)
	{
	case AF_INET:
		src = &sin->sin_addr;
		break;
	case AF_INET6:
		src = &sin6->sin6_addr;
		break;
	}
	return inet_ntop(sa->sa_family, src, buf, INET6_ADDRSTRLEN);
}

static inline int parse_sequence(struct section* sec)
{
	const char* s = sec->sequence;
	int* p = sec->seq;
	int* e = sec->seq + sizeof(sec->seq)/sizeof(sec->seq[0]);
	while(*s && p < e)
	{
		int port;
		char type[4] = "tcp";
		int c = sscanf(s, "%d:%3s", &port, type);

		switch(c)
		{
		case 2:
			if(!strcasecmp(type, "udp"))
				port = -port;
			else
				CHECK("invalid sequence field type", -strcasecmp(type, "tcp"));
		case 1:
			*p++ = port;
			sec->seq_length++;
		}

		s = strchr(s, ',');
		if(!s)
			break;
		s += strspn(s, " \t,");
	}
	if (p < e)
		return 0;
error:
	return -1;
}

static inline int parse_knockd_config(const char* file)
{
	int ret = -1;
	dictionary* d;
	CHECK_NULL("failed to open config file", d = iniparser_load(file));
	conf_usesyslog = iniparser_getboolean(d, "options:usesyslog", 0);
	pidfile = iniparser_getstring(d, "options:pidfile", pidfile);
	logfile = iniparser_getstring(d, "options:logfile", logfile);
	if(!interface)
		interface = iniparser_getstring(d, "options:interface", interface);
	int nsec = iniparser_getnsec(d);
	cfg = kh_init_cfg();
	for(int i = 0; i < nsec; i++)
	{
		const char* secname = iniparser_getsecname(d, i);
		if(!strcmp(secname, "options"))
			continue;

		int is_new = 0;
		khint_t k = kh_put_cfg(cfg, secname, &is_new);
		struct section* sec = &kh_value(cfg, k);
		memset(sec, 0, sizeof(*sec));

		char key[strlen(secname) + sizeof(":start_command") + 1];
		int off = sprintf(key, "%s:", secname);
		char* p = key + off;
#define PARAM(type, name, def) strcpy(p, #name); sec->name = iniparser_get##type(d, key, def)
		PARAM(string, sequence, 0);
		PARAM(int, seq_timeout, 25);
		PARAM(int, cmd_timeout, 10);
		PARAM(string, command, 0);
		PARAM(string, start_command, sec->command);
		PARAM(string, stop_command, 0);
#undef  PARAM
		if(!sec->sequence || !sec->sequence[0] || !sec->command || !sec->command[0])
		{
			logf(LOG_WARNING, "invalid section %s: sequence and/or command is not set", secname);
			kh_del_cfg(cfg, k);
		}
		if(!sec->seq_timeout)
		{
			logf(LOG_WARNING, "invalid section %s: null sequence timeout", secname);
			kh_del_cfg(cfg, k);
		}
		strcpy(p, "tcpflags");
		if(iniparser_getstring(d, key, 0))
		{
			logf(LOG_WARNING, "section %s: tcpflags are not supported", secname);
		}

		if(sec->seq_timeout < min_seq_timeout)
			min_seq_timeout = sec->seq_timeout;
		CHECK("failed to parse port sequence", parse_sequence(sec));
	}

	ret = 0;
error:
	/*if(d)
		iniparser_freedict(d);*/
	if(ret && cfg)
		kh_destroy_cfg(cfg);
	return ret;
}

KHASH_SET_INIT_INT(ports)

static inline int open_ports(struct pollfd** ret_fds)
{
	kh_ports_t* ports;
	CHECK_MEM(fd2port = kh_init_fd2port());
	CHECK_MEM(ports = kh_init_ports());
	for (khint_t i = kh_begin(cfg); i != kh_end(cfg); ++i) {
		if (!kh_exist(cfg,i)) continue;
		struct section* sec = &kh_value(cfg,i);
		for(int j = 0; j < sec->seq_length; j++)
		{
			int ret;
			kh_put_ports(ports, sec->seq[j], &ret);
		}
	}

	int ret = -1;
	int count = kh_size(ports);
	struct pollfd* fds, *p;
	CHECK_MEM(p = fds = calloc(count, sizeof(*fds)));

	for (khint_t i = kh_begin(ports); i != kh_end(ports); ++i) {
		if (!kh_exist(ports,i)) continue;
		int port = kh_key(ports,i);
		int udp = port < 0;
		int flags = 1;
		struct sockaddr* sa;
		socklen_t sl;

#if 1
		struct sockaddr_in6 sin6 = {};
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(udp ? -port : port);
		sin6.sin6_addr = in6addr_any;
		sa = (struct sockaddr*)&sin6;
		sl = sizeof(sin6);
#else
		struct sockaddr_in sin = {};
		sin.sin_family = AF_INET;
		sin.sin_port = htons(udp ? -port : port);
		sin.sin_addr.s_addr = 0;
		sa = (struct sockaddr*)&sin;
		sl = sizeof(sin);
#endif
		CHECK("failed to create socket", p->fd = socket(sa->sa_family, udp ? SOCK_DGRAM : SOCK_STREAM, 0));
		CHECK("failed to set address reuse for port socket", setsockopt(p->fd, SOL_SOCKET, SO_REUSEPORT, &flags, sizeof(flags)));
		CHECK("failed to bind port socket", bind(p->fd, sa, sl));
		if(interface && interface[0])
			CHECK("failed tobind port socket to interface", setsockopt(p->fd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)));
		CHECK("failed to get socket fd flags", flags = fcntl(p->fd, F_GETFL));
		CHECK("failed to set socket fd nonblocking", fcntl(p->fd, F_SETFL, flags | O_NONBLOCK));
		if(!udp)
			CHECK("failed to set socket fd listening", listen(p->fd, SOMAXCONN));

		int is_new = 1;
		khint_t k = kh_put_fd2port(fd2port, p->fd, &is_new);
		kh_value(fd2port, k) = port;

		p->events = POLLIN;
		p++;
	}

	ret = count;
	*ret_fds = fds;
error:
	if(ret < 0 && fds)
		free(fds);
	kh_destroy_ports(ports);
	return ret;
}

static inline int fire_stop_callback(struct stop_callback* scb);
static inline int check_ports_and_act(struct match_list* ml, const char* ipstr)
{
	for (khint_t i = kh_begin(cfg); i != kh_end(cfg); ++i)
	{
		if (!kh_exist(cfg,i)) continue;
		struct section* sec = &kh_value(cfg,i);
		int start = ml->next - sec->seq_length;
		for(int j = 0; j < sec->seq_length; j++)
		{
			struct match* p = MATCH_LIST_AT(ml, start + (j ? j-1 : 0));
			struct match* m = MATCH_LIST_AT(ml, start + j);

			logf(LOG_DEBUG, "check: seq %d@%d ml %d td %d m %d", sec->seq[j], j, m->port, (int)(m->ts - p->ts), (int)(m - ml->m));

			if(sec->seq[j] != m->port // port mismatch
			||((m->ts - p->ts) > sec->seq_timeout)) // or large interval
				goto next;
			logf(LOG_DEBUG, "check: crap");
		}
		// got match
		logf(LOG_INFO, "got match from %s, section '%s'!", ipstr, kh_key(cfg, i));

		// flush match list, force sequence restart for client
		memset(ml, 0, sizeof(*ml));

		struct stop_callback scb;
		scb.cmd = sec->command;
		strcpy(scb.ipstr, ipstr);
		fire_stop_callback(&scb);

		if(sec->stop_command)
		{
			scb.cmd = sec->stop_command;
			scb.at = time(0) + sec->cmd_timeout;
			put_stop_callback(&scb);
		}

next:;
	}
	return 0;
/*error:
	return -1;*/
}

static inline int fire_stop_callback(struct stop_callback* scb)
{
	int cl = strlen(scb->cmd);
	int il = strlen(scb->ipstr);
	int tl = strlen("%IP%");
	char cmd[il * cl / tl + 1];
	const char *s = scb->cmd;
	char *d = cmd;
	while(*s)
	{
		const char* t = strstr(s, "%IP%");
		if(t)
		{
			int pl = t-s;
			memcpy(d, s, pl);
			memcpy(d + pl, scb->ipstr, il);
			s += pl + tl;
			d += pl + il;
		}
		else
		{
			strcpy(d, s);
			break;
		}
	}

	logf(LOG_INFO, "running %s", cmd);
	return system(cmd);
}

static inline int mainloop(int nfds, struct pollfd* fds)
{
	CHECK_MEM(ip = kh_init_ip());
	for(;;)
	{
		time_t now = time(0);
		int timeout = min_seq_timeout;
		for(int i = 0; i < kv_size(stoplist); i++)
		{
			int tmo = kv_A(stoplist, i).at - now;
			if(tmo < 0)
				tmo = 0;
			if(tmo < timeout)
				timeout = tmo;
		}

		int n;
		CHECK("poll failed", n = poll(fds, nfds, timeout * 1000));
		for(int i = 0; n && i < nfds; i++)
		{
			struct pollfd* p = fds + i;
			if(!p->revents)
				continue;

			khint_t k = kh_get_fd2port(fd2port, p->fd);
			CHECK_NULL("BUG fd2port", kh_exist(fd2port, k));
			int port = kh_value(fd2port, k);
			int udp = port < 0;
			char ipstr[INET6_ADDRSTRLEN];
			struct sockaddr_in6 sin6;
			struct sockaddr* sa = (struct sockaddr*)&sin6;
			socklen_t sl = sizeof(sin6);

			if(udp)
			{
				char c;
				CHECK("failed to read udp socket", recvfrom(p->fd, &c, 1, 0, sa, &sl));
			}
			else
			{
				int sfd;
				CHECK("failed to accept connection", sfd = accept(p->fd, sa, &sl));
				close(sfd);
			}

			int is_new = 0;
			khint_t j = kh_put_ip(ip, sa_str(sa, ipstr), &is_new);
			struct match_list* ml = &kh_value(ip, j);
			if(is_new)
				memset(ml, 0, sizeof(*ml));
			match_push(ml, port);
			logf(LOG_INFO, "match: %s at port %d", ipstr, port);
			CHECK("error while checking sequence matching", check_ports_and_act(ml, ipstr));
		}

		for(int i = 0; i < kv_size(stoplist); i++)
		{
			struct stop_callback* scb = &kv_A(stoplist, i);
after_remove:
			if(scb->at > now)
				continue;

			fire_stop_callback(scb);
			free_stop_callback(scb);
			if(kv_size(stoplist))
				goto after_remove;
		}
	}
error:
	return -1;
}

static inline int usage()
{
	fprintf(stderr, "usage: pknockd [-dDv] [-c <config>] [-i <interface>]\n"
					"	-i <interface> Specify an interface to listen on. The default is eth0.\n"
					"	-d Become a daemon. This is usually desired for normal server-like operation.\n"
					"	-c <config> Specify an alternate location for the config file. Default is /etc/knockd.conf.\n"
					"	-D Ouput debugging messages.\n"
					"	-v Output verbose status messages.\n");
	return 1;
}

static void sigint(int sig)
{
	for(int i = 0; i < kv_size(stoplist); i++)
	{
		struct stop_callback* scb = &kv_A(stoplist, i);
		fire_stop_callback(scb);
	}
	int fd, port;
	kh_foreach(fd2port, fd, port, close(fd));
	(void)port;
	fflush(log);
	exit(0);
}

int main(int argc, char** argv)
{
	log = stderr;
	int c = 0;
	int daemonize = 0;
	while(c >= 0)
	{
		c = getopt(argc, argv, "c:dDvi:");
		switch(c)
		{
		case -1:
			continue;
		case 'D':
			min_log_pri = LOG_DEBUG;
			break;
		case 'v':
			min_log_pri = LOG_INFO;
			break;
		case 'c':
			CHECK("failed to parse config", parse_knockd_config(optarg));
			break;
		case 'i':
			interface = strdup(optarg);
			break;
		case 'd':
			daemonize = 1;
		default:
			return usage();
		}
	}

	if(!cfg)
		CHECK("failed to parse config", parse_knockd_config("/etc/knockd.conf"));
	if(!interface)
		interface = "eth0";

	if(!conf_usesyslog && logfile)
	{
		FILE* logfp;
		CHECK_NULL("failed to open log file", logfp = fopen(logfile, "a"));
		log = logfp;
	}

	if(daemonize)
		CHECK("failed to daemonize", daemon(0, 1));
	if((usesyslog = conf_usesyslog))
		openlog("pknockd", 0, LOG_DAEMON);
	if(pidfile)
	{
		FILE* fp = fopen(pidfile, "w");
		if(fp)
		{
			fprintf(fp, "%d", getpid());
			fclose(fp);
		}
	}
	signal(SIGINT, sigint);
	signal(SIGTERM, sigint);

	struct pollfd* fds = NULL;
	int nfds;
	CHECK("failed to open ports for listening", nfds = open_ports(&fds));
	CHECK("error while processing port knocks", mainloop(nfds, fds));

error:
	return 1;
}
