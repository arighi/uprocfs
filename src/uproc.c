/*
 *  uproc: procfs in userspace
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Copyright (C) 2011 Andrea Righi <andrea@betterlinux.com>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

#define FUSE_USE_VERSION 29

#define UPROCFS_VERSION __stringify(VERSION)

#define DEFAULT_CONFIG_FILE	"/etc/uproc.conf"

#include "config.h"

#include "list.h"

#include <assert.h>
#include <ctype.h>
#include <fuse.h>
#include <pthread.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <libgen.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

/* The following macros are all used by the netlink code */
#define NL_BUFF_SIZE	(16 * 1024 * 1024)

#define RECV_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + \
				sizeof(struct proc_event)))
#define RECV_MESSAGE_SIZE (NLMSG_SPACE(RECV_MESSAGE_LEN))

#define BUFF_SIZE (max(RECV_MESSAGE_SIZE, PAGE_SIZE))

/* Netlink structures: proc connector */
typedef struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
	struct nlmsghdr nl_hdr;
	struct __attribute__ ((__packed__)) {
		struct cn_msg cn_msg;
		struct proc_event proc_ev;
	};
} nl_msg_evt_t;

typedef struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
	struct nlmsghdr nl_hdr;
	struct __attribute__ ((__packed__)) {
		struct cn_msg cn_msg;
		enum proc_cn_mcast_op cn_mcast;
	};
} nl_msg_mcast_t;

/* proc listener: thread that listens proc connector events via netlink */
static pthread_t proc_listener_thr;

/* Protect all namespaces hash lists */
static pthread_rwlock_t lock;

/* Used to stop the proc listener thread */
static volatile bool need_exit;

/* Type of namespace rule */
enum key_type {
	TYPE_UID = 0,
	TYPE_GID,
	TYPE_COMM,
};

/* Generic key type to identify the value of a PID property */
typedef struct {
	union {
		unsigned long number;
		char *string;
	};
	enum key_type type;
} uproc_key_t;

/* Internal hash structures */
#define NS_KEY_HASH_SHIFT	9
#define NS_KEY_HASH_SIZE	(1UL << NS_KEY_HASH_SHIFT)

#define PID_MAP_HASH_SHIFT	9
#define PID_MAP_HASH_SIZE	(1UL << PID_MAP_HASH_SHIFT)

/* Used to store PID -> KEY mapping */
struct pid_item {
	struct list_head node;
	pid_t pid;
};

/* Generic namespace definition */
struct namespace {
	struct list_head pid_list;
	struct hlist_node hlist_key;
	struct hlist_node hlist_name;
	char *name;
	uproc_key_t key;
};

/*
 * Compute the hash value for the given string. The algorithm is an
 * implementation of the sdbm database library [Selzer,Yigit].
 *
 * See also: http://www.cse.yorku.ca/~oz/hash.html
 */
static unsigned long hash_string(const char *key, size_t bits)
{
	unsigned long hash = 0;
	int i = 0;

	while (*key && i++ < FILENAME_MAX)
		hash = *key++ + (hash << 6) + (hash << 16) - hash;
	return hash & ((1 << bits) - 1);
}

static inline unsigned long pid_map_hashfn(pid_t pid)
{
	return hash_long((unsigned long)pid, PID_MAP_HASH_SHIFT);
}

static inline unsigned long ns_hashfn_key(uproc_key_t key)
{
	switch (key.type) {
	case TYPE_UID:
	case TYPE_GID:
		return hash_long((unsigned long)(key.type << 16 | key.number),
					NS_KEY_HASH_SHIFT);
	case TYPE_COMM:
		return hash_string(key.string, NS_KEY_HASH_SHIFT);
	default:
		assert(0);
	}
}

static inline unsigned long ns_hashfn_name(const char *name)
{
	return hash_string(name, NS_KEY_HASH_SHIFT);
}

/* Hash list used to retrieve namespaces by key */
static struct hlist_head namespace_key[NS_KEY_HASH_SIZE] = {
	[0 ... NS_KEY_HASH_SIZE - 1] = HLIST_HEAD_INIT,
};
/* Hash list used to retrieve namespaces by name */
static struct hlist_head namespace_name[NS_KEY_HASH_SIZE] = {
	[0 ... NS_KEY_HASH_SIZE - 1] = HLIST_HEAD_INIT,
};
/* Hash list used to retrieve a namespace element by pid */
static struct hlist_head pid_map_list[PID_MAP_HASH_SIZE] = {
	[0 ... PID_MAP_HASH_SIZE - 1] = HLIST_HEAD_INIT,
};

/* Namespace iterators */
#define for_each_namespace(__ns, __i, __n)				\
	for (__i = 0; __i < NS_KEY_HASH_SIZE; __i++)			\
		hlist_for_each_entry(__ns, __n,	&namespace_key[__i], hlist_key)

#define for_each_namespace_safe(__ns, __i, __n, __p)			\
	for (__i = 0; __i < NS_KEY_HASH_SIZE; __i++)			\
		hlist_for_each_entry_safe(__ns, __n, __p,		\
					&namespace_key[__i], hlist_key)

#define for_each_namespace_pid(__ns, __item)				\
	list_for_each_entry(__item, &((__ns)->pid_list), node)

#define for_each_namespace_pid_safe(__ns, __item, __p)			\
		list_for_each_entry_safe(__item, __p,			\
					&((__ns)->pid_list), node)

/*
 * Map a PID to a list of namespace elements.
 *
 * NOTE: a PID can be associated to many namespaces, and a namespace can have
 * many PIDs.
 */
struct pid_map {
	struct hlist_node hlist;
	struct list_head list;
	pid_t pid;
};

/*
 * An element of the pid_map structure.
 */
struct pid_map_item {
	struct list_head node;
	struct pid_item *item;
};

/* Find the list of namespace elements associated to a PID */
static struct pid_map *pid_map_find(pid_t pid)
{
	const struct hlist_head *hash = pid_map_list;
	struct pid_map *map;
	struct hlist_node *n;

	hlist_for_each_entry(map, n, &hash[pid_map_hashfn(pid)], hlist) {
		if (map->pid == pid)
			return map;
	}
	return NULL;
}

/* Add a mapping between a PID and a namespace element */
static int pid_map_add(struct pid_item *item)
{
	struct pid_map *map;
	struct pid_map_item *map_item;
	pid_t pid = item->pid;

	map = pid_map_find(pid);
	if (!map) {
		map = calloc(1, sizeof(*map));
		if (unlikely(!map))
			return -ENOMEM;
		map->pid = pid;
		INIT_LIST_HEAD(&map->list);
		hlist_add_head(&map->hlist, &pid_map_list[pid_map_hashfn(pid)]);
	}
	map_item = calloc(1, sizeof(*map_item));
	if (unlikely(!map_item))
		return -ENOMEM;
	map_item->item = item;
	list_add(&map_item->node, &map->list);

	return 0;
}

/*
 * Remove all the mappings among a PID and a list of namespace elements.
 * This happens when a task exits and its PID is released.
 */
static void pid_map_del(pid_t pid)
{
	struct pid_map *map;
	struct pid_map_item *map_item, *p;
	struct pid_item *item;

	map = pid_map_find(pid);
	if (!map)
		return;
	list_for_each_entry_safe(map_item, p, &map->list, node) {
		item = map_item->item;
		list_del(&item->node);
		free(item);

		list_del(&map_item->node);
		free(map_item);
	}
	hlist_del(&map->hlist);
	free(map);
}

/* Find a namespace by key */
static struct namespace *namespace_find_key(uproc_key_t key)
{
	const struct hlist_head *hash = namespace_key;
	struct namespace *ns;
	struct hlist_node *n;

	hlist_for_each_entry(ns, n, &hash[ns_hashfn_key(key)], hlist_key) {
		if (ns->key.type != key.type)
			continue;
		if (key.type == TYPE_COMM) {
			if (!strncmp(ns->key.string, key.string, FILENAME_MAX))
				return ns;
		} else {
			if (ns->key.number == key.number)
				return ns;
		}
	}
	return NULL;
}

/* Find a namespace by name */
static struct namespace *namespace_find_name(const char *name)
{
	const struct hlist_head *hash = namespace_name;
	struct namespace *ns;
	struct hlist_node *n;

	hlist_for_each_entry(ns, n, &hash[ns_hashfn_name(name)], hlist_name)
		if (!strncmp(ns->name, name, FILENAME_MAX))
			return ns;
	return NULL;
}

/* Register a new namespace rule */
static int namespace_add(uproc_key_t key, const char *name)
{
	struct namespace *ns;

	/* Santiy check: avoid duplicate namespaces */
	if (namespace_find_key(key))
		return -EADDRINUSE;
	/* Initialize and insert the new namespace */
	ns = calloc(1, sizeof(*ns));
	if (unlikely(!ns))
		return -ENOMEM;
	ns->name = strndup(name, FILENAME_MAX);
	if (unlikely(!ns->name)) {
		free(ns);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&ns->pid_list);
	ns->key = key;
	hlist_add_head(&ns->hlist_key, &namespace_key[ns_hashfn_key(key)]);
	hlist_add_head(&ns->hlist_name, &namespace_name[ns_hashfn_name(name)]);

	return 0;
}

/* Remove a namespace rule */
static void namespace_del(struct namespace *ns)
{
	hlist_del(&ns->hlist_key);
	hlist_del(&ns->hlist_name);
	if (ns->key.type == TYPE_COMM)
		free(ns->key.string);
	free(ns->name);
	free(ns);
}

/* Add a PID to a namespace */
static struct pid_item *pid_add_item(struct namespace *ns, pid_t pid)
{
	struct pid_item *item;

	item = malloc(sizeof(*item));
	if (unlikely(!item))
		return NULL;
	item->pid = pid;
	list_add_tail(&item->node, &ns->pid_list);
	pid_map_add(item);

	return item;
}

/* Remove all PIDs from a namespace */
static void pid_cleanup_items(struct namespace *ns)
{
	struct pid_item *item, *p;

	/*
	 * Do not care too much about locking here, at this point there must be
	 * no reference to the namespace.
	 */
	for_each_namespace_pid_safe(ns, item, p)
		pid_map_del(item->pid);
}

/*
 * Get process data (euid, egid, command name) from /proc/<pid>/status file
 */
static int
get_info_from_procfs(pid_t pid, uid_t *euid, gid_t *egid, char **name)
{
	FILE *f;
	char path[FILENAME_MAX];
	char buf[PAGE_SIZE];
	uid_t ruid, suid, fsuid;
	gid_t rgid, sgid, fsgid;
	int len;
	bool found_euid = false;
	bool found_egid = false;
	bool found_name = false;

	sprintf(path, "/proc/%d/status", pid);
	f = fopen(path, "re");
	if (!f)
		return -ENOENT;

	while (fgets(buf, sizeof(buf), f)) {
		if (!strncmp(buf, "Uid:", 4)) {
			if (sscanf((buf + strlen("Uid:") + 1), "%d%d%d%d",
					&ruid, euid, &suid, &fsuid) != 4)
				break;
			found_euid = true;
		} else if (!strncmp(buf, "Gid:", 4)) {
			if (sscanf((buf + strlen("Gid:") + 1), "%d%d%d%d",
					&rgid, egid, &sgid, &fsgid) != 4)
				break;
			found_egid = true;
		} else if (!strncmp(buf, "Name:", 5)) {
			len = strlen(buf);
			if (buf[len - 1] == '\n')
				buf[len - 1] = '\0';
			*name = strdup(buf + strlen("Name:") + 1);
			if (*name == NULL)
				return -ENOMEM;
			found_name = true;
		}
		if (found_euid && found_egid && found_name)
			break;
	}
	fclose(f);
	if (!found_euid || !found_egid || !found_name)
		return -EINVAL;
	return 0;
}

/*
 * New PID -> add it to the right namespaces
 */
static void pid_key_add(pid_t pid)
{
	struct namespace *ns;
	uproc_key_t key;
	uid_t uid;
	gid_t gid;
	char *name = NULL;

	if (get_info_from_procfs(pid, &uid, &gid, &name) < 0)
		goto out;
	pthread_rwlock_wrlock(&lock);
	key.type = TYPE_UID;
	key.number = uid;
	ns = namespace_find_key(key);
	if (ns)
		pid_add_item(ns, pid);
	key.type = TYPE_GID;
	key.number = gid;
	ns = namespace_find_key(key);
	if (ns)
		pid_add_item(ns, pid);
	key.type = TYPE_COMM;
	key.string = name;
	ns = namespace_find_key(key);
	if (ns)
		pid_add_item(ns, pid);
	pthread_rwlock_unlock(&lock);
out:
	free(name);
}

/*
 * PID exit -> remove it from namespaces
 */
static void pid_key_remove(pid_t pid)
{
	pthread_rwlock_wrlock(&lock);
	pid_map_del(pid);
	pthread_rwlock_unlock(&lock);
}

/*
 * PID updated one of its key -> also update the namespaces
 */
static void pid_key_update(pid_t pid)
{
	pid_key_remove(pid);
	pid_key_add(pid);
}

/*** netlink stuff ***/

static int nl_connect(void)
{
	struct sockaddr_nl sa_nl = {};
	int buffersize = NL_BUFF_SIZE;
	int nl_sock;
	int ret;

	nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (nl_sock < 0) {
		perror("socket");
		return nl_sock;
	}
	/* Try to override buffer size */
        if (setsockopt(nl_sock, SOL_SOCKET, SO_RCVBUFFORCE,
				&buffersize, sizeof(buffersize))) {
                /* Somewhat safe default */
                buffersize = 106496;
                if (setsockopt(nl_sock, SOL_SOCKET, SO_RCVBUF,
					&buffersize, sizeof(buffersize))) {
                        close(nl_sock);
                        return -EINVAL;
                }
		fprintf(stderr, "WARNING: netlink buffer set to %d\n",
				buffersize);
        }

	sa_nl.nl_family = AF_NETLINK;
	sa_nl.nl_groups = CN_IDX_PROC;
	sa_nl.nl_pid = getpid();

	ret = bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl));
	if (ret < 0) {
		perror("bind");
		close(nl_sock);
		return ret;
	}

	return nl_sock;
}

/*
 * Subscribe on proc events (process notifications)
 */
static int set_proc_ev_listen(int nl_sock, bool enable)
{
	nl_msg_mcast_t nlcn_msg = {};
	int ret;

	nlcn_msg.nl_hdr.nlmsg_len = sizeof(nlcn_msg);
	nlcn_msg.nl_hdr.nlmsg_pid = getpid();
	nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;

	nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
	nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
	nlcn_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

	nlcn_msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN :
					PROC_CN_MCAST_IGNORE;
	ret = send(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);
	if (ret != sizeof(nlcn_msg)) {
		perror("netlink send");
		return ret;
	}
	return 0;
}

/*
 * Handle a process event
 */
static void handle_proc_ev(const struct cn_msg *cn_hdr)
{
	struct proc_event *ev;
	pid_t pid;

	ev = (struct proc_event *)cn_hdr->data;
	switch (ev->what) {
	case PROC_EVENT_FORK:
		pid = ev->event_data.fork.child_pid;
		pid_key_add(pid);
		break;
	case PROC_EVENT_UID:
	case PROC_EVENT_GID:
		pid = ev->event_data.id.process_pid;
		pid_key_update(pid);
		break;
	case PROC_EVENT_EXEC:
		pid = ev->event_data.exec.process_pid;
		pid_key_update(pid);
		break;
	case PROC_EVENT_EXIT:
		pid = ev->event_data.exit.process_pid;
		pid_key_remove(pid);
		break;
	default:
		break;
	}
}

/*
 * Receive process events
 */
static int recv_proc_ev_loop(int nl_sock)
{
	char buff[BUFF_SIZE] __attribute__ ((__aligned__(PAGE_SIZE)));
	const struct nlmsghdr *nlh;
	const struct cn_msg *cn_hdr;
	struct sockaddr_nl from_nla;
	socklen_t from_nla_len = sizeof(from_nla_len);
	int recv_len;

	while (!need_exit) {
		memset(buff, 0, sizeof(buff));
		recv_len = recvfrom(nl_sock, buff, sizeof(buff), 0,
					(struct sockaddr *)&from_nla,
					&from_nla_len);
		if (recv_len == ENOBUFS) {
			fprintf(stderr,
				"ERROR: netlink buffer full, msg dropped\n");
			continue;
		}
		if (recv_len < 1)
			continue;
		if (from_nla_len != sizeof(from_nla)) {
			fprintf(stderr,
				"ERROR: bad address size\n");
			continue;
		}
		if (from_nla.nl_groups != CN_IDX_PROC || from_nla.nl_pid != 0)
			continue;
		nlh = (struct nlmsghdr *)buff;
		while (NLMSG_OK(nlh, recv_len)) {
			cn_hdr = NLMSG_DATA(nlh);
			if (nlh->nlmsg_type == NLMSG_NOOP) {
				nlh = NLMSG_NEXT(nlh, recv_len);
				continue;
			}
			if ((nlh->nlmsg_type == NLMSG_ERROR) ||
					(nlh->nlmsg_type == NLMSG_OVERRUN))
				break;
			handle_proc_ev(cn_hdr);
			if (nlh->nlmsg_type == NLMSG_DONE)
				break;
			nlh = NLMSG_NEXT(nlh, recv_len);
		}
	}
	return 0;
}

/* Thread that periodically listens proc connector events */
static void *proc_listener(void *dummy)
{
	int nl_sock;
	int ret;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	nl_sock = nl_connect();
	if (nl_sock < 0)
		exit(EXIT_FAILURE);

	ret = set_proc_ev_listen(nl_sock, true);
	if (ret < 0) {
		ret = EXIT_FAILURE;
		goto out;
	}
	ret = recv_proc_ev_loop(nl_sock);
	if (ret < 0) {
		ret = EXIT_FAILURE;
		goto out;
	}
	set_proc_ev_listen(nl_sock, false);
out:
	close(nl_sock);
	pthread_exit(NULL);
}

/*** Configuration parser ***/

static bool is_empty_or_comment(const char *line)
{
	int i;

	for (i = 0; i < strnlen(line, FILENAME_MAX); i++) {
		if (line[i] == ';' || line[i] == '#')
			return true;
		if (!isspace(line[i]) && !iscntrl(line[i]))
			return false;
	}
	return true;
}

static void strip_blank_head(char **p)
{
	char *s = *p;

	while (isspace(*s))
		s++;
	*p = s;
}

static void strip_blank_tail(char *p)
{
	char *start = p, *s;

	s = strchr(p, ';');
	if (s)
		*s = '\0';
	s = strchr(p, '#');
	if (s)
		*s = '\0';
	if (s)
		p = s;

	s = p + strlen(p);
	while ((isspace(*s) || iscntrl(*s)) && (s > start))
		s--;

	*(s + 1) = '\0';
}

/* Simple config file parser */
static int read_config(const char *file)
{
	char line[PAGE_SIZE];
	char type_str[FILENAME_MAX];
	char name[FILENAME_MAX];
	char value[FILENAME_MAX];
	uproc_key_t key;
	char *p;
	FILE *f;
	int line_no = 0;
	int ret;

	if (!strcmp(file, "-"))
		f = stdin;
	else
		f = fopen(file, "r");
	if (!f) {
		fprintf(stderr, "ERROR: couldn't open file %s\n", file);
		return -ENOENT;
	}
	while ((p = fgets(line, sizeof(line), f)) != NULL) {
		line_no++;

		/* Strip heading and trailing spaces */
		strip_blank_head(&p);
		strip_blank_tail(p);

		if (is_empty_or_comment(p))
			continue;

		ret = sscanf(line, "%256s %256s %256s", type_str, value, name);
		if (ret != 3) {
			fprintf(stderr, "ERROR: syntax error at %s:%d\n",
					file, line_no);
			return -EINVAL;
		}
		if (!strcmp(type_str, "uid")) {
			key.type = TYPE_UID;
			key.number = atoi(value);
		} else if (!strcmp(type_str, "gid")) {
			key.type = TYPE_GID;
			key.number = atoi(value);
		} else if (!strcmp(type_str, "cmd")) {
			key.type = TYPE_COMM;
			key.string = strdup(value);
			if (!key.string) {
				fprintf(stderr,
					"ERROR: out of memory at %s:%d\n",
					file, line_no);
				return -ENOMEM;
			}
		} else {
			fprintf(stderr, "ERROR: unknown type '%s' at %s:%d\n",
					type_str, file, line_no);
			return -EINVAL;
		}
		ret = namespace_add(key, name);
		if (ret < 0) {
			fprintf(stderr,
				"ERROR: couldn't register namespace %s: %d\n",
				name, ret);
			return ret;
		}
	}
	if (f != stdin)
		fclose(f);
	return 0;
}

/*** FUSE stuff (uproc filesystem interface) ***/

/* uprocfs state and configuration */
struct uproc_conf {
	char *config_file;
};
static struct uproc_conf uproc_conf;

/* Free internal fuse config memory */
static void uproc_free_config(struct uproc_conf *conf)
{
	free(conf->config_file);
}

/* uprocfs custom command line options */
enum {
	KEY_VERSION = 0,
	KEY_HELP,
};

#define UPROC_OPT(t, p, v) { t, offsetof(struct uproc_conf, p), v }

static struct fuse_opt uproc_opts[] = {
	UPROC_OPT("config_file=%s", config_file, 0),

        FUSE_OPT_KEY("-V", KEY_VERSION),
        FUSE_OPT_KEY("--version", KEY_VERSION),
        FUSE_OPT_KEY("-h", KEY_HELP),
        FUSE_OPT_KEY("--help", KEY_HELP),

	FUSE_OPT_END,
};

static int uproc_readdir(const char *path, void *buf,
				fuse_fill_dir_t filler,
				off_t offset, struct fuse_file_info *fi)
{
	struct namespace *ns;
	struct hlist_node *n;
	int i;

	if (!strcmp(path, "/")) {
		for_each_namespace(ns, i, n)
			filler(buf, ns->name, NULL, 0);
		return 0;
	}
	return -ENOENT;
}

/*
 * The file size is evaluated looking at the size of all the PIDs inside the
 * namespace it refers.
 */
static size_t namespace_size(const struct namespace *ns)
{
	const struct pid_item *item;
	size_t size = 0;

	pthread_rwlock_rdlock(&lock);
	for_each_namespace_pid(ns, item) {
		char str[FILENAME_MAX];

		size += snprintf(str, sizeof(str), "%u\n", item->pid);
	}
	pthread_rwlock_unlock(&lock);

	return size;
}

static int uproc_getattr(const char *path, struct stat *stbuf)
{
	struct namespace *ns;

	memset(stbuf, 0, sizeof(*stbuf));

	if (!strcmp(path, "/")) {
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 2;
		return 0;
	}
	ns = namespace_find_name(path + 1);
	if (ns) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = namespace_size(ns);
		return 0;
	}
	return -ENOENT;
}

static int uproc_open(const char *path, struct fuse_file_info *fi)
{
	struct namespace *ns;

	ns = namespace_find_name(path + 1);
	if (ns) {
		if ((fi->flags & 3) != O_RDONLY)
			return -EACCES;
		else
			return 0;
	}
	return -ENOENT;
}

static int _uproc_read(const struct namespace *ns, char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	const struct pid_item *item;
	int len;
	int ret = 0;

	pthread_rwlock_rdlock(&lock);
	for_each_namespace_pid(ns, item) {
		len = min(snprintf(buf, size, "%u\n", item->pid), size);

		buf += len;
		size -= len;
		ret += len;

		if (!size)
			break;
	}
	pthread_rwlock_unlock(&lock);

	return ret;
}

static int uproc_read(const char *path, char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	struct namespace *ns;

	if (unlikely(!size))
		return 0;
	ns = namespace_find_name(path + 1);
	if (ns)
		return _uproc_read(ns, buf, size, offset, fi);
	return -ENOENT;
}

/*
 * Only called once at startup to populate internal hash lists with all running
 * PIDs.
 *
 * Next PID events will be handled using the netlink proc connector.
 */
static int scan_procfs(void)
{
	DIR *procfs;
	struct dirent *de;
	pid_t pid;
	int n_pids = 0;

	procfs = opendir("/proc");
	if (!procfs) {
		perror("opendir");
		return -ENOENT;
	}
	while ((de = readdir(procfs)) != NULL) {
		/* skip non-pid files */
		if (de->d_name[0] > '9')
			continue;
		if (de->d_name[0] < '1')
			continue;
		pid = atoi(de->d_name);
		if (likely(pid))
			pid_key_add(pid);
	}
	closedir(procfs);

	return n_pids;
}

/*
 * Execute the PID listener thread and populate internal hash lists with all
 * running PIDs.
 */
static void *uproc_init(struct fuse_conn_info *conn)
{
	int ret;

	if (uproc_conf.config_file == NULL) {
		/* NOTE: this is free()'d in uproc_free_config() */
		uproc_conf.config_file = strdup(DEFAULT_CONFIG_FILE);
		if (!uproc_conf.config_file) {
			kill(getpid(), SIGHUP);
			return NULL;
		}
	}
	ret = read_config(uproc_conf.config_file);
	if (ret < 0) {
		kill(getpid(), SIGHUP);
		return NULL;
	}

	pthread_rwlock_init(&lock, NULL);
	if (pthread_create(&proc_listener_thr, NULL, proc_listener, NULL) < 0) {
		perror("pthread_create");
		exit(EXIT_FAILURE);
	}
	scan_procfs();

	return NULL;
}

/* Cleanup routine when uproc is unmounted */
static void uproc_destory(void *unused)
{
	struct namespace *ns;
	struct hlist_node *n, *p;
	int i;

	need_exit = true;
	pthread_join(proc_listener_thr, NULL);

	pthread_rwlock_destroy(&lock);

	for_each_namespace(ns, i, n)
		pid_cleanup_items(ns);
	for_each_namespace_safe(ns, i, n, p)
		namespace_del(ns);
}

/* FUSE filesystem declaration */
static struct fuse_operations uproc_fs = {
	.readdir	= uproc_readdir,
	.getattr	= uproc_getattr,
	.open		= uproc_open,
	.read		= uproc_read,
	.init		= uproc_init,
	.destroy	= uproc_destory,
};

static void uproc_usage(const char *progname)
{
	fprintf(stderr,
"usage: %s mountpoint [options]\n"
"\n"
"general options:\n"
"    -o opt,[opt...]        mount options\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"\n"
"uprocfs options:\n"
"    -o config_file=FILE    specifies alternative configuration file\n"
"\n", progname);
}

static int uproc_fuse_main(struct fuse_args *args)
{
	return fuse_main(args->argc, args->argv, &uproc_fs, NULL);
}

static int uproc_opt_proc(void *data, const char *arg, int key,
				struct fuse_args *outargs)
{
	switch (key) {
	case KEY_HELP:
		uproc_usage(outargs->argv[0]);
		fuse_opt_add_arg(outargs, "-ho");
		uproc_fuse_main(outargs);
		exit(EXIT_FAILURE);

	case KEY_VERSION:
		fprintf(stderr, "uprocfs version %s\n", UPROCFS_VERSION);
		fuse_opt_add_arg(outargs, "--version");
		uproc_fuse_main(outargs);
		exit(EXIT_SUCCESS);
	}
	return 1;
}

int main(int argc, char **argv)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	int ret;

	fuse_opt_parse(&args, &uproc_conf, uproc_opts, uproc_opt_proc);
	ret = uproc_fuse_main(&args);
	fuse_opt_free_args(&args);
	uproc_free_config(&uproc_conf);

	return ret;
}
