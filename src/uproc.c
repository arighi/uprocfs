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

#include "list.h"

#include <assert.h>
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
#include <asm/bitsperlong.h>

/* The following macros are all used by the netlink code */
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

/* Used to stop the proc listener thread */
static volatile bool need_exit;

/* Protect all namespaces hash lists */
static pthread_spinlock_t lock;

/* Internal hash structures */
#define PROC_UID_HASH_SHIFT	10
#define PROC_UID_HASH_SIZE	(1UL << PROC_UID_HASH_SHIFT)
#define key_hashfn(__key) \
		hash_long((unsigned long)__key, PROC_UID_HASH_SHIFT)

/* Used to store PID -> UID mapping */
struct pid_item {
	struct hlist_node hlist;
	pid_t pid;
	int key;
};

/* Used to map a UID to a list of PIDs */
struct key_item {
	struct hlist_node hlist;
	struct list_head list;
	int key;
};

/* Single element of the key_item list */
struct key_item_node {
	struct list_head node;
	pid_t pid;
};

enum key_type {
	TYPE_UID = 0,
	TYPE_GID,
};

struct namespace {
	struct hlist_head pid_key[PROC_UID_HASH_SIZE] __cacheline_aligned;
	struct hlist_head key_pid[PROC_UID_HASH_SIZE] __cacheline_aligned;
	const char *name;
	enum key_type type;
};

#define DEFINE_NAMESPACE(__type, __name)				\
	{								\
		.pid_key = {[0 ... PROC_UID_HASH_SIZE - 1] =		\
						HLIST_HEAD_INIT},	\
		.key_pid = {[0 ... PROC_UID_HASH_SIZE - 1] =		\
						HLIST_HEAD_INIT},	\
		.type = (__type),					\
		.name = (__name),					\
	}

/* Supported PID namespaces */
static struct namespace ns[] = {
	DEFINE_NAMESPACE(TYPE_UID, "uid"),
	DEFINE_NAMESPACE(TYPE_GID, "gid"),
};

/* Total amount of supported namespaces */
#define TYPE_MAX	ARRAY_SIZE(ns)

static inline struct hlist_head *hash_from_pid(enum key_type type)
{
	return ns[type].pid_key;
}

static inline struct hlist_head *hash_from_key(enum key_type type)
{
	return ns[type].key_pid;
}

/*** pid hash table ***/

static struct pid_item *pid_find_item(enum key_type type, pid_t pid)
{
	struct hlist_node *n;
	struct pid_item *item;
	struct hlist_head *hash = hash_from_pid(type);

	hlist_for_each_entry(item, n, &hash[key_hashfn(pid)], hlist)
		if (item->pid == pid)
			return item;
	return NULL;
}

static struct pid_item *pid_add_item(enum key_type type, pid_t pid, int key)
{
	struct pid_item *item;
	struct hlist_head *hash = hash_from_pid(type);

	item = malloc(sizeof(*item));
	if (unlikely(!item))
		return NULL;
	item->pid = pid;
	item->key = key;
	hlist_add_head(&item->hlist, &hash[key_hashfn(pid)]);

	return item;
}

static inline struct pid_item *pid_add(enum key_type type, pid_t pid, int key)
{
	return pid_add_item(type, pid, key);
}

static void pid_cleanup(enum key_type type)
{
	struct hlist_node *n, *p;
	struct pid_item *item;
	struct hlist_head *hash = hash_from_pid(type);
	int i;

	for (i = 0; i < PROC_UID_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(item, n, p, &hash[i], hlist) {
			hlist_del(&item->hlist);
			free(item);
		}
	}
}

/*** key hash table ***/

static struct key_item *key_find_item(enum key_type type, int key)
{
	struct hlist_node *n;
	struct key_item *item;
	struct hlist_head *hash = hash_from_key(type);

	hlist_for_each_entry(item, n, &hash[key_hashfn(key)], hlist)
		if (item->key == key)
			return item;
	return NULL;
}

static struct key_item *key_add_item(enum key_type type, int key)
{
	struct key_item *item;
	struct hlist_head *hash = hash_from_key(type);

	item = malloc(sizeof(*item));
	if (unlikely(!item))
		return NULL;
	item->key = key;
	INIT_LIST_HEAD(&item->list);
	hlist_add_head(&item->hlist, &hash[key_hashfn(key)]);

	return item;
}

static int key_add(enum key_type type, int key, pid_t pid)
{
	struct key_item *item;
	struct key_item_node *node;

	item = key_find_item(type, key);
	if (unlikely(!item))
		item = key_add_item(type, key);
		if (unlikely(!item))
			return -ENOMEM;
	list_for_each_entry(node, &item->list, node)
		if (unlikely(node->pid == pid))
			return -EADDRINUSE;
	node = malloc(sizeof(*node));
	if (unlikely(!node))
		return -ENOMEM;
	node->pid = pid;
	list_add_tail(&node->node, &item->list);

	return 0;
}

static int key_del(enum key_type type, int key, pid_t pid)
{
	struct key_item *item;
	struct key_item_node *node;

	item = key_find_item(type, key);
	if (likely(item)) {
		list_for_each_entry(node, &item->list, node)
			if (node->pid == pid) {
				list_del(&node->node);
				free(node);
				break;
			}
		if (list_empty(&item->list)) {
			hlist_del(&item->hlist);
			free(item);
		}
	}
	return -ENOENT;;
}

static void key_cleanup(enum key_type type)
{
	struct hlist_node *n, *p;
	struct key_item *item;
	struct key_item_node *node, *pnode;
	struct hlist_head *hash = hash_from_key(type);
	int i;

	for (i = 0; i < PROC_UID_HASH_SIZE; i++)
		hlist_for_each_entry_safe(item, n, p, &hash[i], hlist) {
			list_for_each_entry_safe(node, pnode,
						&item->list, node) {
				list_del(&node->node);
				free(node);
			}
			hlist_del(&item->hlist);
			free(item);
		}
}

/*
 * Get process data (euid and egid) from /proc/<pid>/status file
 */
static int get_uid_gid_from_procfs(pid_t pid, uid_t *euid, gid_t *egid)
{
	FILE *f;
	char path[FILENAME_MAX];
	char buf[4092];
	uid_t ruid, suid, fsuid;
	gid_t rgid, sgid, fsgid;
	bool found_euid = false;
	bool found_egid = false;

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
		}
		if (found_euid && found_egid)
			break;
	}
	fclose(f);
	if (!found_euid || !found_egid)
		return -EINVAL;
	return 0;
}

/*
 * New process -> add to hash lists
 */
static void pid_key_add(pid_t pid)
{
	uid_t uid;
	gid_t gid;

	if (get_uid_gid_from_procfs(pid, &uid, &gid) < 0)
		return;
	pthread_spin_lock(&lock);
	/* Add to uid namespace */
	pid_add(TYPE_UID, pid, uid);
	key_add(TYPE_UID, uid, pid);
	/* Add to gid namespace */
	pid_add(TYPE_GID, pid, gid);
	key_add(TYPE_GID, gid, pid);
	pthread_spin_unlock(&lock);
}

/*
 * A PID updated one of its key -> also update hash lists
 */
static void pid_key_update(enum key_type type, pid_t pid, int key)
{
	struct pid_item *item;

	pthread_spin_lock(&lock);
	item = pid_find_item(type, pid);
	if (likely(item)) {
		key_del(type, item->key, item->pid);
		item->key = key;
	} else {
		item = pid_add(type, pid, key);
	}
	key_add(type, item->key, pid);
	pthread_spin_unlock(&lock);
}

/*
 * PID exit -> remove from hash lists
 */
static void pid_key_remove(pid_t pid)
{
	struct pid_item *item;
	int type;

	pthread_spin_lock(&lock);
	for (type = 0; type < TYPE_MAX; type++) {
		item = pid_find_item(type, pid);
		if (likely(item)) {
			hlist_del(&item->hlist);
			key_del(type, item->key, item->pid);
			free(item);
		}
	}
	pthread_spin_unlock(&lock);
}

/*** netlink stuff ***/

static int nl_connect(void)
{
	struct sockaddr_nl sa_nl = {};
	int buffersize = 16 * 1024 * 1024;
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
		pid = ev->event_data.id.process_pid;
		pid_key_update(TYPE_UID, pid, ev->event_data.id.e.euid);
		break;
	case PROC_EVENT_GID:
		pid = ev->event_data.id.process_pid;
		pid_key_update(TYPE_GID, pid, ev->event_data.id.e.egid);
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

/* FUSE stuff (uproc filesystem interface) */

static int _readdir(enum key_type type, void *buf,
				fuse_fill_dir_t filler,
				off_t offset, struct fuse_file_info *fi)
{
	struct hlist_head *hash = hash_from_key(type);
	struct hlist_node *n;
	struct key_item *item;
	int i;

	pthread_spin_lock(&lock);
	for (i = 0; i < PROC_UID_HASH_SIZE; i++)
		hlist_for_each_entry(item, n, &hash[i], hlist) {
			char str[FILENAME_MAX];

			snprintf(str, sizeof(str), "%u", item->key);
			if (filler(buf, str, NULL, 0))
				break;
		}
	pthread_spin_unlock(&lock);

	return 0;
}

static int uproc_readdir(const char *path, void *buf,
				fuse_fill_dir_t filler,
				off_t offset, struct fuse_file_info *fi)
{
	char name[FILENAME_MAX];
	int type;

	if (!strcmp(path, "/")) {
		for (type = 0; type < TYPE_MAX; type++)
			filler(buf, ns[type].name, NULL, 0);
		return 0;
	}
	for (type = 0; type < TYPE_MAX; type++) {
		snprintf(name, sizeof(name), "/%s", ns[type].name);
		if (!strncmp(path, name, sizeof(name)))
			return _readdir(type, buf, filler, offset, fi);
	}

	return -ENOENT;
}

static int _getattr(enum key_type type, int key, struct stat *stbuf)
{
	struct key_item *item;
	struct key_item_node *node;
	int size = 0;
	int ret = 0;

	pthread_spin_lock(&lock);
	item = key_find_item(type, key);
	if (unlikely(!item)) {
		ret = -ENOENT;
		goto out_unlock;
	}
	list_for_each_entry(node, &item->list, node) {
		char buf[FILENAME_MAX];

		size += snprintf(buf, sizeof(buf), "%u\n", node->pid);
	}
	stbuf->st_mode = S_IFREG | 0444;
	stbuf->st_nlink = 1;
	stbuf->st_size = size;
out_unlock:
	pthread_spin_unlock(&lock);

	return ret;
}

static int uproc_getattr(const char *path, struct stat *stbuf)
{
	char name[FILENAME_MAX];
	int key, type;

	memset(stbuf, 0, sizeof(*stbuf));

	if (!strcmp(path, "/")) {
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 2;
		return 0;
	}
	for (type = 0; type < TYPE_MAX; type++) {
		snprintf(name, sizeof(name), "/%s", ns[type].name);
		if (!strncmp(path, name, sizeof(name))) {
			stbuf->st_mode = S_IFDIR | 0555;
			stbuf->st_nlink = 2;
			return 0;
		}
	}
	for (type = 0; type < TYPE_MAX; type++) {
		snprintf(name, sizeof(name), "/%s/%%d", ns[type].name);
		if (sscanf(path, name, &key) == 1)
			return _getattr(type, key, stbuf);
	}

	return -ENOENT;
}

static int _open(enum key_type type, int key, struct fuse_file_info *fi)
{
	struct key_item *item;
	int ret = 0;

	pthread_spin_lock(&lock);
	item = key_find_item(type, key);
	if (unlikely(!item)) {
		ret = -ENOENT;
		goto out_unlock;
	}
	if ((fi->flags & 3) != O_RDONLY)
		ret = -EACCES;
out_unlock:
	pthread_spin_unlock(&lock);

	return ret;
}

static int uproc_open(const char *path, struct fuse_file_info *fi)
{
	char name[FILENAME_MAX];
	int type, key;

	for (type = 0; type < TYPE_MAX; type++) {
		snprintf(name, sizeof(name), "/%s/%%d", ns[type].name);
		if (sscanf(path, name, &key) == 1)
			return _open(type, key, fi);
	}
	return -ENOENT;
}

static int _read(enum key_type type, int key, char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	struct key_item *item;
	struct key_item_node *node;
	int len;
	int ret = 0;

	if (unlikely(!size))
		return 0;

	pthread_spin_lock(&lock);
	item = key_find_item(type, key);
	if (unlikely(!item)) {
		ret = -ENOENT;
		goto out_unlock;
	}
	list_for_each_entry(node, &item->list, node) {
		len = min(snprintf(buf, size, "%u\n", node->pid), size);

		buf += len;
		size -= len;
		ret += len;
		if (!size)
			break;
	}
out_unlock:
	pthread_spin_unlock(&lock);

	return ret;
}

static int uproc_read(const char *path, char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	char name[FILENAME_MAX];
	int type, key;

	for (type = 0; type < TYPE_MAX; type++) {
		snprintf(name, sizeof(name), "/%s/%%d", ns[type].name);
		if (sscanf(path, name, &key) == 1)
			return _read(type, key, buf, size, offset, fi);
	}

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
	pthread_spin_init(&lock, 0);
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
	int type;

	need_exit = true;
	pthread_join(proc_listener_thr, NULL);

	pthread_spin_destroy(&lock);

	for (type = 0; type < TYPE_MAX; type++) {
		key_cleanup(type);
		pid_cleanup(type);
	}
}

static struct fuse_operations uproc_fs = {
	.readdir	= uproc_readdir,
	.getattr	= uproc_getattr,
	.open		= uproc_open,
	.read		= uproc_read,
	.init		= uproc_init,
	.destroy	= uproc_destory,
};

int main(int argc, char **argv)
{
	return fuse_main(argc, argv, &uproc_fs, NULL);
}
