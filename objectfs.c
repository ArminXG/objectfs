/*
 * ObjectFS
 * Copyright © 2018-2019 Armin Schindler
 * Author: Armin Schindler <armin.schindler@melware.de>
 *
 * This program can be distributed under the terms of Apache 2.0 license.
 * See the file LICENSE.
 */

#define USE_XATTR

#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef USE_XATTR
#include <sys/xattr.h>
#endif
#include <fcntl.h>
#include <pthread.h>
#include <endian.h>


#define OFS_VERSION "0.9"

#define MAXNAMELEN 256
#define MAXPATHLEN 8192

#define INODE_ROOT 1

struct ofs_s {
	char	*path;
	mode_t	def_filemode;
	mode_t	def_dirmode;
	int		noatime;
};
static struct ofs_s ofs;

/*
 * endianess
 */
#define READ(s)		le64toh(s)
#define WRITE(s,v)	(s) = htole64(v)

/*
 * logging (debug)
 */
static FILE *logfile = NULL;

static void log_open()
{
	logfile = fopen("objectfs.log", "w");
	/* set logfile to line buffering */
	setvbuf(logfile, NULL, _IOLBF, 0);
}

static void log_close()
{
	if (logfile) {
		fclose(logfile);
	}
	logfile = NULL;
}

static void log_msg(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);

	if (logfile) {
		vfprintf(logfile, format, ap);
	}
}

/*
 * helpers
 */
static char *get_path_and_name(char *p)
{
	size_t len = strlen(p);
	char *s;

	if (len == 0) {
		return p;
	}
	if (len > 1) {
		if (p[len - 1] == '/') {
			/* remove trailing slash */
			p[len - 1] = 0;
		}
	}

	s = strrchr(p, '/');
	if (s == NULL) {
		return NULL;
	}

	*s = 0;
	return s+1;
}

static char *strncpy_safe(char *dest, const char *src, size_t n)
{
	if (n > 0) {
		strncpy(dest, src, n - 1);
		dest[n - 1] = '\0';
	}
	return dest;
}

static uint64_t get_milliseconds(void)
{
	uint64_t msecs;
	struct timespec tspec;

	clock_gettime(CLOCK_MONOTONIC_RAW, &tspec);

	msecs = tspec.tv_sec * 1000L;
	msecs += (tspec.tv_nsec / 1.0e6);

	return msecs;
}

/*
 *****************************************************************************
 * directory functions
 *****************************************************************************
 */

struct __attribute__((__packed__)) dir_entry_s {
	uint64_t	inode;
	uint64_t	reserved[8-1];
	char		name[MAXNAMELEN];
};

struct __attribute__((__packed__)) dir_inode_s {
	uint64_t	inode;
	uint64_t	mode;
	uint64_t	nlink;
	uint64_t	uid;
	uint64_t	gid;
	uint64_t	rdev;
	uint64_t	size;
	uint64_t	atimsec;
	uint64_t	atimnsec;
	uint64_t	ctimsec;
	uint64_t	ctimnsec;
	uint64_t	mtimsec;
	uint64_t	mtimnsec;
	uint64_t	flags;
	uint64_t	reserved[32-15]; // sum=256 bytes including here
	uint64_t	xattrlength;
};

struct __attribute__((__packed__)) dir_inode_xattr_s {
	char		name[MAXNAMELEN];
	uint64_t	valuesize;
};

static pthread_mutex_t directory_mutex = PTHREAD_MUTEX_INITIALIZER;

/* base operations */

static int directory_init(void);

static void directory_lock(void);
static void directory_unlock(void);

/* inode number management */

static uint64_t directory_get_free_inode(void);
static void directory_alloc_inode(uint64_t inode);
static void directory_put_free_inode(uint64_t inode);

/* directory entrylist */

static int directory_read_entrylist(struct dir_entry_s **e, uint64_t inode);
static int directory_write_entrylist(struct dir_entry_s *e, int length, uint64_t inode);
static int directory_do_write_entrylist(struct dir_entry_s *e, int length, uint64_t inode);
static int directory_add_entryobject(uint64_t inode, struct dir_entry_s *e);
static int directory_remove_entryobject(const char *name, uint32_t parent);
static int directory_find_entry(const char *path, uint64_t *inode, uint64_t *parent);
static uint64_t directory_get_entry_by(const char *name, uint64_t parent);
static int directory_add_entry(const char *path, uint64_t mode,
	uint64_t uid, uint64_t gid, uint64_t rdev, uint64_t size,
	struct timespec *atim, struct timespec *ctim, struct timespec *mtim,
	struct dir_inode_s *inodep);

/* inode operations */

static int directory_read_inode(uint64_t inode, struct dir_inode_s **ip);
static int directory_write_inode(uint64_t inode, struct dir_inode_s *i);
static int directory_do_write_inode(uint64_t inode, struct dir_inode_s *i);
static void directory_inode_update_times(uint64_t inode,
	struct timespec *atim, struct timespec *ctim, struct timespec *mtim);
static void directory_inode_increase_nlink(uint64_t inode);
static void directory_inode_decrease_nlink(uint64_t inode);
static int directory_unlink_inode(uint64_t inode, uint64_t parent, struct stat *statbuf);
static int directory_unlink_inodefile(uint64_t inode);
static int directory_chattr_mode(uint64_t inode, mode_t mode);
static int directory_chattr_uidgid(uint64_t inode, uid_t uid, gid_t gid);
static int directory_inode_symlink(uint64_t inode, const char *path);
static int directory_inode_readlink(uint64_t inode, char *link, size_t size);
static int directory_hardlink(const char *newpath, uint64_t inode);
static int directory_inode_truncate(uint64_t inode, off_t newsize);
static int directory_rename(uint64_t inode, uint64_t parent, const char *name, struct stat *statbuf, const char *newpath);

/* inode xattr operations */

#ifdef USE_XATTR
#define XATTR_MAX_ENTRIES 256
static int directory_inode_add_xattr(uint64_t inode, struct dir_inode_s *i, const char *name, const char *value, size_t size);
static int directory_inode_delete_xattr(uint64_t inode, struct dir_inode_s *i, struct dir_inode_xattr_s **xattr, struct dir_inode_xattr_s *xdel);
static int directory_inode_read_xattr(uint64_t inode, struct dir_inode_s *i, struct dir_inode_xattr_s **xattr);
static int directory_inode_setxattr(uint64_t inode, const char *name, const char *value, size_t size, int flags);
static int directory_inode_getxattr(uint64_t inode, const char *name, char *value, size_t size);
static int directory_inode_listxattr(uint64_t inode, char *list, size_t size);
static int directory_inode_removexattr(uint64_t inode, const char *name);
#endif

/* */

/* managing store files */

#define FILETYPE_OBJECT ".obj"
#define FILETYPE_INODE ".dat"

struct store_filename_s {
	char	fullpathinodefile[MAXPATHLEN];
	char	fullpathobjectfile[MAXPATHLEN];
	char	fullpath[MAXPATHLEN];
	char	fullmidpath[MAXPATHLEN];
	char	fulllowpath[MAXPATHLEN];
};

static int store_set_filename(uint64_t inode, struct store_filename_s *store)
{
	int ret;
	int i;
	struct stat statbuf;
	char pathname[MAXPATHLEN];
	char xpath[MAXNAMELEN];
	char lowpath[MAXPATHLEN];
	char midpath[MAXPATHLEN];

	memset(store, 0, sizeof(*store));

	snprintf(pathname, sizeof(pathname), "%s", ofs.path);
	strcpy(lowpath, pathname);
	strcpy(midpath, pathname);

	for (i = 3; i > 0; i--) {
		snprintf(xpath, sizeof(xpath), "/%02x", (unsigned int)((inode >> (i*8)) & 0xff));
		strcat(pathname, xpath);
		if (i > 2) {
			strcat(lowpath, xpath);
		}
		if (i > 1) {
			strcat(midpath, xpath);
		}
		ret = stat(pathname, &statbuf);
		if (ret < 0) {
			ret = mkdir(pathname, ofs.def_dirmode);
			if (ret < 0) {
				ret = -errno;
				log_msg("   store_set_filename() Error mkdir directory : %s\n",
					strerror(-ret));
				break;
			}
		}
	}
	if (ret == 0) {
		snprintf(store->fullpathobjectfile, sizeof(store->fullpathobjectfile), "%s/%08lx%s", pathname, inode, FILETYPE_OBJECT);
		snprintf(store->fullpathinodefile, sizeof(store->fullpathinodefile), "%s/%08lx%s", pathname, inode, FILETYPE_INODE);
		snprintf(store->fullpath, sizeof(store->fullpath), "%s", pathname);
		snprintf(store->fullmidpath, sizeof(store->fullmidpath), "%s", midpath);
		snprintf(store->fulllowpath, sizeof(store->fulllowpath), "%s", lowpath);
	}

	return ret;
}

static void store_clean_dirs(struct store_filename_s *store)
{
	int ret;

	ret = rmdir(store->fullpath);
	if (ret == 0) {
		ret = rmdir(store->fullmidpath);
		if (ret == 0) {
			ret = rmdir(store->fulllowpath);
		}
	}
}

struct store_filecontent_s {
	int		allocated;
	size_t	size;
	void *	buf;
};

static void store_free_filecontent(struct store_filecontent_s *content)
{
	if ((content->allocated) && (content->buf != NULL)) {
		free(content->buf);
	}
	content->allocated = 0;
	content->buf = NULL;
}

static int store_put_filecontent(const char *filename, struct store_filecontent_s *content)
{
	int ret;
	int fd;

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, ofs.def_filemode);
	if (fd < 0) {
		log_msg("   store_put_filecontent() Error opening file %s : %s\n",
			filename, strerror(errno));
		ret = -errno;
	} else {
		ret = write(fd, content->buf, content->size);
		if (ret < 0) {
			log_msg("   store_put_filecontent() Error writing file %s : %s\n",
				filename, strerror(errno));
			ret = -errno;
		} else if (ret != content->size) {
			log_msg("   store_put_filecontent() Error writing all bytes to file %s\n",
				filename);
			ret = -EIO;
		}
		close(fd);
	}
	log_msg("  store_put_filecontent() ret=%d\n", ret);

	return ret;
}

static int store_get_filecontent(const char *filename, struct store_filecontent_s *content)
{
	int ret;
	int fd;
	struct stat statbuf;
	void *buf;

	content->allocated = 0;
	content->size = 0;
	content->buf = NULL;

	ret = stat(filename, &statbuf);
	if (ret < 0) {
		return -errno;
	}
	if (statbuf.st_size == 0) {
		return 0;
	}

	buf = malloc(statbuf.st_size);
	if (buf == NULL) {
		return -ENOMEM;
	}
	memset(buf, 0, statbuf.st_size);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		log_msg("   store_get_filecontent() Error opening file %s : %s\n",
			filename, strerror(errno));
		ret = -errno;
	} else {
		ret = read(fd, buf, statbuf.st_size);
		if (ret < 0) {
			log_msg("   store_get_filecontent() Error reading file %s : %s\n",
				filename, strerror(errno));
			ret = -errno;
		} else if (ret != statbuf.st_size) {
			log_msg("   store_get_filecontent() Error reading all bytes from file %s : %s\n",
				filename, strerror(errno));
			ret = -EIO;
		} else {
			content->allocated = 1;
			content->size = ret;
			content->buf = buf;
			ret = 0;
		}
		close(fd);
	}
	if (ret < 0) {
		free(buf);
	}
	return ret;
}


/* cache operations */

#define CACHE_ENTRY_STATE_UNUSED 0
#define CACHE_ENTRY_STATE_READ 1
#define CACHE_ENTRY_STATE_WRITE 2
#define CACHE_ENTRY_MAX 1024
struct cache_entry_s {
	uint64_t inode;
	int length;
	struct dir_entry_s *e;
	int state;
	uint64_t lastuse;
};
static struct cache_entry_s entry_cache[CACHE_ENTRY_MAX];

static void directory_flush_entry_cache(int invalidate)
{
	int c;
	int ret;
	int count = 0;
	uint64_t ti = get_milliseconds();

	for (c = 0; c < CACHE_ENTRY_MAX; c++) {
		if (entry_cache[c].state == CACHE_ENTRY_STATE_WRITE) {
			ret = directory_do_write_entrylist(entry_cache[c].e, entry_cache[c].length, entry_cache[c].inode);
			entry_cache[c].state = CACHE_ENTRY_STATE_READ;
			entry_cache[c].lastuse = ti;
			if (ret < 0) {
				log_msg("   directory_flush_entry_cache() error writing entrylist\n");
			}
		}
		if (invalidate) {
			if (entry_cache[c].state != CACHE_ENTRY_STATE_UNUSED) {
				free(entry_cache[c].e);
				entry_cache[c].state = CACHE_ENTRY_STATE_UNUSED;
				entry_cache[c].e = NULL;
				entry_cache[c].length = 0;
				entry_cache[c].inode = 0;
				count++;
			}
		}
	}
	log_msg(" directory_flush_entry_cache(invalidate=%d) flushed, invalidated=%d\n", invalidate, count);
}

static void directory_set_entry_cache(uint64_t inode, struct dir_entry_s *e, int length)
{
	int c;
	uint64_t ti = get_milliseconds();
	uint64_t oldti = ti;
	int oldest = 0;
	int ret;

	for (c = 0; c < CACHE_ENTRY_MAX; c++) {
		if (entry_cache[c].state == CACHE_ENTRY_STATE_UNUSED) {
			oldest = c;
			break;
		}
		if (entry_cache[c].lastuse < oldti) {
			oldti = entry_cache[c].lastuse;
			oldest = c;
		}
	}

	if (entry_cache[oldest].state != CACHE_ENTRY_STATE_UNUSED) {
		if (entry_cache[oldest].state == CACHE_ENTRY_STATE_WRITE) {
			ret = directory_do_write_entrylist(entry_cache[oldest].e, entry_cache[oldest].length, entry_cache[oldest].inode);
			if (ret < 0) {
				log_msg("   directory_set_entry_cache() error writing entrylist\n");
			}
		}
		free(entry_cache[oldest].e);
	}

	entry_cache[oldest].e = e;
	entry_cache[oldest].length = length;
	entry_cache[oldest].inode = inode;
	entry_cache[oldest].lastuse = ti;
	entry_cache[oldest].state = CACHE_ENTRY_STATE_WRITE;
}

static void directory_mark_entry_cache(uint64_t inode, struct dir_entry_s *e, int length)
{
	int c;
	uint64_t ti = get_milliseconds();

	for (c = 0; c < CACHE_ENTRY_MAX; c++) {
		if (entry_cache[c].state != CACHE_ENTRY_STATE_UNUSED) {
			if (entry_cache[c].inode == inode) {
				entry_cache[c].state = CACHE_ENTRY_STATE_WRITE;
				entry_cache[c].lastuse = ti;
				entry_cache[c].length = length;
				entry_cache[c].e = e;
				return;
			}
		}
	}
	directory_set_entry_cache(inode, e, length);
}

static struct dir_entry_s * directory_get_entry_cache(uint64_t inode, int *length)
{
	int c;
	struct dir_entry_s *e = NULL;
	uint64_t ti = get_milliseconds();

	log_msg(" directory_get_entry_cache(inode=%lu)\n", inode);

	for (c = 0; c < CACHE_ENTRY_MAX; c++) {
		if (entry_cache[c].state != CACHE_ENTRY_STATE_UNUSED) {
			if (entry_cache[c].inode == inode) {
				e = entry_cache[c].e;
				*length = entry_cache[c].length;
				entry_cache[c].lastuse = ti;
				break;
			}
		}
	}
	log_msg("  directory_get_entry_cache(inode=%lu) e=%p\n", inode, e);

	return e;
}

#define CACHE_INODE_STATE_UNUSED 0
#define CACHE_INODE_STATE_READ 1
#define CACHE_INODE_STATE_WRITE 2
#define CACHE_INODE_MAX 1024
struct cache_inode_s {
	struct dir_inode_s *i;
	int state;
	uint64_t lastuse;
	int fhopen;
};
static struct cache_inode_s inode_cache[CACHE_INODE_MAX];

static void directory_flush_inode_cache(int invalidate)
{
	int c;
	int ret;
	int count = 0;
	uint64_t ti = get_milliseconds();

	for (c = 0; c < CACHE_INODE_MAX; c++) {
		if ((inode_cache[c].state == CACHE_INODE_STATE_WRITE) && 
				((inode_cache[c].fhopen == 0) || (invalidate))) {
			ret = directory_do_write_inode(READ(inode_cache[c].i->inode), inode_cache[c].i);
			inode_cache[c].state = CACHE_INODE_STATE_READ;
			inode_cache[c].lastuse = ti;
			if (ret < 0) {
				log_msg("   directory_flush_inode_cache() error writing inode\n");
			}
		}
		if (invalidate) {
			if (inode_cache[c].state != CACHE_INODE_STATE_UNUSED) {
				free(inode_cache[c].i);
				inode_cache[c].state = CACHE_INODE_STATE_UNUSED;
				inode_cache[c].i = NULL;
				count++;
			}
		}
	}
	log_msg(" directory_flush_inode_cache(invalidate=%d) flushed, invalidated=%d\n", invalidate, count);
}

static void directory_unset_inode_cache(uint64_t inode)
{
	int c;

	for (c = 0; c < CACHE_INODE_MAX; c++) {
		if (inode_cache[c].state != CACHE_INODE_STATE_UNUSED) {
			if (READ(inode_cache[c].i->inode) == inode) {
				inode_cache[c].state = CACHE_INODE_STATE_UNUSED;
				free(inode_cache[c].i);
				inode_cache[c].i = NULL;
				return;
			}
		}
	}
}

static void directory_inode_cache_fhopen(uint64_t inode)
{
	int c;

	for (c = 0; c < CACHE_INODE_MAX; c++) {
		if (inode_cache[c].state != CACHE_INODE_STATE_UNUSED) {
			if (READ(inode_cache[c].i->inode) == inode) {
				inode_cache[c].fhopen++;
				break;
			}
		}
	}
}

static void directory_inode_cache_fhclose(uint64_t inode)
{
	int c;
	int ret;

	for (c = 0; c < CACHE_INODE_MAX; c++) {
		if (inode_cache[c].state != CACHE_INODE_STATE_UNUSED) {
			if (READ(inode_cache[c].i->inode) == inode) {
				if (inode_cache[c].fhopen > 0) {
					inode_cache[c].fhopen--;
				}
				if (inode_cache[c].fhopen == 0) {
					if (inode_cache[c].state == CACHE_INODE_STATE_WRITE) {
						ret = directory_do_write_inode(READ(inode_cache[c].i->inode), inode_cache[c].i);
						if (ret < 0) {
							log_msg("   directory_inode_cache_fhclose() error writing inode\n");
						}
						inode_cache[c].state = CACHE_INODE_STATE_READ;
					}
				}
				break;
			}
		}
	}
}

static void directory_set_inode_cache(struct dir_inode_s *i, int write)
{
	int c;
	uint64_t ti = get_milliseconds();
	uint64_t oldti = ti;
	int oldest = 0;
	int ret;

	for (c = 0; c < CACHE_INODE_MAX; c++) {
		if (inode_cache[c].state == CACHE_INODE_STATE_UNUSED) {
			oldest = c;
			break;
		}
		if (inode_cache[c].lastuse < oldti) {
			oldti = inode_cache[c].lastuse;
			oldest = c;
		}
	}

	if (inode_cache[oldest].state != CACHE_INODE_STATE_UNUSED) {
		if (inode_cache[oldest].state == CACHE_INODE_STATE_WRITE) {
			ret = directory_do_write_inode(READ(inode_cache[oldest].i->inode), inode_cache[oldest].i);
			if (ret < 0) {
				log_msg("   directory_set_inode_cache() error writing inode\n");
			}
		}
		free(inode_cache[oldest].i);
	}

	inode_cache[oldest].i = i;
	inode_cache[oldest].lastuse = ti;
	inode_cache[oldest].fhopen = 0;
	if (write) {
		inode_cache[oldest].state = CACHE_INODE_STATE_WRITE;
	} else {
		inode_cache[oldest].state = CACHE_INODE_STATE_READ;
	}
}

static void directory_mark_inode_cache(uint64_t inode, struct dir_inode_s *i)
{
	int c;
	uint64_t ti = get_milliseconds();

	for (c = 0; c < CACHE_INODE_MAX; c++) {
		if (inode_cache[c].state != CACHE_INODE_STATE_UNUSED) {
			if (READ(inode_cache[c].i->inode) == inode) {
				inode_cache[c].state = CACHE_INODE_STATE_WRITE;
				inode_cache[c].lastuse = ti;
				if (inode_cache[c].i != i) {
					free(inode_cache[c].i);
					inode_cache[c].i = i;
				}
				return;
			}
		}
	}
	directory_set_inode_cache(i, 1);
}

static struct dir_inode_s * directory_get_inode_cache(uint64_t inode)
{
	int c;
	struct dir_inode_s *i = NULL;
	uint64_t ti = get_milliseconds();

	log_msg(" directory_get_inode_cache(inode=%lu)\n", inode);

	for (c = 0; c < CACHE_INODE_MAX; c++) {
		if (inode_cache[c].state != CACHE_INODE_STATE_UNUSED) {
			if (READ(inode_cache[c].i->inode) == inode) {
				i = inode_cache[c].i;
				inode_cache[c].lastuse = ti;
				break;
			}
		}
	}
	log_msg("  directory_get_inode_cache(inode=%lu) i=%p\n", inode, i);

	return i;
}

/* base operations */

static void directory_lock(void)
{
	pthread_mutex_lock(&directory_mutex);
}

static void directory_unlock(void)
{
	directory_flush_entry_cache(0);
	directory_flush_inode_cache(0);
	pthread_mutex_unlock(&directory_mutex);
}

static int directory_init(void)
{
	int ret = 0;
	struct dir_inode_s *i = NULL;
	struct timespec tim;
	uid_t uid;
	gid_t gid;

	uid = getuid();
	gid = getgid();

	log_msg(" directory_init()\n");

	clock_gettime(CLOCK_REALTIME, &tim);

	ret = directory_read_inode(INODE_ROOT, &i);
	if ((ret < 0) || (READ(i->inode) != INODE_ROOT)) {
		log_msg("  directory_init(): root inode not found, creating...\n");
		ret = directory_add_entry("/",
			S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH,
			uid, gid, 0, 4096, &tim, &tim, &tim, NULL);
	}
	
	directory_flush_entry_cache(0);
	directory_flush_inode_cache(0);

	return ret;
}

/* 
 * inode number management
 */

static uint64_t directory_get_free_inode(void)
{
	int fd;
	uint64_t i;
	uint64_t inode = 0;
	int ret;
	struct stat statbuf;
	struct store_filename_s storename;

	ret = store_set_filename(0, &storename);
	if (ret != 0) {
		return 0;
	}
	ret = stat(storename.fullpathinodefile, &statbuf);
	if ((ret != 0) || (statbuf.st_size < sizeof(i))) {
		// TODO: if file/info lost, scan existing inodes
		return (INODE_ROOT + 1);
	}
	fd = open(storename.fullpathinodefile, O_RDONLY);
	if (fd < 0) {
		log_msg("   directory_get_free_inode() Error opening inode file %s : %s\n",
			storename.fullpathinodefile, strerror(errno));
		return 0;
	}
	if (statbuf.st_size > sizeof(i)) {
		if (lseek(fd, (statbuf.st_size - sizeof(i)), SEEK_SET) <= 0) {
			log_msg("   directory_get_free_inode() Did not lseek inode file %s : %s\n",
				storename.fullpathinodefile, strerror(errno));
			close(fd);
			return 0;
		}
	}
	ret = read(fd, &i, sizeof(i));
	if (ret != sizeof(i)) {
		log_msg("   directory_get_free_inode() Did not read inode length from inode file %s : %s\n",
			storename.fullpathinodefile, strerror(errno));
		close(fd);
		return 0;
	}
	close(fd);

	inode = READ(i);

	// TODO: check if this inode is really available

	log_msg(" directory_get_free_inode() inode=%lu\n", inode);

	return inode;
}

static void directory_alloc_inode(uint64_t inode)
{
	int fd;
	uint64_t i;
	int ret;
	struct stat statbuf;
	struct store_filename_s storename;

	log_msg(" directory_alloc_inode(inode=%lu)\n", inode);

	ret = store_set_filename(0, &storename);
	if (ret != 0) {
		return;
	}
	ret = stat(storename.fullpathinodefile, &statbuf);
	if ((ret != 0) || (statbuf.st_size <= sizeof(i))) {
		fd = open(storename.fullpathinodefile, O_WRONLY | O_CREAT | O_TRUNC, ofs.def_filemode);
		if (fd < 0) {
			log_msg("   directory_alloc_inode() Error opening inode file %s : %s\n",
				storename.fullpathinodefile, strerror(errno));
			return;
		}
		WRITE(i, inode + 1);
		ret = write(fd, &i, sizeof(i));
		if (ret != sizeof(i)) {
			log_msg("   directory_alloc_inode() Error writing inode file %s : %s\n",
				storename.fullpathinodefile, strerror(errno));
		}
		close(fd);
		return;
	}

	ret = truncate(storename.fullpathinodefile, statbuf.st_size - sizeof(i));
	if (ret != 0) {
		log_msg("   directory_alloc_inode() Error truncate inode file %s : %s\n",
			storename.fullpathinodefile, strerror(errno));
	}
}

static void directory_put_free_inode(uint64_t inode)
{
	int fd;
	int ret = 0;
	uint64_t i;
	struct store_filename_s storename;

	log_msg(" directory_put_free_inode(inode=%lu)\n", inode);

	ret = store_set_filename(0, &storename);
	if (ret != 0) {
		return;
	}

	fd = open(storename.fullpathinodefile, O_WRONLY | O_CREAT | O_APPEND, ofs.def_filemode);
	if (fd < 0) {
		log_msg("   directory_put_free_inode() Error opening inode file %s : %s\n",
			storename.fullpathinodefile, strerror(errno));
		ret = -errno;
	} else {
		WRITE(i, inode);
		ret = write(fd, &i, sizeof(i));
		close(fd);
	}

	log_msg(" directory_put_free_inode() ret=%d\n", ret);
}

/*
 * inode operations
 */

static int directory_read_inode(uint64_t inode, struct dir_inode_s **ip)
{
	int ret = 0;
	int l;
	struct dir_inode_s *i;
	struct store_filename_s storename;
	struct store_filecontent_s content;

	log_msg(" directory_read_inode(inode=%lu)\n", inode);

	*ip = NULL;

	if (inode < INODE_ROOT) {
		return -EINVAL;
	}

	i = directory_get_inode_cache(inode);
	if (i != NULL) {
		*ip = i;
		return 0;
	}

	ret = store_set_filename(inode, &storename);
	if (ret < 0) {
		return ret;
	}

	ret = store_get_filecontent(storename.fullpathinodefile, &content);
	if ((ret < 0) || (content.size == 0)) {
		return -EIO;
	}
	if (content.size < sizeof(*i)) {
		store_free_filecontent(&content);
		return -EIO;
	}

	i = (struct dir_inode_s *)(content.buf);

	l = content.size - sizeof(*i);
	if (READ(i->xattrlength) > l) {
		WRITE(i->xattrlength, l);
	}

	*ip = i;

	directory_set_inode_cache(i, 0);

	return ret;
}

static int directory_write_inode(uint64_t inode, struct dir_inode_s *i)
{
	directory_mark_inode_cache(inode, i);
	return 0;
}

static int directory_do_write_inode(uint64_t inode, struct dir_inode_s *i)
{
	int ret = 0;
	struct store_filename_s storename;
	struct store_filecontent_s content;

	log_msg(" directory_do_write_inode(inode=%lu)\n", inode);

	if (inode < INODE_ROOT) {
		return 0;
	}

	ret = store_set_filename(inode, &storename);
	if (ret != 0) {
		return ret;
	}

	content.buf = i;
	content.size = (sizeof(*i) + READ(i->xattrlength));

	ret = store_put_filecontent(storename.fullpathinodefile, &content);

	return ret;
}

static void directory_inode_set_size(uint64_t inode, size_t size)
{
	struct dir_inode_s *i = NULL;
	uint64_t s;

	log_msg(" directory_inode_set_size(inode=%lu, size=%lu)\n", inode, size);

	if (directory_read_inode(inode, &i) == 0) {
		s = size;
		WRITE(i->size, s);
		directory_write_inode(inode, i);
	}
}

static void directory_inode_increase_nlink(uint64_t inode)
{
	struct dir_inode_s *i = NULL;
	uint64_t nlink;

	log_msg(" directory_inode_increase_nlink(inode=%lu)\n", inode);

	if (directory_read_inode(inode, &i) == 0) {
		nlink = READ(i->nlink);
		nlink++;
		WRITE(i->nlink, nlink);
		directory_write_inode(inode, i);
	}
}

static void directory_inode_decrease_nlink(uint64_t inode)
{
	struct dir_inode_s *i = NULL;
	uint64_t nlink;
	uint64_t mode;
	uint64_t nlink_min = 0;

	log_msg(" directory_inode_decrease_nlink(inode=%lu)\n", inode);

	if (directory_read_inode(inode, &i) == 0) {
		mode = READ(i->mode);
		if (mode & S_IFDIR) {
			nlink_min = 2;
		}
		nlink = READ(i->nlink);
		if (nlink > nlink_min) {
			nlink--;
			WRITE(i->nlink, nlink);
			directory_write_inode(inode, i);
		}
	}
}

static void directory_inode_update_times(uint64_t inode,
	struct timespec *atim, struct timespec *ctim, struct timespec *mtim)
{
	struct dir_inode_s *i = NULL;

	log_msg(" directory_inode_update_times(inode=%lu, '%s%s%s')\n", inode,
		atim?"a":"_", ctim?"c":"_", mtim?"m":"_");

	if (directory_read_inode(inode, &i) == 0) {
		if (atim != NULL) {
			WRITE(i->atimsec, atim->tv_sec);
			WRITE(i->atimnsec, atim->tv_nsec);
		}
		if (ctim != NULL) {
			WRITE(i->ctimsec, ctim->tv_sec);
			WRITE(i->ctimnsec, ctim->tv_nsec);
		}
		if (mtim != NULL) {
			WRITE(i->mtimsec, mtim->tv_sec);
			WRITE(i->mtimnsec, mtim->tv_nsec);
		}
		directory_write_inode(inode, i);
	}
}

static int directory_inode_getattr(struct dir_inode_s *i, struct stat *statbuf)
{
	int ret = -EINVAL;

	if (i != NULL) {
		statbuf->st_ino    = READ(i->inode);
		statbuf->st_mode   = READ(i->mode);
		statbuf->st_uid    = READ(i->uid);
		statbuf->st_gid    = READ(i->gid);
		statbuf->st_rdev   = READ(i->rdev);
		statbuf->st_nlink  = READ(i->nlink);
		statbuf->st_size   = READ(i->size);
		statbuf->st_atim.tv_sec  = READ(i->atimsec);
		statbuf->st_atim.tv_nsec = READ(i->atimnsec);
		statbuf->st_ctim.tv_sec  = READ(i->ctimsec);
		statbuf->st_ctim.tv_nsec = READ(i->ctimnsec);
		statbuf->st_mtim.tv_sec  = READ(i->mtimsec);
		statbuf->st_mtim.tv_nsec = READ(i->mtimnsec);
		if (statbuf->st_mode & S_IFDIR) {
			statbuf->st_blocks = statbuf->st_nlink - 2;
		} else {
			statbuf->st_blocks = (statbuf->st_size / 512) + 2;
		}
		ret = 0;
	}

	return ret;
}

static int directory_unlink_inode(uint64_t inode, uint64_t parent, struct stat *statbuf)
{
	uint64_t mode = statbuf->st_mode;
	uint64_t nlink = statbuf->st_nlink;
	struct timespec ctim;

	clock_gettime(CLOCK_REALTIME, &ctim);

	directory_inode_update_times(parent, NULL, &ctim, &ctim);

	if (mode & S_IFDIR) {
		directory_inode_decrease_nlink(parent);
		nlink = 0;
	} else {
		nlink--;
	}

	if (nlink == 0) {
		directory_unlink_inodefile(inode);
	} else {
		directory_inode_decrease_nlink(inode);
	}

	return 0;
}

static int directory_unlink_inodefile(uint64_t inode)
{
	int ret;
	int ret2;
	struct store_filename_s storename;

	store_set_filename(inode, &storename);
	ret = unlink(storename.fullpathinodefile);
	ret2 = unlink(storename.fullpathobjectfile);

	store_clean_dirs(&storename);

	directory_unset_inode_cache(inode);
	directory_put_free_inode(inode);

	log_msg(" directory_unlink_inodefile(inode=%lu) unlink file '%s' ret=%d ret=%d\n",
		inode, storename.fullpathinodefile, ret, ret2);

	if (ret2 < 0) {
		ret = ret2;
	}

	return ret;
}

static int directory_chattr_uidgid(uint64_t inode, uid_t uid, gid_t gid)
{
	struct dir_inode_s *i = NULL;

	if (directory_read_inode(inode, &i) == 0) {
		if (uid != -1) {
			WRITE(i->uid, uid);
		}
		if (gid != -1) {
			WRITE(i->gid, gid);
		}
		directory_write_inode(inode, i);
	}
	return 0;
}

static int directory_chattr_mode(uint64_t inode, mode_t mode)
{
	uint64_t m;
	struct dir_inode_s *i = NULL;

	if (directory_read_inode(inode, &i) == 0) {
		m = (READ(i->mode) & S_IFMT) | (mode & 07777);
		WRITE(i->mode, m);
		directory_write_inode(inode, i);
	}
	return 0;
}

static int directory_inode_readlink(uint64_t inode, char *link, size_t size)
{
	int ret = 0;
	size_t s;
	struct store_filename_s storename;
	struct store_filecontent_s content;

	ret = store_set_filename(inode, &storename);
	if (ret < 0) {
		return ret;
	}

	ret = store_get_filecontent(storename.fullpathobjectfile, &content);
	if (ret < 0) {
		return ret;
	}

	s = size - 1;
	if (s > content.size) {
		s = content.size;
	}
	if (s > 0) {
		memcpy(link, content.buf, s);
	}
	link[s] = 0;
	
	store_free_filecontent(&content);

	return ret;
}

static int directory_inode_truncate(uint64_t inode, off_t newsize)
{
	int ret;
	struct store_filename_s storename;

	ret = store_set_filename(inode, &storename);
	if (ret < 0) {
		return ret;
	}

	ret = truncate(storename.fullpathobjectfile, newsize);
	if (ret < 0) {
		ret = -errno;
	}

	return ret;
}

static int directory_inode_symlink(uint64_t inode, const char *path)
{
	int ret = -EIO;
	struct store_filename_s storename;
	struct store_filecontent_s content;

	log_msg(" directory_inode_symlink(inode=%lu) path='%s'\n", inode, path);

	ret = store_set_filename(inode, &storename);
	if (ret != 0) {
		return ret;
	}

	content.size = strlen(path);
	content.buf = (void *)path;

	ret = store_put_filecontent(storename.fullpathobjectfile, &content);
	if (ret > 0) {
		ret = 0;
	}

	return ret;
}

static int directory_rename(uint64_t inode, uint64_t parent, const char *oldname, struct stat *statbuf, const char *newpath)
{
	int ret;
	uint64_t inode2;
	uint64_t parent2;
	char *name;
	struct dir_entry_s e;
	struct timespec ctim;
	char npath[MAXPATHLEN];

	strncpy_safe(npath, newpath, sizeof(npath));
	name = get_path_and_name(npath);
	if ((name == NULL) || (*name == 0)) {
		return -EINVAL;
	}

	log_msg(" directory_rename(inode=%lu parent=%lu npath='%s' name='%s'\n",
		inode, parent, npath, name);

	ret = directory_find_entry(npath, &inode2, &parent2);
	if (ret < 0) {
		return -ENOENT;
	}

	strncpy_safe(e.name, name, sizeof(e.name));
	WRITE(e.inode, inode);

	ret = directory_remove_entryobject(oldname, parent);
	if (ret >= 0) {
		if (S_ISDIR(statbuf->st_mode)) {
			directory_inode_decrease_nlink(parent);
			directory_inode_increase_nlink(inode2);
		}
		ret = directory_add_entryobject(inode2, &e);
		clock_gettime(CLOCK_REALTIME, &ctim);
		directory_inode_update_times(parent, NULL, &ctim, &ctim);
		directory_inode_update_times(inode, NULL, &ctim, NULL);
	}

	return ret;
}

static int directory_hardlink(const char *newpath, uint64_t inode)
{
	struct dir_entry_s e;
	char *name;
	char npath[MAXPATHLEN];
	uint64_t parent;
	uint64_t entry;
	uint64_t parent2;
	struct timespec tim;
	int ret;

	log_msg(" directory_hardlink(newpath='%s', inode=%lu)\n", newpath, inode);

	strncpy_safe(npath, newpath, sizeof(npath));
	name = get_path_and_name(npath);
	if ((name == NULL) || (*name == 0)) {
		return -EINVAL;
	}
	log_msg("  directory_hardlink() npath='%s' name='%s'\n", npath, name);

	ret = directory_find_entry(npath, &parent, &parent2);
	if (ret < 0) {
		return -ENOENT;
	}
	ret = directory_find_entry(newpath, &entry, &parent2);
	if (ret >= 0) {
		return -EEXIST;
	}

	strncpy_safe(e.name, name, sizeof(e.name));
	WRITE(e.inode, inode);
	ret = directory_add_entryobject(parent, &e);

	if (ret >= 0) {
		directory_inode_increase_nlink(inode);

		clock_gettime(CLOCK_REALTIME, &tim);
		directory_inode_update_times(parent, NULL, &tim, &tim);
		directory_inode_update_times(inode, NULL, &tim, NULL);
		ret = 0;
	}

	return ret;
}

#ifdef USE_XATTR
static int directory_inode_read_xattr(uint64_t inode, struct dir_inode_s *i, struct dir_inode_xattr_s **xattr)
{
	int length;
	int curlength;
	int pos = 0;
	int c;
	char *xpos;
	struct dir_inode_xattr_s *xcur;
	struct dir_inode_xattr_s **xa = xattr;

	xpos = (char *)i;
	xpos += sizeof(*i);

	length = READ(i->xattrlength);

	for (c = 0; c < XATTR_MAX_ENTRIES; c++) {
		*xa = NULL;
		xa++;
	}

	c = 0;
	while ((pos < length) && (c < XATTR_MAX_ENTRIES)) {
		xcur = (struct dir_inode_xattr_s *)xpos;
		curlength = sizeof(*xcur) + READ(xcur->valuesize);
		if ((curlength + pos) > length) {
			break;
		}
		*xattr = xcur;
		xattr++;
		xpos += curlength;
		pos += curlength;
		c++;
	}

	log_msg("  directory_inode_read_xattr(inode=%lu) entries=%d\n", inode, c);

	return 0;
}

static int directory_inode_add_xattr(uint64_t inode, struct dir_inode_s *i, const char *name, const char *value, size_t size)
{
	int newsize;
	int attrsize;
	void *buf;
	void *bufpos;
	struct dir_inode_xattr_s xattr;
	struct dir_inode_s *newi;

	attrsize = READ(i->xattrlength);

	newsize = sizeof(*i);
	newsize += attrsize;
	newsize += sizeof(xattr) + size;

	buf = malloc(newsize);
	if (buf == NULL) {
		return -ENOMEM;
	}

	bufpos = buf;
	memcpy(bufpos, i, sizeof(*i) + attrsize);
	bufpos += sizeof(*i) + attrsize;

	strncpy(xattr.name, name, sizeof(xattr.name));
	WRITE(xattr.valuesize, size);
	memcpy(bufpos, &xattr, sizeof(xattr));
	bufpos += sizeof(xattr);
	memcpy(bufpos, value, size);

	attrsize += sizeof(xattr) + size;

	newi = (struct dir_inode_s *) buf;
	WRITE(newi->xattrlength, attrsize);

	directory_write_inode(inode, newi);

	log_msg("  directory_inode_add_xattr(inode=%lu) new attrsize=%d\n", inode, attrsize);

	return 0;
}

static int directory_inode_delete_xattr(uint64_t inode, struct dir_inode_s *i, struct dir_inode_xattr_s **xattr, struct dir_inode_xattr_s *xdel)
{
	int c;
	int curlength;
	int newlength = 0;
	int valuelen;
	struct dir_inode_xattr_s *xcur;
	char *xpos;
	void *buf;

	curlength = READ(i->xattrlength);
	buf = malloc(curlength);
	if (buf == NULL) {
		return -ENOMEM;
	}

	xpos = (char *)i;
    xpos += sizeof(*i);

	for (c = 0; c < XATTR_MAX_ENTRIES; c++) {
		xcur = *xattr;
		if ((xcur != NULL) && (xcur != xdel)) {
			memcpy(xpos, xcur, sizeof(*xcur));
			xpos += sizeof(*xcur);
			valuelen = READ(xcur->valuesize);
			if (valuelen > 0) {
				memcpy(xpos, ((void *)xcur) + sizeof(*xcur), valuelen);
				xpos += valuelen;
			}
			newlength += sizeof(*xcur) + valuelen;
		}
		xattr++;
	}
	WRITE(i->xattrlength, newlength);

	free(buf);

	log_msg("  directory_inode_delete_xattr(inode=%lu) new attrsize=%d\n", inode, newlength);

	return 0;
}

static int directory_inode_removexattr(uint64_t inode, const char *name)
{
	int ret = -ENODATA;
	int c;
	struct dir_inode_s *i;
	struct dir_inode_xattr_s *xattr[XATTR_MAX_ENTRIES];

	if (directory_read_inode(inode, &i) < 0) {
		return -EIO;
	}
	if (directory_inode_read_xattr(inode, i, &xattr[0]) < 0) {
		return -EIO;
	}
	for (c = 0; c < XATTR_MAX_ENTRIES; c++) {
		if (xattr[c] != NULL) {
			if (strcmp(name, xattr[c]->name) == 0) {
				ret = directory_inode_delete_xattr(inode, i, &xattr[0], xattr[c]);
				break;
			}
		}
	}

	log_msg("  directory_inode_removexattr(inode=%lu) name='%s' ret=%d\n", inode, name, ret);

	return ret;
}

static int directory_inode_listxattr(uint64_t inode, char *list, size_t size)
{
	int c;
	int length = 0;
	char *listpos;
	struct dir_inode_s *i;
	struct dir_inode_xattr_s *xattr[XATTR_MAX_ENTRIES];

	if (directory_read_inode(inode, &i) < 0) {
		return -EIO;
	}
	if (directory_inode_read_xattr(inode, i, &xattr[0]) < 0) {
		return -EIO;
	}

	listpos = list;
	for (c = 0; c < XATTR_MAX_ENTRIES; c++) {
		if (xattr[c] != NULL) {
			length += (strlen(xattr[c]->name) + 1);
			if (length < size) {
				strcpy(listpos, xattr[c]->name);
				listpos += strlen(xattr[c]->name);
				*listpos = 0;
				listpos++;
			} else {
				if (size > 0) {
					length = -ERANGE;
					break;
				}
			}
		}
	}
	log_msg("  directory_inode_listxattr(inode=%lu) len=%d '%s'\n", inode, length,
		(list)?list:"");

	return length;
}

static int directory_inode_getxattr(uint64_t inode, const char *name, char *value, size_t size)
{
	int c;
	int length = -ENODATA;
	int valuelen;
	struct dir_inode_s *i;
	struct dir_inode_xattr_s *xattr[XATTR_MAX_ENTRIES];
	void *x;

	if (directory_read_inode(inode, &i) < 0) {
		return -EIO;
	}
	if (directory_inode_read_xattr(inode, i, &xattr[0]) < 0) {
		return -EIO;
	}

	for (c = 0; c < XATTR_MAX_ENTRIES; c++) {
		if (xattr[c] != NULL) {
			if (strcmp(xattr[c]->name, name) == 0) {
				valuelen = READ(xattr[c]->valuesize);
				if ((size > 0) && (valuelen > size)) {
					length = -ERANGE;
				} else {
					if (size > 0) {
						x = (void *)xattr[c];
						x += sizeof(struct dir_inode_xattr_s);
						memcpy(value, x, valuelen);
					}
					length = valuelen;
				}
				break;
			}
		}
	}

	log_msg("  directory_inode_getxattr(inode=%lu) len=%d\n", inode, length);

	return length;
}

static int directory_inode_setxattr(uint64_t inode, const char *name, const char *value, size_t size, int flags)
{
	int ret = 0;
	int exist = -1;
	int c;
	struct dir_inode_s *i;
	struct dir_inode_xattr_s *xattr[XATTR_MAX_ENTRIES];

	// flags: XATTR_CREATE | XATTR_REPLACE

	if (directory_read_inode(inode, &i) < 0) {
		return -EIO;
	}
	if (directory_inode_read_xattr(inode, i, &xattr[0]) < 0) {
		return -EIO;
	}

	for (c = 0; c < XATTR_MAX_ENTRIES; c++) {
		if (xattr[c] == NULL) {
			break;
		}
		if (strcmp(name, xattr[c]->name) == 0) {
			exist = c;
			break;
		}
	}
	if (exist < 0) {
		if (flags & XATTR_REPLACE) {
			return -ENODATA;
		}
		if (c >= XATTR_MAX_ENTRIES) {
			return -ENOSPC;
		}
	} else {
		if (flags & XATTR_CREATE) {
			return -EEXIST;
		}
	}

	if (exist >= 0) {
		ret = directory_inode_delete_xattr(inode, i, &xattr[0], xattr[exist]);
	}
	if (ret >= 0) {
		ret = directory_inode_add_xattr(inode, i, name, value, size);
	}

	log_msg("  directory_inode_setxattr(inode=%lu) name='%s' ret=%d\n", inode, name, ret);

	return ret;
}
#endif //USE_XATTR

/*
 * directory entrylist
 */

static int directory_read_entrylist(struct dir_entry_s **ep, uint64_t inode)
{
	int length;
	int ret;
	struct dir_entry_s *e;
	struct store_filename_s storename;
	struct store_filecontent_s content;

	e = directory_get_entry_cache(inode, &length);
	if (e != NULL) {
		*ep = e;
		return length;
	}

	ret = store_set_filename(inode, &storename);
	if (ret != 0) {
		return ret;
	}

	ret = store_get_filecontent(storename.fullpathobjectfile, &content);
	if ((ret < 0) || (content.size == 0)) {
		return 0;
	}

	e = (struct dir_entry_s *)(content.buf);
	*ep = e;
	length = (content.size / sizeof(struct dir_entry_s));
	directory_set_entry_cache(inode, e, length);

	log_msg(" directory_read_entrylist(inode=%lu) found %d entries.\n", inode, length);

	return length;
}

static int directory_write_entrylist(struct dir_entry_s *e, int length, uint64_t inode)
{
	directory_mark_entry_cache(inode, e, length);
	return 0;
}

static int directory_do_write_entrylist(struct dir_entry_s *e, int length, uint64_t inode)
{
	int ret;
	struct store_filename_s storename;
	struct store_filecontent_s content;

	ret = store_set_filename(inode, &storename);
	if (ret != 0) {
		return ret;
	}

	if (length == 0) {
		unlink(storename.fullpathobjectfile);
		ret = 0;
	} else {
		content.size = (length * sizeof(*e));
		content.buf = (void *)e;
		ret = store_put_filecontent(storename.fullpathobjectfile, &content);
	}
	log_msg(" directory_do_write_entrylist() ret=%d\n", ret);

	return ret;
}

static uint64_t directory_get_entry_by(const char *name, uint64_t parent)
{
	uint64_t id = 0;
	struct dir_entry_s *e = NULL;
	struct dir_entry_s *ee;
	int length;
	int i;
	
	log_msg(" directory_get_entry_by(name='%s', parent=%lu)\n", name, parent);

	if ((parent == 0) && (*name == 0)) {
		return INODE_ROOT;
	}

	length = directory_read_entrylist(&e, parent);
	if (length > 0) {
		ee = e;
		for(i = 0; i < length; i++) {
			if (strcmp(ee->name, name) == 0) {
				id = READ(ee->inode);
				break;
			}
			ee++;
		}
	}

	return id;
}

static int directory_add_entry(const char *path, uint64_t mode,
	uint64_t uid, uint64_t gid, uint64_t rdev, uint64_t size,
	struct timespec *atim, struct timespec *ctim, struct timespec *mtim,
	struct dir_inode_s *inodep)
{
	struct dir_entry_s e;
	struct dir_inode_s *i;
	uint64_t inode;
	uint64_t parent = 0;
	uint64_t nlink = 1;
	int ret = 0;
	char *name;
	char npath[MAXPATHLEN];

	log_msg(" directory_add_entry(path='%s',mode=%o,uid=%lu,gid=%lu,rdev=0x%x,"
		"size=%lu,atim=%lu,ctim=%lu,mtim=%lu)\n", path, mode, uid, gid, rdev,
		size, atim->tv_sec, ctim->tv_sec, mtim->tv_sec);

	strncpy_safe(npath, path, sizeof(npath));
	name = get_path_and_name(npath);
	if (name == NULL) {
		return -EINVAL;
	}
	log_msg("  directory_add_entry() npath='%s' name='%s'\n", npath, name);

	if (*name == 0) {
		/* special case for root entry */
		log_msg("  directory_add_entry() no name in path, doing root entry.\n");
		inode = INODE_ROOT;
	} else {
		ret = directory_find_entry(npath, &inode, &parent);
		if (ret < 0) {
			return ret;
		}
		parent = inode;
		inode = directory_get_free_inode();
		if (inode <= INODE_ROOT) {
			return -EIO;
		}
	}

	i = malloc(sizeof(*i));
	if (i == NULL) {
		return -ENOMEM;
	}
	memset(i, 0, sizeof(*i));

	memset(&e, 0, sizeof(e));

	strncpy_safe(e.name, name, sizeof(e.name));
	WRITE(e.inode, inode);

	WRITE(i->inode, inode);
	WRITE(i->mode, mode);
	if (mode & S_IFDIR) {
		directory_inode_increase_nlink(parent);
		nlink = 2;
	}
	WRITE(i->nlink, nlink);
	WRITE(i->uid, uid);
	WRITE(i->gid, gid);
	WRITE(i->rdev, rdev);
	WRITE(i->size, size);
	WRITE(i->atimsec, atim->tv_sec);
	WRITE(i->atimnsec, atim->tv_nsec);
	WRITE(i->ctimsec, ctim->tv_sec);
	WRITE(i->ctimnsec, ctim->tv_nsec);
	WRITE(i->mtimsec, mtim->tv_sec);
	WRITE(i->mtimnsec, mtim->tv_nsec);

	if (inodep != NULL) {
		memcpy(inodep, i, sizeof(*i));
	}

	directory_inode_update_times(parent, NULL, ctim, ctim);

	ret = directory_write_inode(inode, i);
	if (ret >= 0) {
		ret = directory_add_entryobject(parent, &e);
	}
	directory_alloc_inode(inode);

	log_msg("  directory_add_entry() parent=%lu inode=%lu name='%s' ret=%d\n",
		parent, inode, name, ret);

	return ret;
}

static int directory_find_entry(const char *path, uint64_t *inode, uint64_t *parent)
{
	int ret = 0;
	uint64_t id = 1;
	const char *p = path;
	char *n;
	char name[MAXNAMELEN];
	uint64_t lparent = 0;
	uint64_t pid = 0;

	log_msg(" directory_find_entry(path=%s)\n", path);

	while (p) {
		n = name;
		*n = 0;
		while (*p) {
			if (*p == '/') {
				p++;
				break;
			}
			*n = *p;
			p++;
			n++;
			*n = 0;
		}
		id = directory_get_entry_by(name, lparent);
		log_msg("  directory_find_entry() id=%lu\n", id);
		if (id == 0) {
			ret = -ENOENT;
			break;
		}
		pid = lparent;
		lparent = id;
		if (*p == 0) {
			break;
		}
	}
	log_msg("  directory_find_entry() final inode=%lu parent=%lu ret=%d\n", id, pid, ret);

	*inode = id;
	*parent = pid;

	return ret;
}

static int directory_remove_entryobject(const char *name, uint32_t parent)
{
	int ret = 0;
	int length;
	int i;
	void *elist;
	struct dir_entry_s *e;
	struct dir_entry_s *epos = NULL;
	struct dir_entry_s *lastpos = NULL;

	if (parent < INODE_ROOT) {
		return -EIO;
	}

	log_msg(" directory_remove_entryobject(name='%s', parent=%lu)\n", name, parent);

	length = directory_read_entrylist((struct dir_entry_s **)&elist, parent);
	if (length <= 0) {
		return 0;
	}

	e = (struct dir_entry_s *)elist;
	for (i = 0; i < length; i++) {
		lastpos = e;
		if (strcmp(e->name, name) == 0) {
			epos = e;
		}
		e++;
	}
	if (epos) {
		if (epos != lastpos) {
			memcpy(epos, lastpos, sizeof(*epos));
		}
		length--;
		ret = directory_write_entrylist(elist, length, parent);
	}

	if (ret > 0) ret = 0;

	return ret;
}

static int directory_add_entryobject(uint64_t inode, struct dir_entry_s *e)
{
	int ret = 0;
	int length;
	void *elist;
	void *newelist;

	if (inode < INODE_ROOT) {
		return 0;
	}

	log_msg(" directory_add_entryobject(inode=%lu name='%s')\n", inode, e->name);

	length = directory_read_entrylist((struct dir_entry_s **)&elist, inode);
	if (length < 0) {
		return length;
	}

	newelist = malloc((length + 1) * sizeof(struct dir_entry_s));
	if (newelist != NULL) {
		if (length > 0) {
			memcpy(newelist, elist, (length * sizeof(struct dir_entry_s)));
			free(elist);
		}
		memcpy(newelist + (length * sizeof(struct dir_entry_s)), e, sizeof(struct dir_entry_s));
		length++;
		ret = directory_write_entrylist(newelist, length, inode);
	} else {
		ret = -ENOMEM;
	}

	if (ret > 0) ret = 0;

	return ret;
}

/*
 *****************************************************************************
 * filehandle functions
 *****************************************************************************
 */

struct fs_file_handle_s {
	uint64_t	inode;
	uint64_t	parent;
	char	name[MAXNAMELEN];
	int		fd;
	int		fduse;
	struct stat statbuf;
	struct store_filename_s storename;
};
#define FILHANDLE_CHATTRTYPE_MODE 0
#define FILHANDLE_CHATTRTYPE_USER 1

/* */

static struct fs_file_handle_s *filehandle_open(const char *path)
{
	struct fs_file_handle_s *fh = NULL;
	uint64_t inode;
	uint64_t parent;
	int ret;
	struct dir_inode_s *i = NULL;
	char *name;
	char npath[MAXPATHLEN];

	log_msg(" filehandle_open(path='%s')\n", path);

	strncpy_safe(npath, path, sizeof(npath));
	name = get_path_and_name(npath);

	ret = directory_find_entry(path, &inode, &parent);
	if (ret < 0) {
		return NULL;
	}

	fh = malloc(sizeof(*fh));
	if (fh != NULL) {
		memset(fh, 0, sizeof(*fh));
		fh->fd = -1;
		fh->inode = inode;
		fh->parent = parent;
		strncpy_safe(fh->name, name, sizeof(fh->name));
		ret = directory_read_inode(inode, &i);
		if (ret == 0) {
			ret = directory_inode_getattr(i, &fh->statbuf);
		}
		if (ret < 0) {
			free(fh);
			fh = NULL;
		}
	}

	if (fh) {
		directory_inode_cache_fhopen(inode);

		log_msg("  filehandle_open() set inode=%lu\n", fh->inode);
	}

	return fh;
}

static void filehandle_release(struct fs_file_handle_s *fh)
{
	log_msg(" filehandle_release()\n");

	if (fh != NULL) {
		directory_inode_cache_fhclose(fh->inode);
		free(fh);
	}
}

static int filehandle_is_valid(struct fs_file_handle_s *fh)
{
	if (fh == NULL)
		return 0;

	return 1;
}

static int filehandle_set_names(struct fs_file_handle_s *fh)
{
	int ret;

	if (!(filehandle_is_valid(fh))) {
		return -EBADF;
	}

	ret = store_set_filename(fh->inode, &fh->storename);

	return ret;
}

static void filehandle_update_times(struct fs_file_handle_s *fh,
	struct timespec *atim, struct timespec *ctim, struct timespec *mtim)
{
	if (!(filehandle_is_valid(fh))) {
		log_msg("   filehandle_update_times() filehandle invalid\n");
		return;
	}
	log_msg(" filehandle_update_times() inode=%lu\n", fh->inode);

	directory_inode_update_times(fh->inode, atim, ctim, mtim);
}

static int filehandle_chattr(struct fs_file_handle_s *fh,
	int type, mode_t mode, uid_t uid, gid_t gid)
{
	struct timespec ctim;

	if (!(filehandle_is_valid(fh))) {
		log_msg("   filehandle_chattr() filehandle invalid\n");
		return -EBADF;
	}
	log_msg(" filehandle_chattr(inode=%lu, type=%d, mode=0%o, uid=%d, gid=%d)\n",
		fh->inode, type, mode, uid, gid);

	if (type == FILHANDLE_CHATTRTYPE_MODE) {
		/* mode */
		directory_chattr_mode(fh->inode, mode);
	}
	if (type == FILHANDLE_CHATTRTYPE_USER) {
		/* uid gid */
		directory_chattr_uidgid(fh->inode, uid, gid);
	}
	clock_gettime(CLOCK_REALTIME, &ctim);
	filehandle_update_times(fh, NULL, &ctim, NULL);

	return 0;
}

static int filehandle_release_and_remove(struct fs_file_handle_s *fh)
{
	int ret;
	int ret2;

	ret = directory_remove_entryobject(fh->name, fh->parent);
	ret2 = directory_unlink_inode(fh->inode, fh->parent, &fh->statbuf);

	filehandle_release(fh);

	if (ret2 < 0) {
		ret = ret2;
	}

	return ret;
}

static int filehandle_update_filesize(struct fs_file_handle_s *fh)
{
	int ret;
	struct stat statbuf;

	if ((fh->fduse) && (fh->fd >= 0)) {
		ret = fstat(fh->fd, &statbuf);
	} else {
		ret = stat(fh->storename.fullpathobjectfile, &statbuf);
	}
	if (ret != 0) {
		return -errno;
	}

	directory_inode_set_size(fh->inode, statbuf.st_size);

	return 0;
}

/*
 *****************************************************************************
 * FUSE functions
 *****************************************************************************
 */

/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 */
static void *fs_init(struct fuse_conn_info *conn)
{
	log_msg("fs_init\n");

	return NULL;
}

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 */
static void fs_destroy(void *userdata)
{
	log_msg("fs_destroy\n");

	directory_flush_entry_cache(1);
	directory_flush_inode_cache(1);
}

/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored.  The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 */
static int fs_getattr(const char *path, struct stat *statbuf)
{
	uint64_t inode;
	uint64_t parent;
	int ret = -ENOENT;
	struct dir_inode_s *i = NULL;

	log_msg("fs_getattr(path='%s')\n", path);

	directory_lock();

	ret = directory_find_entry(path, &inode, &parent);

	if (ret >= 0) {
		ret = directory_read_inode(inode, &i);
		if (ret == 0) {
			ret = directory_inode_getattr(i, statbuf);
		}
	}

	directory_unlock();

	log_msg(" fs_getattr(path='%s') ret=%d\n", path, ret);

	return ret;
}

/**
 * Get attributes from an open file
 *
 * This method is called instead of the getattr() method if the
 * file information is available.
 *
 * Currently this is only called after the create() method if that
 * is implemented (see above).  Later it may be called for
 * invocations of fstat() too.
 */
static int fs_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi)
{
	int ret = 0;
	struct fs_file_handle_s *fh = (struct fs_file_handle_s *)fi->fh;
	struct dir_inode_s *i = NULL;

	directory_lock();

	if (!(filehandle_is_valid(fh))) {
		directory_unlock();
		log_msg("fs_fgetattr(path='%s') invalid filehandle!\n");
		return -EBADF;
	}

	log_msg("fs_fgetattr(path='%s') inode=%lu\n", path, fh->inode);

	ret = directory_read_inode(fh->inode, &i);
	if (ret == 0) {
		ret = directory_inode_getattr(i, statbuf);
	}

	directory_unlock();

	log_msg(" fs_fgetattr(path='%s') inode=%lu ret=%d\n", path, fh->inode, ret);

	return ret;
}

/** Open directory
 *
 * Unless the 'default_permissions' mount option is given,
 * this method should check if opendir is permitted for this
 * directory. Optionally opendir may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to readdir, closedir and fsyncdir.
 */
static int fs_opendir(const char *path, struct fuse_file_info *fi)
{
	int ret = -ENOENT;
	struct fs_file_handle_s *fh;
	struct timespec atim;

	log_msg("fs_opendir(path='%s', flags=0x%x)\n", path, fi->flags);

	directory_lock();

	fh = filehandle_open(path);

	if (fh != NULL) {
		if (!S_ISDIR(fh->statbuf.st_mode)) {
			filehandle_release(fh);
			ret = -ENOTDIR;
		} else {
			fi->fh = (intptr_t) fh;
			if ((!(fi->flags & O_NOATIME)) && (!ofs.noatime)) {
				clock_gettime(CLOCK_REALTIME, &atim);
				filehandle_update_times(fh, &atim, NULL, NULL);
			}
			ret = 0;
		}
	}

	directory_unlock();

	return ret;
}

/** Read directory
 *
 * This supersedes the old getdir() interface.  New applications
 * should use this.
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 */
static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
                      struct fuse_file_info *fi)
{
	int ret = 0;
	int length;
	int i;
	struct fs_file_handle_s *fh = (struct fs_file_handle_s *)fi->fh;
	struct dir_entry_s *e;
	struct dir_entry_s *ee;

	directory_lock();

	if (!(filehandle_is_valid(fh))) {
		directory_unlock();
		log_msg("fs_readdir(path='%s') invalid filehandle!\n");
		return -EBADF;
	}

	log_msg("fs_readdir(path='%s') inode=%d\n", path, fh->inode);

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	length = directory_read_entrylist(&e, fh->inode);
	if (length > 0) {
		ee = e;
		for(i = 0; i < length; i++) {
			if (filler(buf, ee->name, NULL, 0) != 0) {
				log_msg("  ERROR fs_readdir() filler:  buffer full\n");
				ret = -ENOMEM;
				break;
			}
			ee++;
		}
	}

	directory_unlock();

	return ret;
}

/** Release directory */
static int fs_releasedir(const char *path, struct fuse_file_info *fi)
{
	int ret = 0;
	struct fs_file_handle_s *fh = (struct fs_file_handle_s *)fi->fh;
	uint64_t inode = 0;

	directory_lock();

	if (!(filehandle_is_valid(fh))) {
		log_msg("fs_releasedir(path='%s') invalid filehandle!\n");
		ret = -EBADF;
	} else {
		inode = fh->inode;
	}

	log_msg("fs_releasedir(path='%s') inode=%d\n", path, inode);

	filehandle_release(fh);

	directory_unlock();

	return ret;
}

/** Synchronize directory contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data
 */
static int fs_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
	int ret = 0;

	log_msg("fs_fsyncdir(path='%s' datasync=%d)\n", path, datasync);

#if 0
	directory_lock();

	// TODO sync db to storedir?

	directory_unlock();
#endif

	return ret;
}

/** Remove a directory */
static int fs_rmdir(const char *path)
{
	int ret = 0;
	struct fs_file_handle_s *fh;

	log_msg("fs_rmdir(path='%s')\n", path);

	directory_lock();

	fh = filehandle_open(path);

	if (fh == NULL) {
		ret = -ENOENT;
	} else {
		if (!S_ISDIR(fh->statbuf.st_mode)) {
			ret = -ENOTDIR;
		} else {
			int length;
			struct dir_entry_s *e;
			length = directory_read_entrylist(&e, fh->inode);
			if (length > 0) {
				ret = -ENOTEMPTY;
			}
		}
	}
	if (ret >= 0) {
		ret = filehandle_release_and_remove(fh);
	} else {
		filehandle_release(fh);
	}

	directory_unlock();

	return ret;
}

/** Create a directory 
 *
 * Note that the mode argument may not have the type specification
 * bits set, i.e. S_ISDIR(mode) can be false.  To obtain the
 * correct directory type bits use  mode|S_IFDIR
 */
static int fs_mkdir(const char *path, mode_t mode)
{
	int ret = 0;
	struct fs_file_handle_s *fh;
	struct timespec atim;
	struct fuse_context *context = fuse_get_context();

	log_msg("fs_mkdir(path='%s', mode=0%3o)\n", path, mode);

	directory_lock();

	fh = filehandle_open(path);
	if (fh) {
		filehandle_release(fh);
		ret = -EEXIST;
	} else {
		clock_gettime(CLOCK_REALTIME, &atim);
		ret = directory_add_entry(path, mode | S_IFDIR, context->uid, context->gid,
			0, 4096, &atim, &atim, &atim, NULL);
	}

	directory_unlock();

	return ret;
}

/** Create a file node
 *
 * This is called for creation of all non-directory, non-symlink
 * nodes.  If the filesystem defines a create() method, then for
 * regular files that will be called instead.
 */
static int fs_mknod(const char *path, mode_t mode, dev_t dev)
{
	int ret = 0;
	struct fs_file_handle_s *fh;
	struct timespec atim;
	struct fuse_context *context = fuse_get_context();

	log_msg("fs_mknod(path='%s', mode=0%3o, dev=%lld)\n", path, mode, dev);

	directory_lock();

	fh = filehandle_open(path);
	if (fh) {
		filehandle_release(fh);
		ret = -EEXIST;
	} else {
		clock_gettime(CLOCK_REALTIME, &atim);
		ret = directory_add_entry(path, mode, context->uid, context->gid,
			dev, 0, &atim, &atim, &atim, NULL);
	}

	directory_unlock();

	return ret;
}

/** Remove a file */
static int fs_unlink(const char *path)
{
	int ret = 0;
	struct fs_file_handle_s *fh;

	log_msg("fs_unlink(path='%s')\n", path);

	directory_lock();

	fh = filehandle_open(path);

	if (fh == NULL) {
		ret = -ENOENT;
	} else {
		if (S_ISDIR(fh->statbuf.st_mode)) {
			ret = -EISDIR;
		} else {
			ret = filehandle_release_and_remove(fh);
		}
	}

	directory_unlock();

	return ret;
}

/**
 * Change the access and modification times of a file with
 * nanosecond resolution
 *
 * This supersedes the old utime() interface.  New applications
 * should use this.
 *
 * See the utimensat(2) man page for details.
 */
static int fs_utimens(const char *path, const struct timespec tv[2])
{
	int ret = 0;
	struct fs_file_handle_s *fh;
	struct timespec *atim = NULL;
	struct timespec *mtim = NULL;
	struct timespec ctim;

	log_msg("fs_utimens(path='%s')\n", path);

	directory_lock();

	fh = filehandle_open(path);
	if (fh == NULL) {
		ret = -ENOENT;
	} else {
		clock_gettime(CLOCK_REALTIME, &ctim);
		if ((tv == NULL) || (tv[0].tv_nsec == UTIME_NOW)) {
			atim = &ctim;
		} else if ((tv != NULL) && (tv[0].tv_nsec != UTIME_OMIT)) {
			atim = (struct timespec *)&tv[0];
		}
		if ((tv == NULL) || (tv[1].tv_nsec == UTIME_NOW)) {
			mtim = &ctim;
		} else if ((tv != NULL) && (tv[1].tv_nsec != UTIME_OMIT)) {
			mtim = (struct timespec *)&tv[1];
		}
		filehandle_update_times(fh, atim, NULL, mtim);
		filehandle_release(fh);
	}

	directory_unlock();

	return ret;
}

/** Change the permission bits of a file */
static int fs_chmod(const char *path, mode_t mode)
{
	int ret = 0;
	struct fs_file_handle_s *fh;

	log_msg("fs_chmod(fpath='%s', mode=0%03o)\n", path, mode);

	directory_lock();

	fh = filehandle_open(path);
	if (fh == NULL) {
		ret = -ENOENT;
	} else {
		ret = filehandle_chattr(fh, FILHANDLE_CHATTRTYPE_MODE, mode, 0, 0);
		filehandle_release(fh);
	}

	directory_unlock();

	return ret;
}

/** Change the owner and group of a file */
static int fs_chown(const char *path, uid_t uid, gid_t gid)
{
	int ret = 0;
	struct fs_file_handle_s *fh;

	log_msg("fs_chown(path='%s', uid=%d, gid=%d)\n", path, uid, gid);

	directory_lock();

	fh = filehandle_open(path);
	if (fh == NULL) {
		ret = -ENOENT;
	} else {
		ret = filehandle_chattr(fh, FILHANDLE_CHATTRTYPE_USER, 0, uid, gid);
		filehandle_release(fh);
	}

	directory_unlock();

	return ret;
}

/** Get file system statistics
 *
 * The 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 */
static int fs_statfs(const char *path, struct statvfs *statv)
{
	int ret;
	struct statvfs svfs;
	fsfilcnt_t inodes = 0;
	fsblkcnt_t blocks = 0;
	//struct dir_inode_s *i;

	statv->f_namemax = MAXNAMELEN - 1;
	statv->f_bsize = 4096;

	ret = statvfs(ofs.path, &svfs);
	if (ret == 0) {
		statv->f_blocks = svfs.f_blocks;
		statv->f_files = svfs.f_files;
		statv->f_ffree = svfs.f_ffree;
		statv->f_bfree = svfs.f_bfree;
		statv->f_bavail = svfs.f_bavail;
	} else {
		statv->f_blocks = 1024ULL * 1024 * 1024 * 1024 * 1024 / statv->f_frsize;
		statv->f_files = 1024ULL * 1024;
		statv->f_ffree = statv->f_files - inodes;
		statv->f_bfree = statv->f_blocks - blocks / statv->f_frsize;
		statv->f_bavail = statv->f_bfree;
	}

#if 0  // TODO
	directory_lock();
	while (READ(d->h.type) != DIRECTORYOBJTYPE_UNUSED) {
		if (READ(d->h.type) == DIRECTORYOBJTYPE_INODE) {
			inodes++;
			i = &(d->s.inode);
			blocks += READ(i->size);
		}
		d++;
	}
	directory_unlock();
#endif

	/* ignored by FUSE
	statv->f_favail = statv->f_ffree;
	statv->f_frsize = statv->f_bsize;
	statv->f_flag = 0;
	statv->f_fsid = 0;
	*/

	log_msg("fs_statfs(path='%s') statvfs-ret=%d\n", path, ret);

	return 0;
}

/** Rename a file */
static int fs_rename(const char *path, const char *newpath)
{
	int ret = 0;
	struct fs_file_handle_s *fh;
	struct fs_file_handle_s *fhnew;
	struct timespec ctim;

	log_msg("fs_rename(fpath='%s', newpath='%s')\n", path, newpath);

	directory_lock();

	fh = filehandle_open(path);
	if (fh == NULL) {
		ret = -ENOENT;
	} else {
		fhnew = filehandle_open(newpath);
		if (fhnew != NULL) {
			if (S_ISDIR(fhnew->statbuf.st_mode)) {
				if (!S_ISDIR(fh->statbuf.st_mode)) {
					ret = -EISDIR;
				} else {
					if (strncmp(path, newpath, strlen(path)) == 0) {
						ret = -EINVAL;
					}
				}
			} else {
				if (S_ISDIR(fh->statbuf.st_mode)) {
					ret = -ENOTDIR;
				} else {
					if (fh->statbuf.st_ino == fhnew->statbuf.st_ino) {
						/* if hardlinks to same file */
						ret = 0x100;
					} else {
						// path and newpath are existing files, unlink newpath first
						ret = directory_remove_entryobject(fhnew->name, fhnew->parent);
						if (ret >= 0) {
							ret = directory_unlink_inode(fhnew->inode, fhnew->parent, &fhnew->statbuf);
							if (ret < 0) {
								struct dir_entry_s e;
								strncpy_safe(e.name, fhnew->name, sizeof(e.name));
								WRITE(e.inode, fhnew->inode);
								directory_add_entryobject(fhnew->parent, &e);
								ret = -EIO;
							}
						}
					}
				}
			}
			filehandle_release(fhnew);
		}
		if (ret == 0) {
			clock_gettime(CLOCK_REALTIME, &ctim);
			filehandle_update_times(fh, NULL, &ctim, NULL);
			ret = directory_rename(fh->inode, fh->parent, fh->name, &fh->statbuf, newpath);
		} else if (ret == 0x100) {
			ret = 0;
		}
		filehandle_release(fh);
	}

	directory_unlock();

	return ret;
}

/** Create a symbolic link */
static int fs_symlink(const char *path, const char *link)
{
	int ret = 0;
	struct fs_file_handle_s *fh;
	struct dir_inode_s i;
	struct timespec atim;
	struct fuse_context *context = fuse_get_context();

	log_msg("fs_symlink(path='%s', link='%s')\n", path, link);

	directory_lock();

	fh = filehandle_open(link);
	if (fh != NULL) {
		ret = -EEXIST;
		filehandle_release(fh);
	} else {
		clock_gettime(CLOCK_REALTIME, &atim);
		ret = directory_add_entry(link, 0777 | S_IFLNK, context->uid, context->gid,
			0, strlen(path), &atim, &atim, &atim, &i);
		if (ret >= 0) {
			ret = directory_inode_symlink(READ(i.inode), path);
		}
	}

	directory_unlock();

	return ret;
}

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character.  If the linkname is too long to fit in the
 * buffer, it should be truncated.  The return value should be 0
 * for success.
 */
static int fs_readlink(const char *path, char *link, size_t size)
{
	int ret = 0;
	struct fs_file_handle_s *fh;

	log_msg("fs_readlink(path='%s')\n", path);

	directory_lock();

	fh = filehandle_open(path);
	if (fh == NULL) {
		ret = -ENOENT;
	} else {
		ret = directory_inode_readlink(fh->inode, link, size);
		filehandle_release(fh);
	}

	directory_unlock();

	return ret;
}

/** Create a hard link to a file */
static int fs_link(const char *path, const char *newpath)
{
	int ret = 0;
	struct fs_file_handle_s *fh;

	log_msg("fs_link(path='%s', newpath='%s')\n", path, newpath);

	directory_lock();

	fh = filehandle_open(path);
	if (fh == NULL) {
		ret = -ENOENT;
	} else {
		if (S_ISDIR(fh->statbuf.st_mode)) {
			ret = -EISDIR;
		} else {
			ret = directory_hardlink(newpath, fh->inode);
		}
		filehandle_release(fh);
	}

	directory_unlock();

	return ret;
}

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor.  So if a
 * filesystem wants to return write errors in close() and the file
 * has cached dirty data, this is a good place to write back data
 * and return any errors.  Since many applications ignore close()
 * errors this is not always useful.
 *
 * NOTE: The flush() method may be called more than once for each
 * open().  This happens if more than one file descriptor refers
 * to an opened file due to dup(), dup2() or fork() calls.  It is
 * not possible to determine if a flush is final, so each flush
 * should be treated equally.  Multiple write-flush sequences are
 * relatively rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will always be called
 * after some writes, or that if will be called at all.
 */
static int fs_flush(const char *path, struct fuse_file_info *fi)
{
	log_msg("fs_flush(path='%s')\n", path);

	directory_lock();
	directory_unlock(); // will do cache flush

	return 0;
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 */
static int fs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
	int ret = 0;
	struct fs_file_handle_s *fh = (struct fs_file_handle_s *)fi->fh;

	if (!(filehandle_is_valid(fh))) {
		return -EIO;
	}

	log_msg("fs_fsync(path='%s' datasync=%d) fd=%d\n", path, datasync, fh->fd);

    if (datasync) {
		ret = fdatasync(fh->fd);
	} else {
		ret = fsync(fh->fd);
	}
	if (ret < 0) {
		ret = -errno;
	}

	return ret;
}

/** Change the size of a file */
static int fs_truncate(const char *path, off_t newsize)
{
	int ret = 0;
	struct fs_file_handle_s *fh;
	struct timespec ctim;

	log_msg("fs_truncate(path='%s', newsize=%lld)\n", path, newsize);

	directory_lock();

	fh = filehandle_open(path);
	if (fh == NULL) {
		ret = -ENOENT;
	} else {
		ret = directory_inode_truncate(fh->inode, newsize);
		clock_gettime(CLOCK_REALTIME, &ctim);
		filehandle_update_times(fh, NULL, &ctim, &ctim);
		filehandle_update_filesize(fh);
		filehandle_release(fh);
	}

	directory_unlock();

	return ret;
}

/**
 * Change the size of an open file
 *
 * This method is called instead of the truncate() method if the
 * truncation was invoked from an ftruncate() system call.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the truncate() method will be
 * called instead.
 */
static int fs_ftruncate(const char *path, off_t newsize, struct fuse_file_info *fi)
{
	int ret;
	struct fs_file_handle_s *fh = (struct fs_file_handle_s *)fi->fh;
	struct timespec ctim;
	
	if (!(filehandle_is_valid(fh))) {
		return -EIO;
	}
	
	log_msg("fs_ftruncate(path='%s', newsize=%lld) fd=%d\n", path, newsize, fh->fd);

	directory_lock();

	ret = ftruncate(fh->fd, newsize);
	if (ret < 0) {
		ret = -errno;
	}
	clock_gettime(CLOCK_REALTIME, &ctim);
	filehandle_update_times(fh, NULL, &ctim, &ctim);
	filehandle_update_filesize(fh);

	directory_unlock();

	return ret;
}

/**
 * Allocates space for an open file
 *
 * This function ensures that required space is allocated for specified
 * file.  If this function returns success then any subsequent write
 * request to specified range is guaranteed not to fail because of lack
 * of space on the file system media.
 *
 */
static int fs_fallocate(const char *path, int mode, off_t offset, off_t len, struct fuse_file_info *fi)
{
	int ret;
	struct fs_file_handle_s *fh = (struct fs_file_handle_s *)fi->fh;
	struct timespec ctim;
	
	if (!(filehandle_is_valid(fh))) {
		return -EIO;
	}
	
	log_msg("fs_fallocate(path='%s', mode=%d, offset=%lld, len=%lld) fd=%d\n",
		path, mode, offset, len, fh->fd);

	directory_lock();

	ret = fallocate(fh->fd, mode, offset, len);

	if (ret < 0) {
		ret = -errno;
	}
	clock_gettime(CLOCK_REALTIME, &ctim);
	filehandle_update_times(fh, NULL, &ctim, &ctim);
	filehandle_update_filesize(fh);

	directory_unlock();

	return ret;
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.  It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 */
static int fs_release(const char *path, struct fuse_file_info *fi)
{
	int ret = 0;
	struct fs_file_handle_s *fh = (struct fs_file_handle_s *)fi->fh;

	directory_lock();

	if (!(filehandle_is_valid(fh))) {
		log_msg("fs_release(path='%s') invalid filehandle!\n");
		ret = -EBADF;
	} else {
		log_msg("fs_release(path='%s', fd=%d)\n", path, fh->fd);

		if (fh->fduse) {
			close(fh->fd);
		}
		filehandle_release(fh);
	}

	directory_unlock();

	// TODO put file to remote
	return ret;
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.  An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 */
static int fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int ret = 0;
	off_t o;
	struct fs_file_handle_s *fh = (struct fs_file_handle_s *)fi->fh;
	struct timespec ctim;

	directory_lock();

	if (!(filehandle_is_valid(fh))) {
		directory_unlock();
		log_msg("fs_read(path='%s') invalid filehandle!\n");
		ret = -EBADF;
	} else {
		log_msg("fs_read(path='%s', size=%llu , offset=%llu, fd=%d)\n", path, size, offset, fh->fd);
		if ((!(fi->flags & O_NOATIME)) && (!ofs.noatime)) {
			clock_gettime(CLOCK_REALTIME, &ctim);
			filehandle_update_times(fh, &ctim, NULL, NULL);
		}
		directory_unlock();

		o = lseek(fh->fd, offset, SEEK_SET);
		if (o < 0) {
			ret = -errno;
		} else {
			ret = read(fh->fd, buf, size);
			if (ret < 0) {
				ret = -errno;
			}
		}
	}
	log_msg(" fs_read(path='%s') ret=%d\n", path, ret);

	return ret;
}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.  An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 */
static int fs_write(const char *path, const char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
	int ret = 0;
	off_t o;
	struct fs_file_handle_s *fh = (struct fs_file_handle_s *)fi->fh;
	struct timespec ctim;

	directory_lock();

	if (!(filehandle_is_valid(fh))) {
		directory_unlock();
		log_msg("fs_write(path='%s') invalid filehandle!\n");
		ret = -EBADF;
	} else {
		log_msg("fs_write(path='%s', size=%llu , offset=%llu, fd=%d)\n", path, size, offset, fh->fd);
		clock_gettime(CLOCK_REALTIME, &ctim);
		filehandle_update_times(fh, &ctim, NULL, &ctim);
		directory_unlock();

		o = lseek(fh->fd, offset, SEEK_SET);
		if (o < 0) {
			ret = -errno;
		} else {
			ret = write(fh->fd, buf, size);
			if (ret < 0) {
				ret = -errno;
			} else {
				directory_lock();
				filehandle_update_filesize(fh);
				directory_unlock();
			}
		}
	}

	return ret;
}

/** File open operation
 *
 * No creation (O_CREAT, O_EXCL) and by default also no
 * truncation (O_TRUNC) flags will be passed to open(). If an
 * application specifies O_TRUNC, fuse first calls truncate()
 * and then open(). Only if 'atomic_o_trunc' has been
 * specified and kernel version is 2.6.24 or later, O_TRUNC is
 * passed on to open.
 *
 * Unless the 'default_permissions' mount option is given,
 * open should check if the operation is permitted for the
 * given flags. Optionally open may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to all file operations.
 */
static int fs_open(const char *path, struct fuse_file_info *fi)
{
	int ret = 0;
	int fd;
	struct fs_file_handle_s *fh;
	struct timespec atim;

	log_msg("fs_open(path='%s', flags=0x%x)\n", path, fi->flags);

	directory_lock();

	fh = filehandle_open(path);

	if (fh == NULL) {
		directory_unlock();
		return -ENOENT;
	}

	ret = filehandle_set_names(fh);
	if (ret != 0) {
   		filehandle_release(fh);
		directory_unlock();
		return ret;
	}

	directory_unlock();

	// TODO get file from remote

	fd = open(fh->storename.fullpathobjectfile, fi->flags);
   	if (fd < 0) {
		directory_lock();
		filehandle_release(fh);
		directory_unlock();
		return -errno;
	}

	fi->fh = (intptr_t) fh;
	fh->fd = fd;
	fh->fduse = 1;
	if ((!(fi->flags & O_NOATIME)) && (!ofs.noatime)) {
		clock_gettime(CLOCK_REALTIME, &atim);
		directory_lock();
		filehandle_update_times(fh, &atim, NULL, NULL);
		directory_unlock();
	}

	log_msg(" fs_open(fd=%d)\n", fd);

	return 0;
}

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 */
static int fs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int ret = 0;
	int fd;
	struct fs_file_handle_s *fh;
	struct timespec atim;
	struct fuse_context *context = fuse_get_context();

	log_msg("fs_create(path='%s', mode=0%03o, flags=%x)\n", path, mode, fi->flags);

	directory_lock();

	fh = filehandle_open(path);

	if (fh != NULL) {
   		filehandle_release(fh);
		directory_unlock();
		return -EEXIST;
	}
	clock_gettime(CLOCK_REALTIME, &atim);

	ret = directory_add_entry(path, mode, context->uid, context->gid,
		0, 0, &atim, &atim, &atim, NULL);
	if (ret != 0) {
		directory_unlock();
		return ret;
	}

	fh = filehandle_open(path);
	if (fh == NULL) {
		directory_unlock();
		return -EIO;
	}

	ret = filehandle_set_names(fh);
	if (ret != 0) {
		filehandle_release(fh);
		directory_unlock();
		return ret;
	}

	fd = creat(fh->storename.fullpathobjectfile, ofs.def_filemode);
   	if (fd < 0) {
		filehandle_release(fh);
		directory_unlock();
		return -errno;
	}

	fi->fh = (intptr_t) fh;
	fh->fd = fd;
	fh->fduse = 1;

	directory_unlock();

	log_msg(" fs_create(fd=%d)\n", fd);

	return 0;
}

#ifdef USE_XATTR
/** Set extended attributes */
static int fs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
	int ret = 0;
	struct fs_file_handle_s *fh;
	struct timespec ctim;

	log_msg("fs_setxattr(path='%s', name=\"%s\", value=%p, size=%d, flags=0x%08x)\n",
		path, name, value, size, flags);

	directory_lock();

	fh = filehandle_open(path);
	if (fh == NULL) {
		ret = -ENOENT;
	} else {
		if ((strlen(name) == 0) || (strlen(name) >= sizeof(((struct dir_inode_xattr_s *)0)->name))) {
			ret = -ENOTSUP;
		} else {
			ret = directory_inode_setxattr(fh->inode, name, value, size, flags);
			if (ret >= 0) {
				clock_gettime(CLOCK_REALTIME, &ctim);
				filehandle_update_times(fh, NULL, &ctim, NULL);
			}
		}
		filehandle_release(fh);
	}

	directory_unlock();

	return ret;
}
#endif //USE_XATTR

#ifdef USE_XATTR
/** Get extended attributes */
static int fs_getxattr(const char *path, const char *name, char *value, size_t size)
{
	int ret = 0;
	struct fs_file_handle_s *fh;

	log_msg("fs_getxattr(path='%s', name='%s', value=%p, size=%d)\n",
		path, name, value, size);	

	directory_lock();

	fh = filehandle_open(path);
	if (fh == NULL) {
		ret = -ENOENT;
	} else {
		if (strlen(name) == 0) {
			ret = -ENOTSUP;
		} else {
			ret = directory_inode_getxattr(fh->inode, name, value, size);
		}
		filehandle_release(fh);
	}

	directory_unlock();

	return ret;
}
#endif // USE_XATTR

#ifdef USE_XATTR
/** List extended attributes */
static int fs_listxattr(const char *path, char *list, size_t size)
{
	int ret = 0;
	struct fs_file_handle_s *fh;

	log_msg("fs_listxattr(path='%s', list=%p, size=%d)\n", path, list, size);

	directory_lock();

	fh = filehandle_open(path);
	if (fh == NULL) {
		ret = -ENOENT;
	} else {
		ret = directory_inode_listxattr(fh->inode, list, size);
		filehandle_release(fh);
	}

	directory_unlock();

	return ret;
}
#endif // USE_XATTR

#ifdef USE_XATTR
/** Remove extended attributes */
static int fs_removexattr(const char *path, const char *name)
{
	int ret = 0;
	struct fs_file_handle_s *fh;
	struct timespec ctim;

	log_msg("fs_removexattr(path='%s', name=\"%s\")\n", path, name);

	fh = filehandle_open(path);
	if (fh == NULL) {
		ret = -ENOENT;
	} else {
		if (strlen(name) == 0) {
			ret = -ENOTSUP;
		} else {
			ret = directory_inode_removexattr(fh->inode, name);
			if (ret >= 0) {
				clock_gettime(CLOCK_REALTIME, &ctim);
				filehandle_update_times(fh, NULL, &ctim, NULL);
			}
		}
		filehandle_release(fh);
	}

	directory_unlock();

	return ret;
}
#endif // USE_XATTR

static struct fuse_operations fs_oper = {
	.init       = fs_init,
	.destroy    = fs_destroy,
	.open       = fs_open,
	.flush      = fs_flush,
	.release    = fs_release,
	.fsync      = fs_fsync,
	.read       = fs_read,
	.write      = fs_write,
	.getattr    = fs_getattr,
	.fallocate  = fs_fallocate,
	.utimens    = fs_utimens,
	.flag_utime_omit_ok = 1,
	.access     = NULL,			/* let VFS do this */
	.truncate   = fs_truncate,
	.ftruncate  = fs_ftruncate,
	.fgetattr   = fs_fgetattr,
	.readdir    = fs_readdir,
	.statfs     = fs_statfs,
	.readlink   = fs_readlink,
	.opendir    = fs_opendir,
	.releasedir = fs_releasedir,
	.fsyncdir   = fs_fsyncdir,
	.getdir     = NULL,			/* depricated */
	.mknod      = fs_mknod,
	.mkdir      = fs_mkdir,
	.symlink    = fs_symlink,
	.unlink     = fs_unlink,
	.rmdir      = fs_rmdir,
	.rename     = fs_rename,
	.link       = fs_link,
	.chmod      = fs_chmod,
	.chown      = fs_chown,
	.create     = fs_create,
#ifdef USE_XATTR
	.setxattr   = fs_setxattr,
	.getxattr   = fs_getxattr,
	.listxattr  = fs_listxattr,
	.removexattr = fs_removexattr,
#endif // USE_XATTR
};

enum {
	KEY_VERSION,
	KEY_HELP,
	KEY_LOG,
	KEY_NOATIME,
};

#define OFS_OPT(t, p, v) { t, offsetof(struct ofs_s, p), v }

static struct fuse_opt ofs_opts[] = {
	OFS_OPT(      "-p %s",           path, 0),
	FUSE_OPT_KEY ("-L",              KEY_LOG),
	FUSE_OPT_KEY ("-V",              KEY_VERSION),
	FUSE_OPT_KEY ("--version",       KEY_VERSION),
	FUSE_OPT_KEY ("-h",              KEY_HELP),
	FUSE_OPT_KEY ("--help",          KEY_HELP),
	FUSE_OPT_KEY ("--noatime",       KEY_NOATIME),
	FUSE_OPT_END
};

static void usage(const char *progname)
{
	printf(
"usage: %s mountpoint [options]\n"
"\n"
"general options:\n"
"    -p <path>              path to storage\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"    --noatime              do not update st_atime on read\n"
"    -L                     enable debug log to ./objectfs.log\n"
"\n", progname);
}

static int ofs_opt_proc(void *data, const char *arg, int key,
                              struct fuse_args *outargs)
{
	switch(key) {
	case KEY_LOG:
		log_open();
		log_msg("START\n");
		return 0;

	case KEY_NOATIME:
		ofs.noatime = 1;
		return 0;

	case KEY_HELP:
		usage(outargs->argv[0]);
		fuse_opt_add_arg(outargs, "-ho");
		fuse_main(outargs->argc, outargs->argv, &fs_oper, NULL);
		exit(1);

	case KEY_VERSION:
		printf("FS version: %s\n", OFS_VERSION);
		fuse_opt_add_arg(outargs, "--version");
		fuse_main(outargs->argc, outargs->argv, &fs_oper, NULL);
		exit(0);
	}
	return 1;
}

int main(int argc, char *argv[])
{
	int ret;
	int fuse_stat = 0;
	struct stat pstat;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	ofs.def_filemode = 0644;
	ofs.def_dirmode = 0755;
	ofs.noatime = 0;

	if (fuse_opt_parse(&args, &ofs, ofs_opts, ofs_opt_proc) == -1) {
		perror("parse options");
		abort();
	}

	/* we provide our own ino, tell fuse to use it */
	fuse_opt_add_arg(&args, "-o");
	fuse_opt_add_arg(&args, "use_ino");

	/* tell fuse to check access permissions */
	fuse_opt_add_arg(&args, "-o");
	fuse_opt_add_arg(&args, "default_permissions");

	if (ofs.path == NULL) {
		fprintf(stderr, "Missing path to storage!\n");
		exit(1);
	}
	if ((stat(ofs.path, &pstat) != 0)  || (!S_ISDIR(pstat.st_mode))) {
		fprintf(stderr, "Path to storage is not a valid directory!\n");
		exit(1);
	}
	log_msg("Path set to: %s\n", ofs.path);

	if ((ret = directory_init())) {
		fprintf(stderr, "Unable to init directory: %s\n", strerror(-ret));
		exit(1);
	}

	fuse_stat = fuse_main(args.argc, args.argv, &fs_oper, NULL);

	log_msg("END\n");
	log_close();

	return fuse_stat;
}


