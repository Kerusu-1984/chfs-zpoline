#define _GNU_SOURCE
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <chfs.h>

const char *syscall_string(int);

#ifdef DEBUG
#define _DEBUG(x)	x
#else
#define _DEBUG(x)
#endif

#define HOOK_FD_FLAG (1<<30)

typedef long (*syscall_fn_t)(long, long, long, long, long, long, long);

static syscall_fn_t real_next_sys_call = NULL;

static long next_sys_call(long a1, long a2, long a3, long a4, long a5,
	long a6, long a7)
{
	long ret;
	int save_errno;

	ret = real_next_sys_call(a1, a2, a3, a4, a5, a6, a7);
	save_errno = errno;
	_DEBUG(printf("call: %s(%ld, %ld, %ld, %ld, %ld, %ld) = %ld %s\n",
		syscall_string(a1), a2, a3, a4, a5, a6, a7, ret,
		ret == -1 ? strerror(errno) : ""));
	errno = save_errno;
	return (ret);
}

#define CHFS_DIR	"/chfs"
#define CHFS_LEN	5
#define IS_CHFS(p)	(strncmp(p, CHFS_DIR, CHFS_LEN) == 0 && \
				(p[CHFS_LEN] == '\0' || p[CHFS_LEN] == '/'))
#define SKIP_DIR(p)	(p += CHFS_LEN)

/* file descriptors opened by dup2 */
static struct {
	int fd;	/* duplicated chfs fd */
	int ref;
} *fd_list;
static int fd_num = 0;

#define MIN_FD_NUM	100

static int
alloc_fd(int num)
{
	if (num < MIN_FD_NUM)
		num = MIN_FD_NUM;
	if (fd_num < num) {
		void *t = realloc(fd_list, 2 * num * sizeof(fd_list[0]));
		if (t != NULL) {
			fd_list = t;
			for (; fd_num < 2 * num; ++fd_num) {
				fd_list[fd_num].fd = -1;
				fd_list[fd_num].ref = 1;
			}
		}
	}
	if (fd_num < num)
		return (-1);
	return (0);
}

static int
dup_fd(int oldfd, int newfd)
{
	int fd, max = newfd > oldfd ? newfd : oldfd;

	if (newfd < 0 || oldfd < 0) {
		errno = EBADF;
		return (-1);
	}
	if (alloc_fd(max + 1) < 0) {
		errno = ENOMEM;
		return (-1);
	}
	fd = fd_list[newfd].fd;
	if (fd != -1) {
		/* if newfd is opened by dup2, close newfd */
		if (fd_list[fd].ref > 1)
			--fd_list[fd].ref;
		else {
			fd_list[fd].fd = -1;
			chfs_close(fd);
		}
	}
	fd_list[newfd].fd = oldfd;
	++fd_list[oldfd].ref;
	return (newfd);
}

static int
is_chfs_fd(int *fd)
{
	if (*fd & HOOK_FD_FLAG) {
		*fd ^= HOOK_FD_FLAG;
		return (1);
	}
	if (*fd < 0 || *fd >= fd_num || fd_list[*fd].fd == -1)
		return (0);
	*fd = fd_list[*fd].fd;
	return (1);
}

static long
hook_dup2(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int oldfd = a2;
	int newfd = a3;
	if (is_chfs_fd(&oldfd))
		return (dup_fd(oldfd, newfd));
	else
		return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long hook_open(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    char *path = (char *)a2;
    int flags = (int)a3;
    mode_t mode = (mode_t)a4;
    if (IS_CHFS(path)) {
        int ret;
	SKIP_DIR(path);
        if (flags & O_CREAT) {
            ret = chfs_create(path, flags, mode);
        } else {
            ret = chfs_open(path, flags);
        }
        if (ret < 0) return ret;
        return ret | HOOK_FD_FLAG;
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}

static long hook_close(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    int fd = (int)a2;
    if (is_chfs_fd(&fd)) {
	if (fd < fd_num) {
	    if (fd_list[fd].ref > 1) {
		--fd_list[fd].ref;
		return (0);
	    } else
		fd_list[fd].fd = -1;
	}
	return (chfs_close(fd));
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}

static long hook_read(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    int fd = (int)a2;
    void *buf = (void *)a3;
    size_t count = (size_t)a4;
    if (is_chfs_fd(&fd)) {
	return (chfs_read(fd, buf, count));
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}

static long hook_write(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    int fd = (int)a2;
    void *buf = (void *)a3;
    size_t count = (size_t)a4;
    if (is_chfs_fd(&fd)) {
	return (chfs_write(fd, buf, count));
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}

static long hook_stat(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    char *path = (char *)a2;
    struct stat *st = (struct stat *)a3;
    if (IS_CHFS(path)) {
	SKIP_DIR(path);
        return chfs_stat(path, st);
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}

static long hook_pread64(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    int fd = (int)a2;
    void *buf = (void *)a3;
    size_t count = (size_t)a4;
    off_t offset = (off_t)a5;
    if (is_chfs_fd(&fd)) {
	return chfs_pread(fd, buf, count, offset);
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}

static long hook_pwrite64(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    int fd = (int)a2;
    void *buf = (void *)a3;
    size_t count = (size_t)a4;
    off_t offset = (off_t)a5;
    if (is_chfs_fd(&fd)) {
	return chfs_pwrite(fd, buf, count, offset);
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}

static long hook_access(long a1, long a2, long a3, long a4, long a5, long a6,
	long a7)
{
    char *path = (char *)a2;
    int mode = (int)a3;
    if (IS_CHFS(path)) {
	SKIP_DIR(path);
	return (chfs_access(path, mode));
    } else {
        return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
    }
}

static long hook_unlink(long a1, long a2, long a3, long a4, long a5, long a6,
	long a7)
{
    char *path = (char *)a2;
    if (IS_CHFS(path)) {
	SKIP_DIR(path);
	return (chfs_unlink(path));
    } else {
        return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
    }
}

static long hook_openat(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    char *path = (char *)a3;
    int flags = (int)a4;
    mode_t mode = (mode_t)a5;
    if (IS_CHFS(path)) {
        int ret;
	SKIP_DIR(path);
        if (flags & O_CREAT) {
            ret = chfs_create(path, flags, mode);
        } else {
            ret = chfs_open(path, flags);
        }
        if (ret < 0) return ret;
        return ret | HOOK_FD_FLAG;
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}

static long hook_lseek(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    int fd  = (int)a2;
    off_t offset = (off_t)a3;
    int whence = (int)a4;
    if (is_chfs_fd(&fd)) {
	return chfs_seek(fd, offset, whence);
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}


static long hook_fsync(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    int fd = (int)a2;
    if (is_chfs_fd(&fd)) {
	return chfs_fsync(fd);
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}

static long hook_fstat(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    int fd = (int)a2;
    struct stat *st = (struct stat *)a3;
    if (is_chfs_fd(&fd)) {
	return chfs_fstat(fd, st);
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}

static long hook_lstat(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    char *path = (char *)a2;
    struct stat *st = (struct stat *)a3;
    if (IS_CHFS(path)) {
	SKIP_DIR(path);
        return chfs_stat(path, st);
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}

static long hook_mkdir(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    char *path = (char *)a2;
    mode_t mode = (mode_t)a3;
    if (IS_CHFS(path)) {
	    SKIP_DIR(path);
        return chfs_mkdir(path, mode);
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}

static long
hook_getdents64(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = a2;
	char *dirp = (char *)a3;
	ssize_t count = a4;

	if (is_chfs_fd(&fd))
		return (chfs_linux_getdents64(fd, dirp, count));
	else
		return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long hook_newfstatat(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    char *path = (char *)a3;
    struct stat *buf = (struct stat *)a4;
    if (IS_CHFS(path)) {
	SKIP_DIR(path);
        return chfs_stat(path, buf);
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}

static long
hook_statx(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a3;
	struct statx *sx = (struct statx *)a6;
	struct stat sb;

	if (IS_CHFS(path)) {
		int ret;

		SKIP_DIR(path);
		ret = chfs_stat(path, &sb);
		if (ret < 0)
			return (ret);
		sx->stx_blksize = sb.st_blksize;
		sx->stx_nlink = sb.st_nlink;
		sx->stx_uid = sb.st_uid;
		sx->stx_gid = sb.st_gid;
		sx->stx_mode = sb.st_mode;
		sx->stx_ino = sb.st_ino;
		sx->stx_size = sb.st_size;
		sx->stx_blocks = sb.st_blocks;
		sx->stx_mtime.tv_sec = sb.st_mtim.tv_sec;
		sx->stx_mtime.tv_nsec = sb.st_mtim.tv_nsec;
		sx->stx_ctime.tv_sec = sb.st_ctim.tv_sec;
		sx->stx_ctime.tv_nsec = sb.st_ctim.tv_nsec;
		return (ret);
	} else
		return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long hook_function(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    _DEBUG(printf("hook: %s(%ld, %ld, %ld, %ld, %ld, %ld)\n",
		syscall_string(a1), a2, a3, a4, a5, a6, a7));

    switch (a1) {
        case SYS_read:
            return hook_read(a1, a2, a3, a4, a5, a6, a7);
        case SYS_write:
            return hook_write(a1, a2, a3, a4, a5, a6, a7);
        case SYS_open:
            return hook_open(a1, a2, a3, a4, a5, a6, a7);
        case SYS_close:
            return hook_close(a1, a2, a3, a4, a5, a6, a7);
        case SYS_stat:
            return hook_stat(a1, a2, a3, a4, a5, a6, a7);
        case SYS_fstat:
            return hook_fstat(a1, a2, a3, a4, a5, a6, a7);
        case SYS_lstat:
            return hook_lstat(a1, a2, a3, a4, a5, a6, a7);
        case SYS_lseek:
            return hook_lseek(a1, a2, a3, a4, a5, a6, a7);
        case SYS_pread64:
            return hook_pread64(a1, a2, a3, a4, a5, a6, a7);
        case SYS_pwrite64:
            return hook_pwrite64(a1, a2, a3, a4, a5, a6, a7);
        case SYS_access:
            return hook_access(a1, a2, a3, a4, a5, a6, a7);
	case SYS_dup2:
	    return hook_dup2(a1, a2, a3, a4, a5, a6, a7);
        case SYS_unlink:
            return hook_unlink(a1, a2, a3, a4, a5, a6, a7);
        case SYS_openat:
            return hook_openat(a1, a2, a3, a4, a5, a6, a7);
        case SYS_fsync:
            return hook_fsync(a1, a2, a3, a4, a5, a6, a7);
        case SYS_mkdir:
            return hook_mkdir(a1, a2, a3, a4, a5, a6, a7);
	case SYS_getdents64:
	    return hook_getdents64(a1, a2, a3, a4, a5, a6, a7);
        case SYS_newfstatat:
            return hook_newfstatat(a1, a2, a3, a4, a5, a6, a7);
	case SYS_statx:
	    return hook_statx(a1, a2, a3, a4, a5, a6, a7);
        default:
            break;
    }
    return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

int __hook_init(long placeholder __attribute__((unused)),
		void *sys_call_hook_ptr)
{
    chfs_init(NULL);
    real_next_sys_call = *((syscall_fn_t *) sys_call_hook_ptr);
    *((syscall_fn_t *) sys_call_hook_ptr) = hook_function;
    return (0);
}

void __hook_cleanup(void) __attribute__((destructor));

void __hook_cleanup(void) {
    chfs_term();
    free(fd_list);
}
