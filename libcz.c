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
    if (fd & HOOK_FD_FLAG) {
        return chfs_close(fd ^ HOOK_FD_FLAG);
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
    if (fd & HOOK_FD_FLAG) {
        return chfs_read(fd ^ HOOK_FD_FLAG, buf, count);
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
    if (fd & HOOK_FD_FLAG) {
        return chfs_write(fd ^ HOOK_FD_FLAG, buf, count);
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
    if (fd & HOOK_FD_FLAG) {
        return chfs_pread(fd ^ HOOK_FD_FLAG, buf, count, offset);
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
    if (fd & HOOK_FD_FLAG) {
        return chfs_pwrite(fd ^ HOOK_FD_FLAG, buf, count, offset);
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
    if (fd & HOOK_FD_FLAG) {
        return chfs_seek(fd ^ HOOK_FD_FLAG, offset, whence);
    } else {
        return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
    }
}


static long hook_fsync(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
    int fd = (int)a2;
    if (fd & HOOK_FD_FLAG) {
        return chfs_fsync(fd ^ HOOK_FD_FLAG);
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
    if (fd & HOOK_FD_FLAG) {
        return chfs_fstat(fd ^ HOOK_FD_FLAG, st);
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
        case SYS_unlink:
            return hook_unlink(a1, a2, a3, a4, a5, a6, a7);
        case SYS_openat:
            return hook_openat(a1, a2, a3, a4, a5, a6, a7);
        case SYS_fsync:
            return hook_fsync(a1, a2, a3, a4, a5, a6, a7);
        case SYS_mkdir:
            return hook_mkdir(a1, a2, a3, a4, a5, a6, a7);
        case SYS_newfstatat:
            return hook_newfstatat(a1, a2, a3, a4, a5, a6, a7);
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
}
