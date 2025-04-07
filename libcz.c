#define _GNU_SOURCE
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <chfs.h>

const char *syscall_string(int);

#ifdef DEBUG
#define _DEBUG(x)	x
#define _ASSERT(x)	do { if ((x) == 0) fprintf(stderr, \
		"%s:%d: %s: Assertion '%s' failed.\n", \
		__FILE__, __LINE__, __func__, #x), exit(1); } while (0);
#else
#define _DEBUG(x)
#define _ASSERT(x)
#endif

typedef long (*syscall_fn_t)(long, long, long, long, long, long, long);

static syscall_fn_t real_next_sys_call = NULL;

static long next_sys_call(long a1, long a2, long a3, long a4, long a5,
	long a6, long a7)
{
	long ret;
	int save_errno;

	ret = real_next_sys_call(a1, a2, a3, a4, a5, a6, a7);
	save_errno = errno;
	_DEBUG(printf("call[%d]: %s(%ld, %ld, %ld, %ld, %ld, %ld) = %ld %s\n",
		getpid(), syscall_string(a1), a2, a3, a4, a5, a6, a7, ret,
		ret == -1 ? strerror(errno) : ""));
	_DEBUG(fflush(stdout));
	_ASSERT(strcmp(syscall_string(a1), "unknown"));
	errno = save_errno;
	return (ret);
}

#define CHFS_DIR	"/chfs"
#define CHFS_LEN	5
#ifdef DEBUG
#define IS_CHFS(p)	(printf("path[%d]=%s\n", getpid(), p), \
				strncmp(p, CHFS_DIR, CHFS_LEN) == 0 && \
				(p[CHFS_LEN] == '\0' || p[CHFS_LEN] == '/'))
#else
#define IS_CHFS(p)	(strncmp(p, CHFS_DIR, CHFS_LEN) == 0 && \
				(p[CHFS_LEN] == '\0' || p[CHFS_LEN] == '/'))
#endif
#define SKIP_DIR(p)	(p += CHFS_LEN)

/* file descriptors opened by dup2 */
static struct {
	int fd;	/* duplicated chfs fd */
	int ref;
} *fd_list;
static int fd_num = 0;

#define MIN_FD_NUM	100

static int
alloc_fd_list(int num)
{
	if (num < MIN_FD_NUM)
		num = MIN_FD_NUM;
	if (fd_num < num) {
		void *t = realloc(fd_list, 2 * num * sizeof(fd_list[0]));
		if (t != NULL) {
			fd_list = t;
			for (; fd_num < 2 * num; ++fd_num) {
				fd_list[fd_num].fd = -1;
				fd_list[fd_num].ref = 0;
			}
		}
	}
	if (fd_num < num)
		return (-1);
	return (0);
}

static int
alloc_fd(int newfd)
{
	int fd = open("/dev/null", O_RDWR|O_CLOEXEC);

	if (fd == -1 || fd == newfd)
		return (fd);
	newfd = dup3(fd, newfd, O_CLOEXEC);
	close(fd);
	return (newfd);
}

static int
alloc_fd_min(int min)
{
	int fd = open("/dev/null", O_RDWR|O_CLOEXEC), newfd;

	if (fd == -1 || fd >= min)
		return (fd);
	newfd = fcntl(fd, F_DUPFD_CLOEXEC, min);
	close(fd);
	return (newfd);
}

static int
dup_internal(int oldfd, int newfd)
{
	int fd;

	fd = fd_list[newfd].fd;
	if (fd != -1) {
		/* if newfd is opened, close newfd */
		if (--fd_list[fd].ref == 0)
			chfs_close(fd);
		_ASSERT(fd_list[fd].ref >= 0);
	}
	fd_list[newfd].fd = oldfd;
	++fd_list[oldfd].ref;
	return (newfd);
}

static int
dup_fd(int oldfd, int min)
{
	int newfd, max;

	if (oldfd < 0) {
		errno = EBADF;
		return (-1);
	}
	newfd = alloc_fd_min(min);
	if (newfd == -1)
		return (newfd);

	max = newfd > oldfd ? newfd : oldfd;
	if (alloc_fd_list(max + 1) < 0) {
		close(newfd);
		errno = ENOMEM;
		return (-1);
	}
	return (dup_internal(oldfd, newfd));
}

static int
dup2_fd(int oldfd, int newfd)
{
	int max = newfd > oldfd ? newfd : oldfd;

	if (newfd < 0 || oldfd < 0) {
		errno = EBADF;
		return (-1);
	}
	if (alloc_fd_list(max + 1) < 0) {
		errno = ENOMEM;
		return (-1);
	}
	if (alloc_fd(newfd) == -1)
		return (-1);

	return (dup_internal(oldfd, newfd));
}

static int
is_chfs_fd(int *fd)
{
	if (*fd < 0 || *fd >= fd_num || fd_list[*fd].fd == -1)
		return (0);
	*fd = fd_list[*fd].fd;
	return (1);
}

static long
hook_dup(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int oldfd = a2;

	if (is_chfs_fd(&oldfd))
		return (dup_fd(oldfd, 0));
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_dup2(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int oldfd = a2;
	int newfd = a3;

	if (is_chfs_fd(&oldfd))
		return (dup2_fd(oldfd, newfd));
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_fcntl(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = a2;
	int op = a3;
	int arg = a4;

	if (is_chfs_fd(&fd)) {
		switch (op) {
		case F_DUPFD:
		case F_DUPFD_CLOEXEC:
			return (dup_fd(fd, arg));
		}
		return (0);
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static int
hook_open_internal(const char *path, int flags, mode_t mode)
{
	int ret;

	if (flags & O_CREAT)
		ret = chfs_create(path, flags, mode);
	else
		ret = chfs_open(path, flags);
	if (ret < 0)
		return (ret);
	return (dup_fd(ret, 0));
}

static long
hook_open(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	int flags = (int)a3;
	mode_t mode = (mode_t)a4;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		return (hook_open_internal(path, flags, mode));
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_close(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2, fd2;

	fd2 = fd;
	if (is_chfs_fd(&fd2)) {
		if (close(fd) == -1)
			perror("close");
		fd_list[fd].fd = -1;
		if (--fd_list[fd2].ref == 0)
			chfs_close(fd2);
		_ASSERT(fd_list[fd2].ref >= 0);
		return (0);
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_read(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	void *buf = (void *)a3;
	size_t count = (size_t)a4;

	if (is_chfs_fd(&fd))
		return (chfs_read(fd, buf, count));
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_write(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	void *buf = (void *)a3;
	size_t count = (size_t)a4;

	if (is_chfs_fd(&fd))
		return (chfs_write(fd, buf, count));
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_stat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	struct stat *st = (struct stat *)a3;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		return (chfs_stat(path, st));
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_pread64(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	void *buf = (void *)a3;
	size_t count = (size_t)a4;
	off_t offset = (off_t)a5;

	if (is_chfs_fd(&fd))
		return (chfs_pread(fd, buf, count, offset));
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_pwrite64(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	void *buf = (void *)a3;
	size_t count = (size_t)a4;
	off_t offset = (off_t)a5;

	if (is_chfs_fd(&fd))
		return (chfs_pwrite(fd, buf, count, offset));
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_access(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	int mode = (int)a3;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		return (chfs_access(path, mode));
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_unlink(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		return (chfs_unlink(path));
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_symlink(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *target = (char *)a2;
	char *linkpath = (char *)a3;

	if (IS_CHFS(target)) {
		SKIP_DIR(target);
		return (chfs_symlink(target, linkpath));
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_readlink(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	char *buf = (char *)a3;
	size_t bufsize = (size_t)a4;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		return (chfs_readlink(path, buf, bufsize));
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static int is_cwd_chfs = 0;

static long
hook_getcwd(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *buf = (char *)a2, *p;
	size_t size = (size_t)a3, len;

	if (is_cwd_chfs) {
		p = chfs_path_at(AT_FDCWD, "");
		if (p != NULL) {
			len = CHFS_LEN + 1;
			if (p[0] != '\0')
				len += 1 + strlen(p);
			if (buf != NULL && size < len) {
				free(p);
				errno = ERANGE;
				return ((long)NULL);
			}
			if (buf == NULL)
				buf = malloc(len);
			if (buf == NULL) {
				free(p);
				return ((long)NULL);
			}
			strcpy(buf, CHFS_DIR);
			if (p[0] != '\0') {
				strcat(buf, "/");
				strcat(buf, p);
			}
			free(p);
			return ((long)buf);
		}
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_chdir(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	int ret;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		ret = chfs_chdir(path);
		if (ret == 0)
			is_cwd_chfs = 1;
		return (ret);
	} else if (path != NULL && path[0] != '/' && is_cwd_chfs)
		return (chfs_chdir(path));
	is_cwd_chfs = 0;
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_fchdir(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2, ret;

	if (is_chfs_fd(&fd)) {
		ret = chfs_fchdir(fd);
		if (ret == 0)
			is_cwd_chfs = 1;
		return (ret);
	}
	is_cwd_chfs = 0;
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_openat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	char *path = (char *)a3, *p;
	int flags = (int)a4;
	mode_t mode = (mode_t)a5;
	int ret;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		return (hook_open_internal(path, flags, mode));
	} else if (path[0] == '/')
		;
	else if ((fd == AT_FDCWD && is_cwd_chfs) || is_chfs_fd(&fd)) {
		p = chfs_path_at(fd, path);
		if (p != NULL) {
			ret = hook_open_internal(p, flags, mode);
			free(p);
			return (ret);
		}
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_mkdirat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	char *path = (char *)a3, *p;
	mode_t mode = (mode_t)a4;
	int ret;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		return (chfs_mkdir(path, mode));
	} else if (path[0] == '/')
		;
	else if ((fd == AT_FDCWD && is_cwd_chfs) || is_chfs_fd(&fd)) {
		p = chfs_path_at(fd, path);
		if (p != NULL) {
			ret = chfs_mkdir(p, mode);
			free(p);
			return (ret);
		}
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static int
hook_unlinkat_internal(const char *path, int flags)
{
	if (flags & AT_REMOVEDIR)
		return (chfs_rmdir(path));
	return (chfs_unlink(path));
}

static long
hook_unlinkat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	char *path = (char *)a3, *p;
	int flags = (int)a4, ret;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		return (hook_unlinkat_internal(path, flags));
	} else if (path[0] == '/')
		;
	else if ((fd == AT_FDCWD && is_cwd_chfs) || is_chfs_fd(&fd)) {
		p = chfs_path_at(fd, path);
		if (p != NULL) {
			ret = hook_unlinkat_internal(p, flags);
			free(p);
			return (ret);
		}
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_lseek(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd  = (int)a2;
	off_t offset = (off_t)a3;
	int whence = (int)a4;

	if (is_chfs_fd(&fd))
		return (chfs_seek(fd, offset, whence));
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_fsync(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;

	if (is_chfs_fd(&fd))
		return (chfs_fsync(fd));
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_truncate(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	off_t length = (off_t)a3;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		return (chfs_truncate(path, length));
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_ftruncate(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	off_t length = (off_t)a3;

	if (is_chfs_fd(&fd))
		return (chfs_ftruncate(fd, length));
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_fstat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	struct stat *st = (struct stat *)a3;

	if (is_chfs_fd(&fd))
		return (chfs_fstat(fd, st));
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_lstat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	struct stat *st = (struct stat *)a3;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		return (chfs_stat(path, st));
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_mkdir(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	mode_t mode = (mode_t)a3;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		return (chfs_mkdir(path, mode));
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_rmdir(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		return (chfs_rmdir(path));
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_creat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	mode_t mode = (mode_t)a3;
	int ret;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		ret = chfs_create(path, O_CREAT|O_WRONLY|O_TRUNC, mode);
		if (ret < 0)
			return (ret);
		return (dup_fd(ret, 0));
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_nop_path(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;

	if (IS_CHFS(path))
		return (0);
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_nop_fd(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;

	if (is_chfs_fd(&fd))
		return (0);
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_nop_at(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	char *path = (char *)a3;

	if (IS_CHFS(path))
		return (0);
	else if (path[0] == '/')
		;
	else if ((fd == AT_FDCWD && is_cwd_chfs) || is_chfs_fd(&fd))
		return (0);
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static void
hook_disp_notsupp(long a1)
{
	fprintf(stderr, "Not supported: %s\n", syscall_string(a1));
	fflush(stderr);
}

static long
hook_notsupp_path(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;

	if (IS_CHFS(path)) {
		hook_disp_notsupp(a1);
		return (-1);
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_notsupp_path2(long a1, long a2, long a3, long a4, long a5, long a6,
	long a7)
{
	char *path1 = (char *)a2;
	char *path2 = (char *)a3;

	if (IS_CHFS(path1) || IS_CHFS(path2)) {
		hook_disp_notsupp(a1);
		return (-1);
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_notsupp_fd(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;

	if (is_chfs_fd(&fd)) {
		hook_disp_notsupp(a1);
		return (-1);
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_notsupp_fd2(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a3;

	if (is_chfs_fd(&fd)) {
		hook_disp_notsupp(a1);
		return (-1);
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_notsupp_at(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	char *path = (char *)a3;

	if (IS_CHFS(path)) {
		hook_disp_notsupp(a1);
		return (-1);
	} else if (path[0] == '/')
		;
	else if ((fd == AT_FDCWD && is_cwd_chfs) || is_chfs_fd(&fd)) {
		hook_disp_notsupp(a1);
		return (-1);
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_notsupp_at2(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd1 = (int)a2;
	char *path1 = (char *)a3;
	int fd2 = (int)a4;
	char *path2 = (char *)a5;

	if (IS_CHFS(path1) || IS_CHFS(path2)) {
		hook_disp_notsupp(a1);
		return (-1);
	} else if ((path1[0] != '/' &&
		((fd1 == AT_FDCWD && is_cwd_chfs) || is_chfs_fd(&fd1))) ||
		(path2[0] != '/' &&
		((fd2 == AT_FDCWD && is_cwd_chfs) || is_chfs_fd(&fd2)))) {
		hook_disp_notsupp(a1);
		return (-1);
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_getdents64(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = a2;
	char *dirp = (char *)a3;
	ssize_t count = a4;

	if (is_chfs_fd(&fd))
		return (chfs_linux_getdents64(fd, dirp, count));
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_newfstatat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	char *path = (char *)a3, *p;
	struct stat *buf = (struct stat *)a4;
	int flags = (int)a5;
	int ret;

	if (IS_CHFS(path)) {
		SKIP_DIR(path);
		return (chfs_stat(path, buf));
	} else if ((fd == AT_FDCWD && is_cwd_chfs) || is_chfs_fd(&fd)) {
		if (path == NULL && (flags & AT_EMPTY_PATH)) {
			if (fd == AT_FDCWD && is_cwd_chfs) {
				p = chfs_path_at(AT_FDCWD, "");
				if (p == NULL) {
					errno = ENOMEM;
					return (-1);
				}
				ret = chfs_stat(p, buf);
				free(p);
				return (ret);
			}
			return (chfs_fstat(fd, buf));
		}
		p = chfs_path_at(fd, path);
		if (p == NULL) {
			errno = ENOMEM;
			return (-1);
		}
		ret = chfs_stat(p, buf);
		free(p);
		return (ret);
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static int clone_called = 0;
static long clone_pid;

static long
hook_clone(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	clone_pid = next_sys_call(a1, a2, a3, a4, a5, a6, a7);

	++clone_called;
	if (clone_pid == 0)
		chfs_init_margo();
	return (clone_pid);
}

static long
hook_statx(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a3;
	struct statx *sx = (struct statx *)a6;
	struct stat sb;
	int ret;

	if (IS_CHFS(path)) {
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
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

static long
hook_function(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	_DEBUG(printf("hook[%d]: %s(%ld, %ld, %ld, %ld, %ld, %ld)\n",
		getpid(), syscall_string(a1), a2, a3, a4, a5, a6, a7));
	_DEBUG(fflush(stdout));

	switch (a1) {
	case SYS_read:
		return (hook_read(a1, a2, a3, a4, a5, a6, a7));
	case SYS_write:
		return (hook_write(a1, a2, a3, a4, a5, a6, a7));
	case SYS_open:
		return (hook_open(a1, a2, a3, a4, a5, a6, a7));
	case SYS_close:
		return (hook_close(a1, a2, a3, a4, a5, a6, a7));
	case SYS_stat:
		return (hook_stat(a1, a2, a3, a4, a5, a6, a7));
	case SYS_fstat:
		return (hook_fstat(a1, a2, a3, a4, a5, a6, a7));
	case SYS_lstat:
		return (hook_lstat(a1, a2, a3, a4, a5, a6, a7));
	case SYS_lseek:
		return (hook_lseek(a1, a2, a3, a4, a5, a6, a7));
	case SYS_ioctl:
		return (hook_nop_fd(a1, a2, a3, a4, a5, a6, a7));
	case SYS_pread64:
		return (hook_pread64(a1, a2, a3, a4, a5, a6, a7));
	case SYS_pwrite64:
		return (hook_pwrite64(a1, a2, a3, a4, a5, a6, a7));
	case SYS_readv:
	case SYS_writev:
		return (hook_notsupp_fd(a1, a2, a3, a4, a5, a6, a7));
	case SYS_access:
		return (hook_access(a1, a2, a3, a4, a5, a6, a7));
	case SYS_dup:
		return (hook_dup(a1, a2, a3, a4, a5, a6, a7));
	case SYS_sendfile:
		return (hook_notsupp_fd2(a1, a2, a3, a4, a5, a6, a7));
	case SYS_dup2:
	case SYS_dup3:
		return (hook_dup2(a1, a2, a3, a4, a5, a6, a7));
	case SYS_clone:
	case SYS_fork:
	case SYS_vfork:
	case SYS_clone3:
		return (hook_clone(a1, a2, a3, a4, a5, a6, a7));
	case SYS_fcntl:
		return (hook_fcntl(a1, a2, a3, a4, a5, a6, a7));
	case SYS_flock:
		return (hook_nop_fd(a1, a2, a3, a4, a5, a6, a7));
	case SYS_fsync:
	case SYS_fdatasync:
		return (hook_fsync(a1, a2, a3, a4, a5, a6, a7));
	case SYS_truncate:
		return (hook_truncate(a1, a2, a3, a4, a5, a6, a7));
	case SYS_ftruncate:
		return (hook_ftruncate(a1, a2, a3, a4, a5, a6, a7));
	case SYS_getdents:
		return (hook_notsupp_fd(a1, a2, a3, a4, a5, a6, a7));
	case SYS_getcwd:
		return (hook_getcwd(a1, a2, a3, a4, a5, a6, a7));
	case SYS_chdir:
		return (hook_chdir(a1, a2, a3, a4, a5, a6, a7));
	case SYS_fchdir:
		return (hook_fchdir(a1, a2, a3, a4, a5, a6, a7));
	case SYS_rename:
		return (hook_notsupp_path2(a1, a2, a3, a4, a5, a6, a7));
	case SYS_mkdir:
		return (hook_mkdir(a1, a2, a3, a4, a5, a6, a7));
	case SYS_rmdir:
		return (hook_rmdir(a1, a2, a3, a4, a5, a6, a7));
	case SYS_creat:
		return (hook_creat(a1, a2, a3, a4, a5, a6, a7));
	case SYS_link:
		return (hook_notsupp_path2(a1, a2, a3, a4, a5, a6, a7));
	case SYS_unlink:
		return (hook_unlink(a1, a2, a3, a4, a5, a6, a7));
	case SYS_symlink:
		return (hook_symlink(a1, a2, a3, a4, a5, a6, a7));
	case SYS_readlink:
		return (hook_readlink(a1, a2, a3, a4, a5, a6, a7));
	case SYS_chmod:
	case SYS_chown:
	case SYS_lchown:
	case SYS_utime:
		return (hook_nop_path(a1, a2, a3, a4, a5, a6, a7));
	case SYS_fchmod:
	case SYS_fchown:
		return (hook_nop_fd(a1, a2, a3, a4, a5, a6, a7));
	case SYS_mknod:
	case SYS_uselib:
	case SYS_statfs:
		return (hook_notsupp_path(a1, a2, a3, a4, a5, a6, a7));
	case SYS_fstatfs:
		return (hook_notsupp_fd(a1, a2, a3, a4, a5, a6, a7));
	case SYS_chroot:
	case SYS_swapon:
	case SYS_swapoff:
		return (hook_notsupp_path(a1, a2, a3, a4, a5, a6, a7));
	case SYS_readahead:
		return (hook_notsupp_fd(a1, a2, a3, a4, a5, a6, a7));
	case SYS_setxattr:
	case SYS_lsetxattr:
	case SYS_getxattr:
	case SYS_lgetxattr:
	case SYS_listxattr:
	case SYS_llistxattr:
	case SYS_removexattr:
	case SYS_lremovexattr:
		return (hook_nop_path(a1, a2, a3, a4, a5, a6, a7));
	case SYS_fsetxattr:
	case SYS_fgetxattr:
	case SYS_flistxattr:
	case SYS_fremovexattr:
		return (hook_nop_fd(a1, a2, a3, a4, a5, a6, a7));
	case SYS_getdents64:
		return (hook_getdents64(a1, a2, a3, a4, a5, a6, a7));
	case SYS_fadvise64:
		return (hook_nop_fd(a1, a2, a3, a4, a5, a6, a7));
	case SYS_utimes:
		return (hook_nop_path(a1, a2, a3, a4, a5, a6, a7));
	case SYS_inotify_add_watch:
	case SYS_inotify_rm_watch:
		return (hook_notsupp_fd(a1, a2, a3, a4, a5, a6, a7));
	case SYS_openat:
		return (hook_openat(a1, a2, a3, a4, a5, a6, a7));
	case SYS_mkdirat:
		return (hook_mkdirat(a1, a2, a3, a4, a5, a6, a7));
	case SYS_mknodat:
		return (hook_notsupp_at(a1, a2, a3, a4, a5, a6, a7));
	case SYS_fchownat:
	case SYS_futimesat:
		return (hook_nop_at(a1, a2, a3, a4, a5, a6, a7));
	case SYS_newfstatat:
		return (hook_newfstatat(a1, a2, a3, a4, a5, a6, a7));
	case SYS_unlinkat:
		return (hook_unlinkat(a1, a2, a3, a4, a5, a6, a7));
	case SYS_renameat:
	case SYS_linkat:
		return (hook_notsupp_at2(a1, a2, a3, a4, a5, a6, a7));
	case SYS_statx:
		return (hook_statx(a1, a2, a3, a4, a5, a6, a7));
	default:
		break;
	}
	return (next_sys_call(a1, a2, a3, a4, a5, a6, a7));
}

int
__hook_init(long placeholder __attribute__((unused)),
	void *sys_call_hook_ptr)
{
	chfs_init(NULL);
	real_next_sys_call = *((syscall_fn_t *) sys_call_hook_ptr);
	*((syscall_fn_t *) sys_call_hook_ptr) = hook_function;
	return (0);
}

void __hook_cleanup(void) __attribute__((destructor));

void
__hook_cleanup(void)
{
	/* XXX - after clone, there are several cases */
#if 0
	/* XXX - workaround: margo_finalize() does not terminate after fork */
	if (clone_called == 0 || (clone_called == 1 && clone_pid))
		chfs_term();
	free(fd_list);
#endif
}
