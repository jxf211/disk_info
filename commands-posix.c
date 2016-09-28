/*
 * QEMU Guest Agent POSIX-specific command implementations
 *
 * Copyright IBM Corp. 2011
 *
 * Authors:
 *  Michael Roth      <mdroth@linux.vnet.ibm.com>
 *  Michal Privoznik  <mprivozn@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include <glib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <net/route.h>
#include "qga/guest-agent-core.h"
#include "qga-qmp-commands.h"
#include "qapi/qmp/qerror.h"
#include "qemu/queue.h"
#include "qemu/host-utils.h"

#ifndef CONFIG_HAS_ENVIRON
#ifdef __APPLE__
#include <crt_externs.h>
#define environ (*_NSGetEnviron())
#else
extern char **environ;
#endif
#endif

#if defined(__linux__)
#include <mntent.h>
#include <linux/fs.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <mntent.h>
#include <sys/vfs.h>

#ifdef FIFREEZE
#define CONFIG_FSFREEZE
#endif
#ifdef FITRIM
#define CONFIG_FSTRIM
#endif
#endif

static void ga_wait_child(pid_t pid, int *status, Error **errp)
{
    pid_t rpid;

    *status = 0;

    do {
        rpid = waitpid(pid, status, 0);
    } while (rpid == -1 && errno == EINTR);

    if (rpid == -1) {
        error_setg_errno(errp, errno, "failed to wait for child (pid: %d)",
                         pid);
        return;
    }

    g_assert(rpid == pid);
}

void qmp_guest_shutdown(bool has_mode, const char *mode, Error **errp)
{
    const char *shutdown_flag;
    Error *local_err = NULL;
    pid_t pid;
    int status;

    slog("guest-shutdown called, mode: %s", mode);
    if (!has_mode || strcmp(mode, "powerdown") == 0) {
        shutdown_flag = "-P";
    } else if (strcmp(mode, "halt") == 0) {
        shutdown_flag = "-H";
    } else if (strcmp(mode, "reboot") == 0) {
        shutdown_flag = "-r";
    } else {
        error_setg(errp,
                   "mode is invalid (valid values are: halt|powerdown|reboot");
        return;
    }

    pid = fork();
    if (pid == 0) {
        /* child, start the shutdown */
        setsid();
        reopen_fd_to_null(0);
        reopen_fd_to_null(1);
        reopen_fd_to_null(2);

        execle("/sbin/shutdown", "shutdown", "-h", shutdown_flag, "+0",
               "hypervisor initiated shutdown", (char*)NULL, environ);
        _exit(EXIT_FAILURE);
    } else if (pid < 0) {
        error_setg_errno(errp, errno, "failed to create child process");
        return;
    }

    ga_wait_child(pid, &status, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    if (!WIFEXITED(status)) {
        error_setg(errp, "child process has terminated abnormally");
        return;
    }

    if (WEXITSTATUS(status)) {
        error_setg(errp, "child process has failed to shutdown");
        return;
    }

    /* succeeded */
}

int64_t qmp_guest_get_time(Error **errp)
{
   int ret;
   qemu_timeval tq;
   int64_t time_ns;

   ret = qemu_gettimeofday(&tq);
   if (ret < 0) {
       error_setg_errno(errp, errno, "Failed to get time");
       return -1;
   }

   time_ns = tq.tv_sec * 1000000000LL + tq.tv_usec * 1000;
   return time_ns;
}

void qmp_guest_set_time(bool has_time, int64_t time_ns, Error **errp)
{
    int ret;
    int status;
    pid_t pid;
    Error *local_err = NULL;
    struct timeval tv;

    /* If user has passed a time, validate and set it. */
    if (has_time) {
        /* year-2038 will overflow in case time_t is 32bit */
        if (time_ns / 1000000000 != (time_t)(time_ns / 1000000000)) {
            error_setg(errp, "Time %" PRId64 " is too large", time_ns);
            return;
        }

        tv.tv_sec = time_ns / 1000000000;
        tv.tv_usec = (time_ns % 1000000000) / 1000;

        ret = settimeofday(&tv, NULL);
        if (ret < 0) {
            error_setg_errno(errp, errno, "Failed to set time to guest");
            return;
        }
    }

    /* Now, if user has passed a time to set and the system time is set, we
     * just need to synchronize the hardware clock. However, if no time was
     * passed, user is requesting the opposite: set the system time from the
     * hardware clock (RTC). */
    pid = fork();
    if (pid == 0) {
        setsid();
        reopen_fd_to_null(0);
        reopen_fd_to_null(1);
        reopen_fd_to_null(2);

        /* Use '/sbin/hwclock -w' to set RTC from the system time,
         * or '/sbin/hwclock -s' to set the system time from RTC. */
        execle("/sbin/hwclock", "hwclock", has_time ? "-w" : "-s",
               NULL, environ);
        _exit(EXIT_FAILURE);
    } else if (pid < 0) {
        error_setg_errno(errp, errno, "failed to create child process");
        return;
    }

    ga_wait_child(pid, &status, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    if (!WIFEXITED(status)) {
        error_setg(errp, "child process has terminated abnormally");
        return;
    }

    if (WEXITSTATUS(status)) {
        error_setg(errp, "hwclock failed to set hardware clock to system time");
        return;
    }
}

typedef struct GuestFileHandle {
    uint64_t id;
    FILE *fh;
    QTAILQ_ENTRY(GuestFileHandle) next;
} GuestFileHandle;

static struct {
    QTAILQ_HEAD(, GuestFileHandle) filehandles;
} guest_file_state;

static int64_t guest_file_handle_add(FILE *fh, Error **errp)
{
    GuestFileHandle *gfh;
    int64_t handle;

    handle = ga_get_fd_handle(ga_state, errp);
    if (handle < 0) {
        return -1;
    }

    gfh = g_malloc0(sizeof(GuestFileHandle));
    gfh->id = handle;
    gfh->fh = fh;
    QTAILQ_INSERT_TAIL(&guest_file_state.filehandles, gfh, next);

    return handle;
}

static GuestFileHandle *guest_file_handle_find(int64_t id, Error **errp)
{
    GuestFileHandle *gfh;

    QTAILQ_FOREACH(gfh, &guest_file_state.filehandles, next)
    {
        if (gfh->id == id) {
            return gfh;
        }
    }

    error_setg(errp, "handle '%" PRId64 "' has not been found", id);
    return NULL;
}

typedef const char * const ccpc;

#ifndef O_BINARY
#define O_BINARY 0
#endif

/* http://pubs.opengroup.org/onlinepubs/9699919799/functions/fopen.html */
static const struct {
    ccpc *forms;
    int oflag_base;
} guest_file_open_modes[] = {
    { (ccpc[]){ "r",          NULL }, O_RDONLY                                 },
    { (ccpc[]){ "rb",         NULL }, O_RDONLY                      | O_BINARY },
    { (ccpc[]){ "w",          NULL }, O_WRONLY | O_CREAT | O_TRUNC             },
    { (ccpc[]){ "wb",         NULL }, O_WRONLY | O_CREAT | O_TRUNC  | O_BINARY },
    { (ccpc[]){ "a",          NULL }, O_WRONLY | O_CREAT | O_APPEND            },
    { (ccpc[]){ "ab",         NULL }, O_WRONLY | O_CREAT | O_APPEND | O_BINARY },
    { (ccpc[]){ "r+",         NULL }, O_RDWR                                   },
    { (ccpc[]){ "rb+", "r+b", NULL }, O_RDWR                        | O_BINARY },
    { (ccpc[]){ "w+",         NULL }, O_RDWR   | O_CREAT | O_TRUNC             },
    { (ccpc[]){ "wb+", "w+b", NULL }, O_RDWR   | O_CREAT | O_TRUNC  | O_BINARY },
    { (ccpc[]){ "a+",         NULL }, O_RDWR   | O_CREAT | O_APPEND            },
    { (ccpc[]){ "ab+", "a+b", NULL }, O_RDWR   | O_CREAT | O_APPEND | O_BINARY }
};

static int
find_open_flag(const char *mode_str, Error **errp)
{
    unsigned mode;

    for (mode = 0; mode < ARRAY_SIZE(guest_file_open_modes); ++mode) {
        ccpc *form;

        form = guest_file_open_modes[mode].forms;
        while (*form != NULL && strcmp(*form, mode_str) != 0) {
            ++form;
        }
        if (*form != NULL) {
            break;
        }
    }

    if (mode == ARRAY_SIZE(guest_file_open_modes)) {
        error_setg(errp, "invalid file open mode '%s'", mode_str);
        return -1;
    }
    return guest_file_open_modes[mode].oflag_base | O_NOCTTY | O_NONBLOCK;
}

#define DEFAULT_NEW_FILE_MODE (S_IRUSR | S_IWUSR | \
                               S_IRGRP | S_IWGRP | \
                               S_IROTH | S_IWOTH)

static FILE *
safe_open_or_create(const char *path, const char *mode, Error **errp)
{
    Error *local_err = NULL;
    int oflag;

    oflag = find_open_flag(mode, &local_err);
    if (local_err == NULL) {
        int fd;

        /* If the caller wants / allows creation of a new file, we implement it
         * with a two step process: open() + (open() / fchmod()).
         *
         * First we insist on creating the file exclusively as a new file. If
         * that succeeds, we're free to set any file-mode bits on it. (The
         * motivation is that we want to set those file-mode bits independently
         * of the current umask.)
         *
         * If the exclusive creation fails because the file already exists
         * (EEXIST is not possible for any other reason), we just attempt to
         * open the file, but in this case we won't be allowed to change the
         * file-mode bits on the preexistent file.
         *
         * The pathname should never disappear between the two open()s in
         * practice. If it happens, then someone very likely tried to race us.
         * In this case just go ahead and report the ENOENT from the second
         * open() to the caller.
         *
         * If the caller wants to open a preexistent file, then the first
         * open() is decisive and its third argument is ignored, and the second
         * open() and the fchmod() are never called.
         */
        fd = open(path, oflag | ((oflag & O_CREAT) ? O_EXCL : 0), 0);
        if (fd == -1 && errno == EEXIST) {
            oflag &= ~(unsigned)O_CREAT;
            fd = open(path, oflag);
        }

        if (fd == -1) {
            error_setg_errno(&local_err, errno, "failed to open file '%s' "
                             "(mode: '%s')", path, mode);
        } else {
            qemu_set_cloexec(fd);

            if ((oflag & O_CREAT) && fchmod(fd, DEFAULT_NEW_FILE_MODE) == -1) {
                error_setg_errno(&local_err, errno, "failed to set permission "
                                 "0%03o on new file '%s' (mode: '%s')",
                                 (unsigned)DEFAULT_NEW_FILE_MODE, path, mode);
            } else {
                FILE *f;

                f = fdopen(fd, mode);
                if (f == NULL) {
                    error_setg_errno(&local_err, errno, "failed to associate "
                                     "stdio stream with file descriptor %d, "
                                     "file '%s' (mode: '%s')", fd, path, mode);
                } else {
                    return f;
                }
            }

            close(fd);
            if (oflag & O_CREAT) {
                unlink(path);
            }
        }
    }

    error_propagate(errp, local_err);
    return NULL;
}

int64_t qmp_guest_file_open(const char *path, bool has_mode, const char *mode,
                            Error **errp)
{
    FILE *fh;
    Error *local_err = NULL;
    int fd;
    int64_t ret = -1, handle;

    if (!has_mode) {
        mode = "r";
    }
    slog("guest-file-open called, filepath: %s, mode: %s", path, mode);
    fh = safe_open_or_create(path, mode, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return -1;
    }

    /* set fd non-blocking to avoid common use cases (like reading from a
     * named pipe) from hanging the agent
     */
    fd = fileno(fh);
    ret = fcntl(fd, F_GETFL);
    ret = fcntl(fd, F_SETFL, ret | O_NONBLOCK);
    if (ret == -1) {
        error_setg_errno(errp, errno, "failed to make file '%s' non-blocking",
                         path);
        fclose(fh);
        return -1;
    }

    handle = guest_file_handle_add(fh, errp);
    if (handle < 0) {
        fclose(fh);
        return -1;
    }

    slog("guest-file-open, handle: %" PRId64, handle);
    return handle;
}

void qmp_guest_file_close(int64_t handle, Error **errp)
{
    GuestFileHandle *gfh = guest_file_handle_find(handle, errp);
    int ret;

    slog("guest-file-close called, handle: %" PRId64, handle);
    if (!gfh) {
        return;
    }

    ret = fclose(gfh->fh);
    if (ret == EOF) {
        error_setg_errno(errp, errno, "failed to close handle");
        return;
    }

    QTAILQ_REMOVE(&guest_file_state.filehandles, gfh, next);
    g_free(gfh);
}

struct GuestFileRead *qmp_guest_file_read(int64_t handle, bool has_count,
                                          int64_t count, Error **errp)
{
    GuestFileHandle *gfh = guest_file_handle_find(handle, errp);
    GuestFileRead *read_data = NULL;
    guchar *buf;
    FILE *fh;
    size_t read_count;

    if (!gfh) {
        return NULL;
    }

    if (!has_count) {
        count = QGA_READ_COUNT_DEFAULT;
    } else if (count < 0) {
        error_setg(errp, "value '%" PRId64 "' is invalid for argument count",
                   count);
        return NULL;
    }

    fh = gfh->fh;
    buf = g_malloc0(count+1);
    read_count = fread(buf, 1, count, fh);
    if (ferror(fh)) {
        error_setg_errno(errp, errno, "failed to read file");
        slog("guest-file-read failed, handle: %" PRId64, handle);
    } else {
        buf[read_count] = 0;
        read_data = g_malloc0(sizeof(GuestFileRead));
        read_data->count = read_count;
        read_data->eof = feof(fh);
        if (read_count) {
            read_data->buf_b64 = g_base64_encode(buf, read_count);
        }
    }
    g_free(buf);
    clearerr(fh);

    return read_data;
}

GuestFileWrite *qmp_guest_file_write(int64_t handle, const char *buf_b64,
                                     bool has_count, int64_t count,
                                     Error **errp)
{
    GuestFileWrite *write_data = NULL;
    guchar *buf;
    gsize buf_len;
    int write_count;
    GuestFileHandle *gfh = guest_file_handle_find(handle, errp);
    FILE *fh;

    if (!gfh) {
        return NULL;
    }

    fh = gfh->fh;
    buf = g_base64_decode(buf_b64, &buf_len);

    if (!has_count) {
        count = buf_len;
    } else if (count < 0 || count > buf_len) {
        error_setg(errp, "value '%" PRId64 "' is invalid for argument count",
                   count);
        g_free(buf);
        return NULL;
    }

    write_count = fwrite(buf, 1, count, fh);
    if (ferror(fh)) {
        error_setg_errno(errp, errno, "failed to write to file");
        slog("guest-file-write failed, handle: %" PRId64, handle);
    } else {
        write_data = g_malloc0(sizeof(GuestFileWrite));
        write_data->count = write_count;
        write_data->eof = feof(fh);
    }
    g_free(buf);
    clearerr(fh);

    return write_data;
}

struct GuestFileSeek *qmp_guest_file_seek(int64_t handle, int64_t offset,
                                          int64_t whence, Error **errp)
{
    GuestFileHandle *gfh = guest_file_handle_find(handle, errp);
    GuestFileSeek *seek_data = NULL;
    FILE *fh;
    int ret;

    if (!gfh) {
        return NULL;
    }

    fh = gfh->fh;
    ret = fseek(fh, offset, whence);
    if (ret == -1) {
        error_setg_errno(errp, errno, "failed to seek file");
    } else {
        seek_data = g_new0(GuestFileSeek, 1);
        seek_data->position = ftell(fh);
        seek_data->eof = feof(fh);
    }
    clearerr(fh);

    return seek_data;
}

void qmp_guest_file_flush(int64_t handle, Error **errp)
{
    GuestFileHandle *gfh = guest_file_handle_find(handle, errp);
    FILE *fh;
    int ret;

    if (!gfh) {
        return;
    }

    fh = gfh->fh;
    ret = fflush(fh);
    if (ret == EOF) {
        error_setg_errno(errp, errno, "failed to flush file");
    }
}

static void guest_file_init(void)
{
    QTAILQ_INIT(&guest_file_state.filehandles);
}

/* linux-specific implementations. avoid this if at all possible. */
#if defined(__linux__)

#if defined(CONFIG_FSFREEZE) || defined(CONFIG_FSTRIM)
typedef struct FsMount {
    char *dirname;
    char *devtype;
    QTAILQ_ENTRY(FsMount) next;
} FsMount;

typedef QTAILQ_HEAD(FsMountList, FsMount) FsMountList;

static void free_fs_mount_list(FsMountList *mounts)
{
     FsMount *mount, *temp;

     if (!mounts) {
         return;
     }

     QTAILQ_FOREACH_SAFE(mount, mounts, next, temp) {
         QTAILQ_REMOVE(mounts, mount, next);
         g_free(mount->dirname);
         g_free(mount->devtype);
         g_free(mount);
     }
}

/*
 * Walk the mount table and build a list of local file systems
 */
static void build_fs_mount_list(FsMountList *mounts, Error **errp)
{
    struct mntent *ment;
    FsMount *mount;
    char const *mtab = "/proc/self/mounts";
    FILE *fp;

    fp = setmntent(mtab, "r");
    if (!fp) {
        error_setg(errp, "failed to open mtab file: '%s'", mtab);
        return;
    }

    while ((ment = getmntent(fp))) {
        /*
         * An entry which device name doesn't start with a '/' is
         * either a dummy file system or a network file system.
         * Add special handling for smbfs and cifs as is done by
         * coreutils as well.
         */
        if ((ment->mnt_fsname[0] != '/') ||
            (strcmp(ment->mnt_type, "smbfs") == 0) ||
            (strcmp(ment->mnt_type, "cifs") == 0)) {
            continue;
        }

        mount = g_malloc0(sizeof(FsMount));
        mount->dirname = g_strdup(ment->mnt_dir);
        mount->devtype = g_strdup(ment->mnt_type);

        QTAILQ_INSERT_TAIL(mounts, mount, next);
    }

    endmntent(fp);
}
#endif

#if defined(CONFIG_FSFREEZE)

typedef enum {
    FSFREEZE_HOOK_THAW = 0,
    FSFREEZE_HOOK_FREEZE,
} FsfreezeHookArg;

static const char *fsfreeze_hook_arg_string[] = {
    "thaw",
    "freeze",
};

static void execute_fsfreeze_hook(FsfreezeHookArg arg, Error **errp)
{
    int status;
    pid_t pid;
    const char *hook;
    const char *arg_str = fsfreeze_hook_arg_string[arg];
    Error *local_err = NULL;

    hook = ga_fsfreeze_hook(ga_state);
    if (!hook) {
        return;
    }
    if (access(hook, X_OK) != 0) {
        error_setg_errno(errp, errno, "can't access fsfreeze hook '%s'", hook);
        return;
    }

    slog("executing fsfreeze hook with arg '%s'", arg_str);
    pid = fork();
    if (pid == 0) {
        setsid();
        reopen_fd_to_null(0);
        reopen_fd_to_null(1);
        reopen_fd_to_null(2);

        execle(hook, hook, arg_str, NULL, environ);
        _exit(EXIT_FAILURE);
    } else if (pid < 0) {
        error_setg_errno(errp, errno, "failed to create child process");
        return;
    }

    ga_wait_child(pid, &status, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    if (!WIFEXITED(status)) {
        error_setg(errp, "fsfreeze hook has terminated abnormally");
        return;
    }

    status = WEXITSTATUS(status);
    if (status) {
        error_setg(errp, "fsfreeze hook has failed with status %d", status);
        return;
    }
}

/*
 * Return status of freeze/thaw
 */
GuestFsfreezeStatus qmp_guest_fsfreeze_status(Error **errp)
{
    if (ga_is_frozen(ga_state)) {
        return GUEST_FSFREEZE_STATUS_FROZEN;
    }

    return GUEST_FSFREEZE_STATUS_THAWED;
}

/*
 * Walk list of mounted file systems in the guest, and freeze the ones which
 * are real local file systems.
 */
int64_t qmp_guest_fsfreeze_freeze(Error **errp)
{
    int ret = 0, i = 0;
    FsMountList mounts;
    struct FsMount *mount;
    Error *local_err = NULL;
    int fd;

    slog("guest-fsfreeze called");

    execute_fsfreeze_hook(FSFREEZE_HOOK_FREEZE, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return -1;
    }

    QTAILQ_INIT(&mounts);
    build_fs_mount_list(&mounts, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return -1;
    }

    /* cannot risk guest agent blocking itself on a write in this state */
    ga_set_frozen(ga_state);

    QTAILQ_FOREACH_REVERSE(mount, &mounts, FsMountList, next) {
        fd = qemu_open(mount->dirname, O_RDONLY);
        if (fd == -1) {
            error_setg_errno(errp, errno, "failed to open %s", mount->dirname);
            goto error;
        }

        /* we try to cull filesytems we know won't work in advance, but other
         * filesytems may not implement fsfreeze for less obvious reasons.
         * these will report EOPNOTSUPP. we simply ignore these when tallying
         * the number of frozen filesystems.
         *
         * any other error means a failure to freeze a filesystem we
         * expect to be freezable, so return an error in those cases
         * and return system to thawed state.
         */
        ret = ioctl(fd, FIFREEZE);
        if (ret == -1) {
            if (errno != EOPNOTSUPP) {
                error_setg_errno(errp, errno, "failed to freeze %s",
                                 mount->dirname);
                close(fd);
                goto error;
            }
        } else {
            i++;
        }
        close(fd);
    }

    free_fs_mount_list(&mounts);
    return i;

error:
    free_fs_mount_list(&mounts);
    qmp_guest_fsfreeze_thaw(NULL);
    return 0;
}

/*
 * Walk list of frozen file systems in the guest, and thaw them.
 */
int64_t qmp_guest_fsfreeze_thaw(Error **errp)
{
    int ret;
    FsMountList mounts;
    FsMount *mount;
    int fd, i = 0, logged;
    Error *local_err = NULL;

    QTAILQ_INIT(&mounts);
    build_fs_mount_list(&mounts, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return 0;
    }

    QTAILQ_FOREACH(mount, &mounts, next) {
        logged = false;
        fd = qemu_open(mount->dirname, O_RDONLY);
        if (fd == -1) {
            continue;
        }
        /* we have no way of knowing whether a filesystem was actually unfrozen
         * as a result of a successful call to FITHAW, only that if an error
         * was returned the filesystem was *not* unfrozen by that particular
         * call.
         *
         * since multiple preceding FIFREEZEs require multiple calls to FITHAW
         * to unfreeze, continuing issuing FITHAW until an error is returned,
         * in which case either the filesystem is in an unfreezable state, or,
         * more likely, it was thawed previously (and remains so afterward).
         *
         * also, since the most recent successful call is the one that did
         * the actual unfreeze, we can use this to provide an accurate count
         * of the number of filesystems unfrozen by guest-fsfreeze-thaw, which
         * may * be useful for determining whether a filesystem was unfrozen
         * during the freeze/thaw phase by a process other than qemu-ga.
         */
        do {
            ret = ioctl(fd, FITHAW);
            if (ret == 0 && !logged) {
                i++;
                logged = true;
            }
        } while (ret == 0);
        close(fd);
    }

    ga_unset_frozen(ga_state);
    free_fs_mount_list(&mounts);

    execute_fsfreeze_hook(FSFREEZE_HOOK_THAW, errp);

    return i;
}

static void guest_fsfreeze_cleanup(void)
{
    Error *err = NULL;

    if (ga_is_frozen(ga_state) == GUEST_FSFREEZE_STATUS_FROZEN) {
        qmp_guest_fsfreeze_thaw(&err);
        if (err) {
            slog("failed to clean up frozen filesystems: %s",
                 error_get_pretty(err));
            error_free(err);
        }
    }
}
#endif /* CONFIG_FSFREEZE */

#if defined(CONFIG_FSTRIM)
/*
 * Walk list of mounted file systems in the guest, and trim them.
 */
void qmp_guest_fstrim(bool has_minimum, int64_t minimum, Error **errp)
{
    int ret = 0;
    FsMountList mounts;
    struct FsMount *mount;
    int fd;
    Error *local_err = NULL;
    struct fstrim_range r = {
        .start = 0,
        .len = -1,
        .minlen = has_minimum ? minimum : 0,
    };

    slog("guest-fstrim called");

    QTAILQ_INIT(&mounts);
    build_fs_mount_list(&mounts, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    QTAILQ_FOREACH(mount, &mounts, next) {
        fd = qemu_open(mount->dirname, O_RDONLY);
        if (fd == -1) {
            error_setg_errno(errp, errno, "failed to open %s", mount->dirname);
            goto error;
        }

        /* We try to cull filesytems we know won't work in advance, but other
         * filesytems may not implement fstrim for less obvious reasons.  These
         * will report EOPNOTSUPP; we simply ignore these errors.  Any other
         * error means an unexpected error, so return it in those cases.  In
         * some other cases ENOTTY will be reported (e.g. CD-ROMs).
         */
        ret = ioctl(fd, FITRIM, &r);
        if (ret == -1) {
            if (errno != ENOTTY && errno != EOPNOTSUPP) {
                error_setg_errno(errp, errno, "failed to trim %s",
                                 mount->dirname);
                close(fd);
                goto error;
            }
        }
        close(fd);
    }

error:
    free_fs_mount_list(&mounts);
}
#endif /* CONFIG_FSTRIM */


#define LINUX_SYS_STATE_FILE "/sys/power/state"
#define SUSPEND_SUPPORTED 0
#define SUSPEND_NOT_SUPPORTED 1

static void bios_supports_mode(const char *pmutils_bin, const char *pmutils_arg,
                               const char *sysfile_str, Error **errp)
{
    Error *local_err = NULL;
    char *pmutils_path;
    pid_t pid;
    int status;

    pmutils_path = g_find_program_in_path(pmutils_bin);

    pid = fork();
    if (!pid) {
        char buf[32]; /* hopefully big enough */
        ssize_t ret;
        int fd;

        setsid();
        reopen_fd_to_null(0);
        reopen_fd_to_null(1);
        reopen_fd_to_null(2);

        if (pmutils_path) {
            execle(pmutils_path, pmutils_bin, pmutils_arg, NULL, environ);
        }

        /*
         * If we get here either pm-utils is not installed or execle() has
         * failed. Let's try the manual method if the caller wants it.
         */

        if (!sysfile_str) {
            _exit(SUSPEND_NOT_SUPPORTED);
        }

        fd = open(LINUX_SYS_STATE_FILE, O_RDONLY);
        if (fd < 0) {
            _exit(SUSPEND_NOT_SUPPORTED);
        }

        ret = read(fd, buf, sizeof(buf)-1);
        if (ret <= 0) {
            _exit(SUSPEND_NOT_SUPPORTED);
        }
        buf[ret] = '\0';

        if (strstr(buf, sysfile_str)) {
            _exit(SUSPEND_SUPPORTED);
        }

        _exit(SUSPEND_NOT_SUPPORTED);
    } else if (pid < 0) {
        error_setg_errno(errp, errno, "failed to create child process");
        goto out;
    }

    ga_wait_child(pid, &status, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto out;
    }

    if (!WIFEXITED(status)) {
        error_setg(errp, "child process has terminated abnormally");
        goto out;
    }

    switch (WEXITSTATUS(status)) {
    case SUSPEND_SUPPORTED:
        goto out;
    case SUSPEND_NOT_SUPPORTED:
        error_setg(errp,
                   "the requested suspend mode is not supported by the guest");
        goto out;
    default:
        error_setg(errp,
                   "the helper program '%s' returned an unexpected exit status"
                   " code (%d)", pmutils_path, WEXITSTATUS(status));
        goto out;
    }

out:
    g_free(pmutils_path);
}

static void guest_suspend(const char *pmutils_bin, const char *sysfile_str,
                          Error **errp)
{
    Error *local_err = NULL;
    char *pmutils_path;
    pid_t pid;
    int status;

    pmutils_path = g_find_program_in_path(pmutils_bin);

    pid = fork();
    if (pid == 0) {
        /* child */
        int fd;

        setsid();
        reopen_fd_to_null(0);
        reopen_fd_to_null(1);
        reopen_fd_to_null(2);

        if (pmutils_path) {
            execle(pmutils_path, pmutils_bin, NULL, environ);
        }

        /*
         * If we get here either pm-utils is not installed or execle() has
         * failed. Let's try the manual method if the caller wants it.
         */

        if (!sysfile_str) {
            _exit(EXIT_FAILURE);
        }

        fd = open(LINUX_SYS_STATE_FILE, O_WRONLY);
        if (fd < 0) {
            _exit(EXIT_FAILURE);
        }

        if (write(fd, sysfile_str, strlen(sysfile_str)) < 0) {
            _exit(EXIT_FAILURE);
        }

        _exit(EXIT_SUCCESS);
    } else if (pid < 0) {
        error_setg_errno(errp, errno, "failed to create child process");
        goto out;
    }

    ga_wait_child(pid, &status, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto out;
    }

    if (!WIFEXITED(status)) {
        error_setg(errp, "child process has terminated abnormally");
        goto out;
    }

    if (WEXITSTATUS(status)) {
        error_setg(errp, "child process has failed to suspend");
        goto out;
    }

out:
    g_free(pmutils_path);
}

void qmp_guest_suspend_disk(Error **errp)
{
    Error *local_err = NULL;

    bios_supports_mode("pm-is-supported", "--hibernate", "disk", &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    guest_suspend("pm-hibernate", "disk", errp);
}

void qmp_guest_suspend_ram(Error **errp)
{
    Error *local_err = NULL;

    bios_supports_mode("pm-is-supported", "--suspend", "mem", &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    guest_suspend("pm-suspend", "mem", errp);
}

void qmp_guest_suspend_hybrid(Error **errp)
{
    Error *local_err = NULL;

    bios_supports_mode("pm-is-supported", "--suspend-hybrid", NULL,
                       &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    guest_suspend("pm-suspend-hybrid", NULL, errp);
}

static GuestNetworkInterfaceList *
guest_find_interface(GuestNetworkInterfaceList *head,
                     const char *name)
{
    for (; head; head = head->next) {
        if (strcmp(head->value->name, name) == 0) {
            break;
        }
    }

    return head;
}

/*
 * Build information about guest interfaces
 */
GuestNetworkInterfaceList *qmp_guest_network_get_interfaces(Error **errp)
{
    GuestNetworkInterfaceList *head = NULL, *cur_item = NULL;
    struct ifaddrs *ifap, *ifa;

    if (getifaddrs(&ifap) < 0) {
        error_setg_errno(errp, errno, "getifaddrs failed");
        goto error;
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        GuestNetworkInterfaceList *info;
        GuestIpAddressList **address_list = NULL, *address_item = NULL;
        char addr4[INET_ADDRSTRLEN];
        char addr6[INET6_ADDRSTRLEN];
        int sock;
        struct ifreq ifr;
        unsigned char *mac_addr;
        void *p;

        g_debug("Processing %s interface", ifa->ifa_name);

        info = guest_find_interface(head, ifa->ifa_name);

        if (!info) {
            info = g_malloc0(sizeof(*info));
            info->value = g_malloc0(sizeof(*info->value));
            info->value->name = g_strdup(ifa->ifa_name);

            if (!cur_item) {
                head = cur_item = info;
            } else {
                cur_item->next = info;
                cur_item = info;
            }
        }

        if (!info->value->has_hardware_address &&
            ifa->ifa_flags & SIOCGIFHWADDR) {
            /* we haven't obtained HW address yet */
            sock = socket(PF_INET, SOCK_STREAM, 0);
            if (sock == -1) {
                error_setg_errno(errp, errno, "failed to create socket");
                goto error;
            }

            memset(&ifr, 0, sizeof(ifr));
            pstrcpy(ifr.ifr_name, IF_NAMESIZE, info->value->name);
            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
                error_setg_errno(errp, errno,
                                 "failed to get MAC address of %s",
                                 ifa->ifa_name);
                close(sock);
                goto error;
            }

            close(sock);
            mac_addr = (unsigned char *) &ifr.ifr_hwaddr.sa_data;

            info->value->hardware_address =
                g_strdup_printf("%02x:%02x:%02x:%02x:%02x:%02x",
                                (int) mac_addr[0], (int) mac_addr[1],
                                (int) mac_addr[2], (int) mac_addr[3],
                                (int) mac_addr[4], (int) mac_addr[5]);

            info->value->has_hardware_address = true;
        }

        if (ifa->ifa_addr &&
            ifa->ifa_addr->sa_family == AF_INET) {
            /* interface with IPv4 address */
            p = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            if (!inet_ntop(AF_INET, p, addr4, sizeof(addr4))) {
                error_setg_errno(errp, errno, "inet_ntop failed");
                goto error;
            }

            address_item = g_malloc0(sizeof(*address_item));
            address_item->value = g_malloc0(sizeof(*address_item->value));
            address_item->value->ip_address = g_strdup(addr4);
            address_item->value->ip_address_type = GUEST_IP_ADDRESS_TYPE_IPV4;

            if (ifa->ifa_netmask) {
                /* Count the number of set bits in netmask.
                 * This is safe as '1' and '0' cannot be shuffled in netmask. */
                p = &((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
                address_item->value->prefix = ctpop32(((uint32_t *) p)[0]);
            }
        } else if (ifa->ifa_addr &&
                   ifa->ifa_addr->sa_family == AF_INET6) {
            /* interface with IPv6 address */
            p = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            if (!inet_ntop(AF_INET6, p, addr6, sizeof(addr6))) {
                error_setg_errno(errp, errno, "inet_ntop failed");
                goto error;
            }

            address_item = g_malloc0(sizeof(*address_item));
            address_item->value = g_malloc0(sizeof(*address_item->value));
            address_item->value->ip_address = g_strdup(addr6);
            address_item->value->ip_address_type = GUEST_IP_ADDRESS_TYPE_IPV6;

            if (ifa->ifa_netmask) {
                /* Count the number of set bits in netmask.
                 * This is safe as '1' and '0' cannot be shuffled in netmask. */
                p = &((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr;
                address_item->value->prefix =
                    ctpop32(((uint32_t *) p)[0]) +
                    ctpop32(((uint32_t *) p)[1]) +
                    ctpop32(((uint32_t *) p)[2]) +
                    ctpop32(((uint32_t *) p)[3]);
            }
        }

        if (!address_item) {
            continue;
        }

        address_list = &info->value->ip_addresses;

        while (*address_list && (*address_list)->next) {
            address_list = &(*address_list)->next;
        }

        if (!*address_list) {
            *address_list = address_item;
        } else {
            (*address_list)->next = address_item;
        }

        info->value->has_ip_addresses = true;


    }

    freeifaddrs(ifap);
    return head;

error:
    freeifaddrs(ifap);
    qapi_free_GuestNetworkInterfaceList(head);
    return NULL;
}

static void set_interface(GuestNetworkInterface *interface, Error **errp)
{
    GuestIpAddressList *address_item = NULL;
    GuestIpAddress *address = NULL;
    struct ifreq ifr;
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    struct ifreq ifr_msk;
    struct sockaddr_in *sin_msk = (struct sockaddr_in *)&ifr_msk.ifr_addr;
    int sock = 0;

    for (address_item = interface->ip_addresses; address_item;
            address_item = address_item->next) {

        address = address_item->value;
        if (address->ip_address_type == GUEST_IP_ADDRESS_TYPE_IPV4) {
            break;
        }
    }

    if (address_item == NULL) {
        error_setg(errp, "no IPv4 address for interface %s",
                   interface->name);
        return;
    }
    g_debug("setting %s interface address to %s/%" PRId64, interface->name,
            address->ip_address, address->prefix);

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, interface->name, IFNAMSIZ - 1);
    memset(&ifr_msk, 0, sizeof ifr_msk);
    strncpy(ifr_msk.ifr_name, interface->name, IFNAMSIZ - 1);

    sin->sin_family = AF_INET;
    if (!inet_pton(AF_INET, address->ip_address, &sin->sin_addr)) {
        error_setg_errno(errp, errno, "failed to convert address %s",
                         address->ip_address);
        return;
    }
    sin_msk->sin_family = AF_INET;
    sin_msk->sin_addr.s_addr = \
            htonl(0xFFFFFFFF & (0xFFFFFFFF << (32 - address->prefix)));

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        error_setg_errno(errp, errno, "failed to create socket");
        return;
    }

    if (ioctl(sock, SIOCSIFADDR, &ifr) == -1) {
        error_setg_errno(errp, errno, "failed to set address %s",
                         address->ip_address);
        close(sock);
        return;
    }

    if (ioctl(sock, SIOCSIFNETMASK, &ifr_msk) == -1) {
        error_setg_errno(errp, errno, "failed to set netmask length %" PRId64,
                         address->prefix);
        close(sock);
        return;
    }

    close(sock);
}

GuestSystemInfo *qmp_guest_get_system(Error **err)
{
    GuestSystemInfo *info;
    info = g_malloc(sizeof(GuestSystemInfo));
    info->system = g_malloc(64);
    memset(info->system, 0 , 64);
    sprintf(info->system, "Linux");
    return info;
}

int64_t qmp_guest_network_set_interfaces(GuestNetworkInterfaceList *interfaces,
                                         Error **errp)
{
    struct ifaddrs *ifap, *ifa;
    int64_t processed;
    Error *local_err = NULL;

    if (getifaddrs(&ifap) < 0) {
        error_setg_errno(errp, errno, "getifaddrs failed");
        goto error;
    }

    processed = 0;
    while (interfaces != NULL) {
        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (strcmp(ifa->ifa_name, interfaces->value->name) == 0) {
                break;
            }
        }
        if (ifa == NULL) {
            error_setg(errp, "interface %s not found",
                       interfaces->value->name);
            break;
        }

        g_debug("Processing %s interface", ifa->ifa_name);

        set_interface(interfaces->value, &local_err);
        if (local_err != NULL) {
            break;
        }
        ++processed;
        interfaces = interfaces->next;
    }

    if (local_err != NULL) {
        if (processed == 0) {
            error_propagate(errp, local_err);
        } else {
            error_free(local_err);
        }
    }

    return processed;

error:
    freeifaddrs(ifap);
    error_propagate(errp, local_err);
    return -1;
}

#define SYSCONF_EXACT(name, errp) sysconf_exact((name), #name, (errp))

static long sysconf_exact(int name, const char *name_str, Error **errp)
{
    long ret;

    errno = 0;
    ret = sysconf(name);
    if (ret == -1) {
        if (errno == 0) {
            error_setg(errp, "sysconf(%s): value indefinite", name_str);
        } else {
            error_setg_errno(errp, errno, "sysconf(%s)", name_str);
        }
    }
    return ret;
}

/* Transfer online/offline status between @vcpu and the guest system.
 *
 * On input either @errp or *@errp must be NULL.
 *
 * In system-to-@vcpu direction, the following @vcpu fields are accessed:
 * - R: vcpu->logical_id
 * - W: vcpu->online
 * - W: vcpu->can_offline
 *
 * In @vcpu-to-system direction, the following @vcpu fields are accessed:
 * - R: vcpu->logical_id
 * - R: vcpu->online
 *
 * Written members remain unmodified on error.
 */
static void transfer_vcpu(GuestLogicalProcessor *vcpu, bool sys2vcpu,
                          Error **errp)
{
    char *dirpath;
    int dirfd;

    dirpath = g_strdup_printf("/sys/devices/system/cpu/cpu%" PRId64 "/",
                              vcpu->logical_id);
    dirfd = open(dirpath, O_RDONLY | O_DIRECTORY);
    if (dirfd == -1) {
        error_setg_errno(errp, errno, "open(\"%s\")", dirpath);
    } else {
        static const char fn[] = "online";
        int fd;
        int res;

        fd = openat(dirfd, fn, sys2vcpu ? O_RDONLY : O_RDWR);
        if (fd == -1) {
            if (errno != ENOENT) {
                error_setg_errno(errp, errno, "open(\"%s/%s\")", dirpath, fn);
            } else if (sys2vcpu) {
                vcpu->online = true;
                vcpu->can_offline = false;
            } else if (!vcpu->online) {
                error_setg(errp, "logical processor #%" PRId64 " can't be "
                           "offlined", vcpu->logical_id);
            } /* otherwise pretend successful re-onlining */
        } else {
            unsigned char status;

            res = pread(fd, &status, 1, 0);
            if (res == -1) {
                error_setg_errno(errp, errno, "pread(\"%s/%s\")", dirpath, fn);
            } else if (res == 0) {
                error_setg(errp, "pread(\"%s/%s\"): unexpected EOF", dirpath,
                           fn);
            } else if (sys2vcpu) {
                vcpu->online = (status != '0');
                vcpu->can_offline = true;
            } else if (vcpu->online != (status != '0')) {
                status = '0' + vcpu->online;
                if (pwrite(fd, &status, 1, 0) == -1) {
                    error_setg_errno(errp, errno, "pwrite(\"%s/%s\")", dirpath,
                                     fn);
                }
            } /* otherwise pretend successful re-(on|off)-lining */

            res = close(fd);
            g_assert(res == 0);
        }

        res = close(dirfd);
        g_assert(res == 0);
    }

    g_free(dirpath);
}

GuestLogicalProcessorList *qmp_guest_get_vcpus(Error **errp)
{
    int64_t current;
    GuestLogicalProcessorList *head, **link;
    long sc_max;
    Error *local_err = NULL;

    current = 0;
    head = NULL;
    link = &head;
    sc_max = SYSCONF_EXACT(_SC_NPROCESSORS_CONF, &local_err);

    while (local_err == NULL && current < sc_max) {
        GuestLogicalProcessor *vcpu;
        GuestLogicalProcessorList *entry;

        vcpu = g_malloc0(sizeof *vcpu);
        vcpu->logical_id = current++;
        vcpu->has_can_offline = true; /* lolspeak ftw */
        transfer_vcpu(vcpu, true, &local_err);

        entry = g_malloc0(sizeof *entry);
        entry->value = vcpu;

        *link = entry;
        link = &entry->next;
    }

    if (local_err == NULL) {
        /* there's no guest with zero VCPUs */
        g_assert(head != NULL);
        return head;
    }

    qapi_free_GuestLogicalProcessorList(head);
    error_propagate(errp, local_err);
    return NULL;
}

int64_t qmp_guest_set_vcpus(GuestLogicalProcessorList *vcpus, Error **errp)
{
    int64_t processed;
    Error *local_err = NULL;

    processed = 0;
    while (vcpus != NULL) {
        transfer_vcpu(vcpus->value, false, &local_err);
        if (local_err != NULL) {
            break;
        }
        ++processed;
        vcpus = vcpus->next;
    }

    if (local_err != NULL) {
        if (processed == 0) {
            error_propagate(errp, local_err);
        } else {
            error_free(local_err);
        }
    }

    return processed;
}

GuestStats *qmp_guest_get_stats(Error **errp)
{
    Error *local_err = NULL;
    GuestStats *stats = NULL;
    GuestVCPUStats *vcpu = NULL;
    GuestVCPUStatsList **vcpu_link = NULL;
    GuestVCPUStatsList *vcpu_entry = NULL;
#define CPU_TIME_COLUMNS 9
    uint64_t cpu_time[CPU_TIME_COLUMNS];
    char *block_name = NULL;
    GuestBlockStats *block = NULL;
    GuestBlockStatsList **block_link = NULL;
    GuestBlockStatsList *block_entry = NULL;
#define BLOCK_STAT_COLUMNS 11
    uint64_t block_stats[BLOCK_STAT_COLUMNS];
    GuestInterfaceStats *interface = NULL;
    GuestInterfaceStatsList **interface_link = NULL;
    GuestInterfaceStatsList *interface_entry = NULL;
    struct ifaddrs *ifap = 0, *ifa = 0;
    int sock;
    struct ifreq ifr;
    unsigned char *mac_addr;
    FILE *fp = NULL;
#define BUFSIZE 512
    char buf[BUFSIZE];
    char dummy[BUFSIZE];
    char filename[BUFSIZE];
    int i;
    DIR *dir;
    struct dirent *ent;
    int ret_value = 0;

    stats = g_malloc0(sizeof *stats);

    /* get cpu stats */
    g_debug("Processing VCPUs");
    vcpu_link = &stats->vcpu;
    fp = fopen("/proc/stat", "r");
    if (fp == NULL) {
        error_setg_errno(&local_err, errno, "open(\"/proc/stat\")");
        goto error;
    }
    while (fgets(buf, sizeof buf, fp)) {
        if (strncmp(buf, "intr", 4) == 0) {
            break;
        }
        if (strncmp(buf, "cpu ", 4) == 0) {
            continue;
        }

        vcpu = g_malloc0(sizeof *vcpu);
        sscanf(buf, "cpu%" PRIu64
               " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
               " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
               " %" PRIu64,
               &vcpu->processor,
               cpu_time, cpu_time + 1, cpu_time + 2, cpu_time + 3,
               cpu_time + 4, cpu_time + 5, cpu_time + 6, cpu_time + 7,
               cpu_time + 8);

        vcpu->idle_time = cpu_time[3];
        vcpu->total_time = 0;
        for (i = 0; i < 9; ++i) {
            vcpu->total_time += cpu_time[i];
        }

        vcpu_entry = g_malloc0(sizeof *vcpu_entry);
        vcpu_entry->value = vcpu;

        *vcpu_link = vcpu_entry;
        vcpu_link = &vcpu_entry->next;
    }
    fclose(fp);

    /* get memory stats */
    g_debug("Processing memory");
    stats->memory = g_malloc0(sizeof *stats->memory);
    fp = fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        error_setg_errno(&local_err, errno, "open(\"/proc/meminfo\")");
        goto error;
    }
    if (fgets(buf, sizeof buf, fp)) {
        sscanf(buf, "%s %" PRIu64, dummy, &stats->memory->mem_total);
    } else {
        error_setg_errno(&local_err, errno, "fgets()");
        fclose(fp);
        goto error;
    }
    if (fgets(buf, sizeof buf, fp)) {
        sscanf(buf, "%s %" PRIu64, dummy, &stats->memory->mem_free);
    } else {
        error_setg_errno(&local_err, errno, "fgets()");
        fclose(fp);
        goto error;
    }
    fclose(fp);

    /* get block stats */
    g_debug("Processing block devices");
    block_link = &stats->disk;
    if ((dir = opendir("/sys/block"))) {
        while ((ent = readdir(dir))) {
            block_name = ent->d_name;
            if (strncmp(block_name, "sd", 2) &&
                    strncmp(block_name, "vd", 2) &&
                    strncmp(block_name, "hd", 2) &&
                    strncmp(block_name, "xvd", 3)) {

                /* skips everything else */
                continue;
            }
            memset(filename, 0, sizeof filename);
            snprintf(filename, BUFSIZE, "/sys/block/%s/queue/hw_sector_size",
                     block_name);
            fp = fopen(filename, "r");
            if (fp == NULL) {
                continue;
            }

            block = g_malloc0(sizeof *block);
            block->dev = g_strdup(block_name);
            ret_value = fscanf(fp, "%" PRIu64, &block->sector_size);
            if (-1 == ret_value) {
                error_setg_errno(&local_err, errno, "fscanf()");
            }
            fclose(fp);

            memset(filename, 0, sizeof filename);
            snprintf(filename, BUFSIZE, "/sys/block/%s/stat", block_name);
            fp = fopen(filename, "r");
            if (fp == NULL) {
                error_setg_errno(&local_err, errno, "open(\"%s\")", filename);
                qapi_free_GuestBlockStats(block);
                goto error;
            }
            ret_value = fscanf(fp,
                         " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                         " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                         " %" PRIu64 " %" PRIu64 " %" PRIu64,
                         block_stats, block_stats + 1, block_stats + 2,
                         block_stats + 3, block_stats + 4, block_stats + 5,
                         block_stats + 6, block_stats + 7, block_stats + 8,
                         block_stats + 9, block_stats + 10);
            if (-1 == ret_value) {
                error_setg_errno(&local_err, errno, "fscanf()");
            }
            fclose(fp);

            block->reads = block_stats[0];
            block->rd_sectors = block_stats[2];
            block->writes = block_stats[4];
            block->wr_sectors = block_stats[6];

            block_entry = g_malloc0(sizeof *block_entry);
            block_entry->value = block;

            *block_link = block_entry;
            block_link = &block_entry->next;
        }
        closedir (dir);
    } else {
        error_setg_errno(errp, errno, "opendir() failed");
        goto error;
    }

    /* get interface stats */
    g_debug("Processing interfaces");
    interface_link = &stats->interfaces;
    if (getifaddrs(&ifap) < 0) {
        error_setg_errno(errp, errno, "getifaddrs failed");
        goto error;
    }
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, "lo") == 0) {
            continue;
        }
        for (interface_entry = stats->interfaces; interface_entry;
                interface_entry = interface_entry->next) {
            if (strcmp(interface_entry->value->name, ifa->ifa_name) == 0) {
                break;
            }
        }

        if (!interface_entry) {
            interface = g_malloc0(sizeof *interface);
            interface_entry = g_malloc0(sizeof *interface_entry);
            interface_entry->value = interface;
            interface->name = g_strdup(ifa->ifa_name);

            *interface_link = interface_entry;
            interface_link = &interface_entry->next;

#define GET_INTERFACE_STATS(x) \
do { \
    memset(filename, 0, sizeof filename); \
    snprintf(filename, BUFSIZE, "/sys/class/net/%s/statistics/" #x, \
            ifa->ifa_name); \
    fp = fopen(filename, "r"); \
    if (fp == NULL) { \
        error_setg_errno(&local_err, errno, "open(\"%s\")", filename); \
        goto error; \
    } \
    ret_value = fscanf(fp, "%" PRIu64, &interface->x); \
    fclose(fp); \
} while (0)

            GET_INTERFACE_STATS(rx_bytes);
            GET_INTERFACE_STATS(rx_dropped);
            GET_INTERFACE_STATS(rx_errors);
            GET_INTERFACE_STATS(rx_packets);
            GET_INTERFACE_STATS(tx_bytes);
            GET_INTERFACE_STATS(tx_dropped);
            GET_INTERFACE_STATS(tx_errors);
            GET_INTERFACE_STATS(tx_packets);
        }

        if (ifa->ifa_flags & SIOCGIFHWADDR) {
            sock = socket(PF_INET, SOCK_STREAM, 0);
            if (sock == -1) {
                error_setg_errno(errp, errno, "failed to create socket");
                goto error;
            }

            memset(&ifr, 0, sizeof(ifr));
            pstrcpy(ifr.ifr_name, IF_NAMESIZE, interface->name);
            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
                error_setg_errno(errp, errno,
                                 "failed to get MAC address of %s",
                                 ifa->ifa_name);
                close(sock);
                goto error;
            }

            close(sock);

            mac_addr = (unsigned char *) &ifr.ifr_hwaddr.sa_data;
            interface->hardware_address =
                    g_strdup_printf("%02x:%02x:%02x:%02x:%02x:%02x",
                                    (int) mac_addr[0], (int) mac_addr[1],
                                    (int) mac_addr[2], (int) mac_addr[3],
                                    (int) mac_addr[4], (int) mac_addr[5]);
        }
    }
    freeifaddrs(ifap);

    stats->timestamp = time(0);

    return stats;

error:
    freeifaddrs(ifap);
    qapi_free_GuestStats(stats);
    error_propagate(errp, local_err);
    return NULL;
}

int64_t qmp_guest_init(const char *hostname, const char *ctrl_device,
                       const char *ctrl_mac, const char *ctrl_ip_address,
                       const char *srv_device, const char *srv_mac,
                       const char *init_password, const char *hypervisor_ip,
                       Error **errp)
{
    int status;
    Error *local_err = NULL;
    pid_t pid;

    if (!hostname[0] || !ctrl_device[0] || !ctrl_mac[0] ||
            !ctrl_ip_address[0] || !srv_device[0] || !srv_mac[0] ||
            !init_password[0] || !hypervisor_ip[0]) {
        error_setg(errp, "Illegal parameters");
        return -1;
    }

    g_debug("guest-init called");
    g_debug("hostname: %s", hostname);
    g_debug("ctrl_device: %s", ctrl_device);
    g_debug("ctrl_mac: %s", ctrl_mac);
    g_debug("ctrl_ip_address: %s", ctrl_ip_address);
    g_debug("srv_device: %s", srv_device);
    g_debug("srv_mac: %s", srv_mac);
    g_debug("init_password: %s", init_password);
    g_debug("hypervisor_ip: %s", hypervisor_ip);

    pid = fork();
    if (pid == 0) {
        setsid();
        reopen_fd_to_null(0);
        reopen_fd_to_null(1);
        reopen_fd_to_null(2);

        execle("/etc/vm_init.sh", "vm_init.sh", hostname, ctrl_device,
               ctrl_ip_address, ctrl_mac, srv_device, srv_mac, init_password,
               hypervisor_ip, NULL, environ);
        _exit(EXIT_FAILURE);
    } else if (pid < 0) {
        error_setg_errno(errp, errno, "failed to create child process");
        return -1;
    }

    ga_wait_child(pid, &status, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return -1;
    }

    if (!WIFEXITED(status)) {
        error_setg(errp, "child process has terminated abnormally");
        return -1;
    }

    if (WEXITSTATUS(status)) {
        error_setg(errp, "VM init script failed");
        return -1;
    }

    return 0;
}

int64_t qmp_guest_network_set_gateway(const char* ip, Error **errp)
{
    int fd = 0;
    struct sockaddr_in sin;
    struct rtentry rtadd;
    struct rtentry rtdel;

    memset(&sin, 0x00, sizeof(sin));
    memset(&rtadd, 0x00, sizeof(rtadd));
    memset(&rtdel, 0x00, sizeof(rtdel));

    g_debug("guest-network-set-gateway called");

    if (!ip[0]) {
        error_setg(errp, "Illegal parameters");
        return -1;
    }

    g_debug("gateway: %s", ip);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        error_setg(errp, "socket create error");
        return -1;
    }

    /* RTF_GATEWAT: destination is a gateway
     * rt_gateway : gateway addr
     * rt_dst     : target address
     * rt_genmask : target network mask
     */

    rtdel.rt_flags = RTF_GATEWAY;
    ((struct sockaddr_in *)&rtdel.rt_dst)->sin_family = AF_INET;
    ((struct sockaddr_in *)&rtdel.rt_genmask)->sin_family = AF_INET;
    // delete all gateway
    while (ioctl(fd, SIOCDELRT, &rtdel) != -1);

    rtadd.rt_flags = RTF_GATEWAY;
    sin.sin_family = AF_INET;
    if (inet_aton(ip, &sin.sin_addr) == 0) {
        error_setg(errp, "inet_aton error");
    }
    memcpy(&rtadd.rt_gateway, &sin, sizeof(sin));
    ((struct sockaddr_in *)&rtadd.rt_dst)->sin_family = AF_INET;
    ((struct sockaddr_in *)&rtadd.rt_genmask)->sin_family = AF_INET;
    // add gateway
    if (ioctl(fd, SIOCADDRT, &rtadd) == -1) {
        error_setg(errp, "%s", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

ListenerConnInfoList *qmp_guest_get_lb_conn_info(Error **errp)
{
#define NAMELEN 100
#define BUFSIZE 512
#define SOCK_KEY "stats socket"
#define CONF_FILE "/etc/haproxy/haproxy.cfg"
#define STAT_ARGS_1_PRE " echo show stat -1 1 -1 | nc -U "
#define STAT_ARGS_4_PRE " echo show stat -1 4 -1 | nc -U "
#define STAT_ARGS_SUF " &&"
#define LIS_PRE "echo \"` ("
#define LIS_SUF " ) | grep -vE \'(^#.*)|(^$)\' | awk -F\',\' " \
                "\'{print $1, $34}\' `\" | sort | awk \'{a[$1]+=$2}END" \
                "{for(i in a)print i, a[i]}\'"
#define SER_PRE "echo \"` ("
#define SER_MID " ) | grep "
#define SER_SUF " | grep -v \'^$\' | awk -F\',\' \'{print $2,$34}\' `\" | " \
                "sort | awk \'{a[$1]+=$2}END{for(i in a)print i,a[i]}\'"

    char buf[BUFSIZE];
    char name[NAMELEN];
    char sockfile[BUFSIZE];
    char stat_args_1[BUFSIZE*BUFSIZE];
    char stat_args_4[BUFSIZE*BUFSIZE];
    char cmd[BUFSIZE*BUFSIZE+BUFSIZE];
    char ret[BUFSIZE*BUFSIZE+BUFSIZE];
    uint32_t conn_num               = 0;
    FILE *fp                        = NULL;
    BackVMConnInfo *bkvminfo        = NULL;
    BackVMConnInfoList *bkvm_head   = NULL;
    BackVMConnInfoList *bkvm_enty   = NULL;
    BackVMConnInfoList **bkvm_link  = NULL;
    ListenerConnInfo *lisinfo       = NULL;
    ListenerConnInfoList *lis_head  = NULL;
    ListenerConnInfoList *lis_enty  = NULL;
    ListenerConnInfoList **lis_link = NULL;

    memset(buf, 0x00, sizeof(buf));
    memset(cmd, 0x00, sizeof(cmd));
    memset(ret, 0x00, sizeof(ret));
    memset(name, 0x00, sizeof(name));
    memset(sockfile, 0x00, sizeof(sockfile));
    memset(stat_args_1, 0x00, sizeof(stat_args_1));
    memset(stat_args_4, 0x00, sizeof(stat_args_4));

    lis_link = &lis_head;

    fp = fopen(CONF_FILE, "r");
    if (fp == NULL) {
        g_debug("open config file failed: %s", strerror(errno));
        return lis_head;
    }

    memset(buf, 0x00, sizeof(buf));
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strstr(buf, SOCK_KEY) != NULL) {
            // sock file in this line
            memset(sockfile, 0x00, sizeof(sockfile));
            sscanf(buf, "%*s%*s%s", sockfile);
            strcat(stat_args_1, STAT_ARGS_1_PRE);
            strcat(stat_args_4, STAT_ARGS_4_PRE);
            strcat(stat_args_1, sockfile);
            strcat(stat_args_4, sockfile);
            strcat(stat_args_1, STAT_ARGS_SUF);
            strcat(stat_args_4, STAT_ARGS_SUF);
        }
        memset(buf, 0x00, sizeof(buf));
    }

    fclose(fp);

    if (stat_args_1[0] == 0x00) {
        g_debug("sock file not found");
        return lis_head;
    }

    stat_args_1[strlen(stat_args_1)-sizeof(STAT_ARGS_SUF)+1] = '\0';
    stat_args_4[strlen(stat_args_4)-sizeof(STAT_ARGS_SUF)+1] = '\0';
    memset(cmd, 0x00, sizeof(cmd));
    strcat(cmd, LIS_PRE);
    strcat(cmd, stat_args_1);
    strcat(cmd, LIS_SUF);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        g_debug("popen failed: %s", strerror(errno));
        return lis_head;
    }

    memset(buf, 0x00, sizeof(buf));
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        conn_num = 0;
        memset(name, 0x00, sizeof(name));
        sscanf(buf, "%s %d", name, &conn_num);
        lisinfo = g_malloc0(sizeof(*lisinfo));
        lisinfo->name = g_strdup(name);
        lisinfo->conn_num = conn_num;
        lis_enty = g_malloc0(sizeof(*lis_enty));
        lis_enty->value = lisinfo;
        lis_enty->next = NULL;

        *lis_link = lis_enty;
        lis_link = &lis_enty->next;
    }

    pclose(fp);

    lis_enty = lis_head;
    while (lis_enty != NULL) {
        memset(cmd, 0x00, sizeof(cmd));
        strcat(cmd, SER_PRE);
        strcat(cmd, stat_args_4);
        strcat(cmd, SER_MID);
        strcat(cmd, lis_enty->value->name);
        strcat(cmd, SER_SUF);
        fp = popen(cmd, "r");
        if (fp == NULL) {
             g_debug("server stat popen failed: %s", strerror(errno));
             lis_enty = lis_enty->next;
             continue;
        }

        bkvm_link = &bkvm_head;
        memset(buf, 0x00, sizeof(buf));
        while (fgets(buf, sizeof(buf), fp) != NULL) {
            conn_num = 0;
            memset(name, 0x00, sizeof(name));
            sscanf(buf, "%s %d", name, &conn_num);
            bkvminfo = g_malloc0(sizeof(*bkvminfo));
            bkvminfo->name = g_strdup(name);
            bkvminfo->conn_num = conn_num;
            bkvm_enty = g_malloc0(sizeof(*bkvm_enty));
            bkvm_enty->value = bkvminfo;
            bkvm_enty->next = NULL;

            *bkvm_link = bkvm_enty;
            bkvm_link = &bkvm_enty->next;
        }
        pclose(fp);
        lis_enty->value->vms_conn = bkvm_head;
        lis_enty = lis_enty->next;
    }
    return lis_head;
}

static void  kscale(unsigned long b, unsigned long bs , char *str)
{
    static const unsigned long long T = 1024*1024*1024*1024ul;
    static const unsigned long long G = 1024*1024*1024ull;
    static const unsigned long long M = 1024*1024;
    static const unsigned long long K = 1024;

    unsigned long long size = b * (unsigned long long)bs;
    if (size > T) {
        sprintf(str, "%0.2f T", size/(T*1.0));
    }
    else if (size > G) {
        sprintf(str, "%0.2f G", size/(G*1.0));
    }
    else if (size > M) {
        sprintf(str, "%0.2f M", size/(1.0*M));
    }
    else if (size > K) {
        sprintf(str, "%0.2f K", size/(1.0*K));
    }
    else {
        sprintf(str, "%0.2f B", size*1.0);
    }
}

DiskInfoList *qmp_guest_get_disk_info(Error **errp)
{
    FILE* mount_table;
    struct mntent *mount_entry;
    struct statfs s;
    unsigned long blocks_used;
    int blocks_percent_used;
    mount_table = NULL;
    DiskInfo  *lisinf=NULL;
    DiskInfoList *lis_head  = NULL;
    DiskInfoList **lis_link = NULL;
    DiskInfoList *lis_entry = NULL;

    lis_link = &lis_head;
    mount_table = setmntent("/etc/mtab", "r");
    if (!mount_table)
    {
        fprintf(stderr, "set mount entry error/n");
        return NULL;
    }

    while (1) {
        const char *device;
        const char *mount_point;
        if (mount_table) {
            mount_entry = getmntent(mount_table);
            if (!mount_entry) {
                endmntent(mount_table);
                break;
            }
        }
        else
            continue;
        device = mount_entry->mnt_fsname;
        mount_point = mount_entry->mnt_dir;
        if (statfs(mount_point, &s) != 0)
        {
            fprintf(stderr, "statfs failed!/n");
            continue;
        }
        if ((s.f_blocks > 0) || !mount_table )
        {
            blocks_used = s.f_blocks - s.f_bfree;
            blocks_percent_used = 0;
            if (blocks_used + s.f_bavail)
            {
                blocks_percent_used = (blocks_used * 100ULL
                        + (blocks_used + s.f_bavail)/2
                        ) / (blocks_used + s.f_bavail);
            }
            /* GNU coreutils 6.10 skips certain mounts, try to be compatible.  */
            if (strcmp(device, "rootfs") == 0)
                continue;

            char size[20];
            char used[20];
            char avail[20];
            char percent[20];
            kscale(s.f_blocks, s.f_bsize, size);
            kscale(s.f_blocks - s.f_bfree, s.f_bsize, used);
            kscale(s.f_bavail, s.f_bsize, avail);
            sprintf(percent, "%d%%", blocks_percent_used);
            lisinf = g_malloc0(sizeof (*lisinf));
            lisinf->device  =  g_strdup(device);
            lisinf->size  = g_strdup(size);
            lisinf->used =  g_strdup(used);
            lisinf->avail = g_strdup(avail);
            lisinf->percent = g_strdup(percent);
            lisinf->mountpoint = g_strdup(mount_point);

            lis_entry = g_malloc0(sizeof(*lis_entry));
            lis_entry->value = lisinf;
            lis_entry->next = NULL;

            *lis_link = lis_entry;
            lis_link = &lis_entry->next;

        }
    }

	return lis_head;
}

#else /* defined(__linux__) */

void qmp_guest_suspend_disk(Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);
}

void qmp_guest_suspend_ram(Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);
}

void qmp_guest_suspend_hybrid(Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);
}

GuestNetworkInterfaceList *qmp_guest_network_get_interfaces(Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);
    return NULL;
}

int64_t qmp_guest_network_set_interfaces(GuestNetworkInterfaceList *interfaces,
                                         Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);
    return -1;
}

GuestLogicalProcessorList *qmp_guest_get_vcpus(Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);
    return NULL;
}

int64_t qmp_guest_set_vcpus(GuestLogicalProcessorList *vcpus, Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);
    return -1;
}

GuestStats *qmp_guest_get_stats(Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);
    return NULL;
}

int64_t qmp_guest_init(const char *hostname, const char *ctrl_device,
                    const char *ctrl_mac, const char *ctrl_ip_address,
                    const char *srv_device, const char *srv_mac,
                    const char *init_password, const char *hypervisor_ip,
                    Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);
    return -1;
}

int64_t qmp_guest_network_set_gateway(const char* ip, Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);
    return -1;
}

ListenerConnInfoList *qmp_guest_get_lb_conn_info(Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);
    return NULL;
}
#endif

#if !defined(CONFIG_FSFREEZE)

GuestFsfreezeStatus qmp_guest_fsfreeze_status(Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);

    return 0;
}

int64_t qmp_guest_fsfreeze_freeze(Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);

    return 0;
}

int64_t qmp_guest_fsfreeze_thaw(Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);

    return 0;
}
#endif /* CONFIG_FSFREEZE */

#if !defined(CONFIG_FSTRIM)
void qmp_guest_fstrim(bool has_minimum, int64_t minimum, Error **errp)
{
    error_set(errp, QERR_UNSUPPORTED);
}
#endif

/* register init/cleanup routines for stateful command groups */
void ga_command_state_init(GAState *s, GACommandState *cs)
{
#if defined(CONFIG_FSFREEZE)
    ga_command_state_add(cs, NULL, guest_fsfreeze_cleanup);
#endif
    ga_command_state_add(cs, guest_file_init, NULL);
}

//DiskInfoList *qmp_guest_get_disk_info(Error **errp)
//{
//    error_set(errp, QERR_UNSUPPORTED);
//
//    return NULL;
//}
