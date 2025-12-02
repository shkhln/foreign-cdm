#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/_iovec.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/jail.h>
#include <sys/mount.h>
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <jail.h>
#include <libutil.h>

#include "config.h"

static bool xmount(const char* fstype, const char* from, const char* to, unsigned long long flags) {

  assert(((flags & (~0ULL ^ ~0U)) & ~MNT_NOCOVER) == 0);

  char errmsg[255];
  errmsg[0] = '\0';

  int capacity = 8;

  if (strcmp(fstype, "devfs") == 0) {
    capacity += 2;
  }

  if (flags & MNT_NOCOVER) {
    capacity += 2;
  }

  struct iovec* iov = malloc(sizeof(struct iovec) * capacity);

  iov[0].iov_base = "fstype";
  iov[0].iov_len  = sizeof("fstype");
  iov[1].iov_base = __DECONST(char*, fstype);
  iov[1].iov_len  = strlen(fstype) + 1;

  iov[2].iov_base = "fspath";
  iov[2].iov_len  = sizeof("fspath");
  iov[3].iov_base = __DECONST(char*, to);
  iov[3].iov_len  = strlen(to) + 1;

  iov[4].iov_base = "from";
  iov[4].iov_len  = sizeof("from");
  iov[5].iov_base = __DECONST(char*, from);
  iov[5].iov_len  = strlen(from) + 1;

  iov[6].iov_base = "errmsg";
  iov[6].iov_len  = sizeof("errmsg");
  iov[7].iov_base = errmsg;
  iov[7].iov_len  = sizeof(errmsg);

  int len = 8;

  if (strcmp(fstype, "devfs") == 0) {

    assert(len + 2 <= capacity);

    iov[len].iov_base = "ruleset";
    iov[len].iov_len  = sizeof("ruleset");
    len++;

    // apparently 4 means devfsrules_jail (/etc/defaults/devfs.rules)
    iov[len].iov_base = "4";
    iov[len].iov_len  = sizeof("4");
    len++;
  }

  if (flags & MNT_NOCOVER) {

    assert(len + 2 <= capacity);

    iov[len].iov_base = "nocover";
    iov[len].iov_len  = sizeof("nocover");
    len++;

    iov[len].iov_base = NULL;
    iov[len].iov_len  = 0;
    len++;
  }

  assert(len == capacity);

  if (nmount(iov, len, (int)flags) == 0) {
    free(iov);
    return true;
  }

  if ((flags & MNT_NOCOVER) && errno == EBUSY) {
    free(iov);
    return false;
  }

  err(EXIT_FAILURE, "nmount %s -> %s: %s", from, to, errmsg);
}

static void xchdir(const char* path) {
  if (chdir(path) == -1) {
    err(EXIT_FAILURE, "chdir(\"%s\")", path);
  }
}

static void xclose(int fd) {
  int e = close(fd);
  assert(e == 0);
}

static void xcreat(char* path, int mode) {
  int fd = open(path, O_CREAT | O_WRONLY, mode);
  if (fd == -1) {
    err(EXIT_FAILURE, "can't create %s", path);
  }

  xclose(fd);
}

static void xmkdir(const char* path, mode_t mode) {
  if (mkdir(path, mode) == -1) {
    err(EXIT_FAILURE, "mkdir(\"%s\")", path);
  }
}

int main(int argc, char* argv[]) {

  assert(geteuid() == UID_ROOT);

  char* rdir_path = getenv("XDG_RUNTIME_DIR");

  if (rdir_path == NULL) {
    warnx("XDG_RUNTIME_DIR is undefined, using HOME instead");
    rdir_path = getenv("HOME");
    if (rdir_path == NULL) {
      errx(EXIT_FAILURE, "HOME is undefined");
    }
  }

  char* libcdm_path = getenv("FCDM_CDM_SO_PATH");
  char* worker_path = getenv("FCDM_WORKER_PATH");

  if (access(rdir_path, R_OK | W_OK | X_OK) == -1) {
    err(EXIT_FAILURE, "can't access %s", rdir_path);
  }

  if (libcdm_path != NULL && access(libcdm_path, R_OK) == -1) {
    err(EXIT_FAILURE, "can't access %s", libcdm_path);
  }

  if (worker_path != NULL && access(worker_path, R_OK | X_OK) == -1) {
    err(EXIT_FAILURE, "can't access %s", worker_path);
  }

  xchdir(rdir_path);

  int lock_fd = flopen(FCDM_LOCKFILE, O_CREAT, 0444);
  if (lock_fd == -1) {
    err(EXIT_FAILURE, "unable to lock " FCDM_LOCKFILE " for the mount point setup");
  }

  fchown(lock_fd, getuid(), getgid());

  mkdir(FCDM_JAIL_DIR, 0555);
  chown(FCDM_JAIL_DIR, getuid(), getgid());

  xchdir(FCDM_JAIL_DIR);

  if (xmount("tmpfs", "tmpfs", ".", MNT_NOEXEC | MNT_NOCOVER)) {

      char linux_emul_path[MAXPATHLEN];
      size_t linux_emul_path_size = MAXPATHLEN;
      if (sysctlbyname("compat.linux.emul_path", linux_emul_path, &linux_emul_path_size, NULL, 0) == -1) {
        err(EXIT_FAILURE, "sysctlbyname");
      }

      const char* dirs[] = { "bin", "etc", "lib", "lib64", "usr" };
      for (unsigned int i = 0; i < nitems(dirs); i++) {

        xmkdir(dirs[i], 0555);

        char path[MAXPATHLEN];
        int n = snprintf(path, MAXPATHLEN, "%s/%s", linux_emul_path, dirs[i]);
        assert(n > 0 && n < MAXPATHLEN);

        xmount("nullfs", path, dirs[i], MNT_RDONLY | MNT_NOSUID);
      }

      xmkdir("dev",  0555);
      xmkdir("proc", 0555);
      xmkdir("sys",  0555);

      xmount("devfs",     "devfs",     "dev",  0);
      xmount("linprocfs", "linprocfs", "proc", 0);
      xmount("linsysfs",  "linsysfs",  "sys",  0);

      xmkdir("opt", 0555);

      if (libcdm_path != NULL) {
        xcreat("opt/cdm.so", 0555);
        xmount("nullfs", libcdm_path, "opt/cdm.so", MNT_RDONLY | MNT_NOSUID);
      }

      if (worker_path != NULL) {
        xcreat("opt/worker", 0555);
        xmount("nullfs", worker_path, "opt/worker", MNT_RDONLY | MNT_NOSUID);
      }

      xcreat(".setup-done", 0444);
      xcreat(".whatever",   0444);
      xmount("nullfs", ".whatever", ".setup-done", 0);

      xmount("tmpfs", "tmpfs", ".", MNT_NOEXEC | MNT_RDONLY | MNT_UPDATE);
  } else {
    warnx("assuming %s/%s is already mounted [pid = %d]", rdir_path, FCDM_JAIL_DIR, getpid());
  }

  // we keep this file open while the jail is running to make unmount(".setup-done") fail with EBUSY
  int setup_marker_fd = open(".setup-done", O_RDONLY);
  if (setup_marker_fd == -1) {
    err(EXIT_FAILURE, "open(\".setup-done\")");
  }

  if (flock(lock_fd, LOCK_UN) == -1) {
    err(EXIT_FAILURE, "unable to unlock " FCDM_LOCKFILE);
  }

  int pid_fd;
  pid_t pid = pdfork(&pid_fd, 0);
  if (pid == -1) {
    err(EXIT_FAILURE, "pdfork");
  }

  if (pid == 0) {

    char*  exe;
    char** arg;
    char** env;

    if (argc > 1) {

      errno = 0;
      intmax_t socket_fd = strtoimax(argv[1], NULL, 10);
      assert(errno != ERANGE && errno != EINVAL);

      dup2(socket_fd, 3);
      closefrom(4);

      exe = "/opt/worker";
      arg = (char* []){ "fcdm-worker", "3", NULL };
      env = (char* []){ "FCDM_CDM_SO_PATH=/opt/cdm.so", getenv("FCDM_LOG_INFO") != NULL ? "FCDM_LOG_INFO=1" : NULL, NULL };

    } else {

      closefrom(3);

      exe = "/bin/sh";
      arg = (char* []){ exe, NULL };
      env = (char* []){ "PATH=/bin", NULL };
    }

    struct jailparam params[1];

    jailparam_init  (&params[0], "path");
    jailparam_import(&params[0], ".");

    // Note that pwd_chroot_chdir (used internally by jail_set) returns EPERM
    // if there are any open directories, so it's important to close all such fds.
    // (It also ignores the kern.chroot_allow_open_directories sysctl.)
    int jid = jailparam_set(params, nitems(params), JAIL_CREATE | JAIL_ATTACH);
    if (jid == -1) {
      err(EXIT_FAILURE, "jailparam_set: %s", jail_errmsg);
    } else {
      warnx("spawned jail %d", jid);
    }

    jailparam_free(params, nitems(params));

    //TODO: should we use setusercontext instead?
    //TODO: there is also "allow.suser" jail param
    if (setresgid(GID_NOBODY, GID_NOBODY, GID_NOBODY) == -1) {
      err(EXIT_FAILURE, "setresgid");
    }

    if (setresuid(UID_NOBODY, UID_NOBODY, UID_NOBODY) == -1) {
      err(EXIT_FAILURE, "setresuid");
    }

    execve(exe, arg, env);
    err(EXIT_FAILURE, "execve");

  } else {

    int kq = kqueue();
    if (kq == -1) {
      err(EXIT_FAILURE, "kqueue");
    }

    struct kevent kev;
    EV_SET(&kev, pid_fd, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT, 0, NULL);

    if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
      err(EXIT_FAILURE, "kevent");
    }

    while (kevent(kq, NULL, 0, &kev, 1, NULL) == -1) {
      if (errno != EINTR) {
        err(EXIT_FAILURE, "kevent");
      }
    }

    xclose(pid_fd);
    xclose(setup_marker_fd);

    if (flock(lock_fd, LOCK_EX) == -1) {
      err(EXIT_FAILURE, "unable to lock " FCDM_LOCKFILE " for cleanup");
    }

    xchdir(rdir_path);

    if (unmount(FCDM_JAIL_DIR "/.setup-done", 0) == 0) {

      const char* paths[] = {
        FCDM_JAIL_DIR "/bin",
        FCDM_JAIL_DIR "/dev",
        FCDM_JAIL_DIR "/etc",
        FCDM_JAIL_DIR "/lib",
        FCDM_JAIL_DIR "/lib64",
        FCDM_JAIL_DIR "/proc",
        FCDM_JAIL_DIR "/sys",
        FCDM_JAIL_DIR "/usr",
        FCDM_JAIL_DIR "/opt/cdm.so",
        FCDM_JAIL_DIR "/opt/worker",
        FCDM_JAIL_DIR
      };

      for (unsigned int i = 0; i < nitems(paths); i++) {
        if (unmount(paths[i], 0) == -1) {
          warnx("force unmounting %s/%s", rdir_path, paths[i]);
          if (unmount(paths[i], MNT_FORCE) == -1) {
            warn("can't unmount %s/%s", rdir_path, paths[i]);
          }
        }
      }
    }

    return WEXITSTATUS(kev.data);
  }
}
