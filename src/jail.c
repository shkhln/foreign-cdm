#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/_iovec.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/jail.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <jail.h>
#include "config.h"

#define ULL_HI_MASK ((unsigned long long)-1 ^ (unsigned int)-1)

static bool xmount(const char* fstype, const char* from, const char* to, unsigned long long flags) {

  assert(((flags & ULL_HI_MASK) & ~MNT_NOCOVER) == 0);

  char errmsg[255];
  errmsg[0] = '\0';

  int capacity = 8;

  if (strcmp(fstype, "devfs") == 0) {
    capacity += 2;
  }

  if (flags & MNT_NOCOVER) {
    capacity += 2;
  }

  struct iovec* iov = malloc(capacity);

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

static void touch(char* path, int mode) {
  int fd = open(path, O_WRONLY | O_CREAT, mode);
  if (fd == -1) {
    err(EXIT_FAILURE, "can't create %s", path);
  }

  int err = close(fd);
  assert(err == 0);
}

static void xchdir(const char* path) {
  if (chdir(path) == -1) {
    err(EXIT_FAILURE, "chdir(%s)", path);
  }
}

static void xmkdir(const char* path, mode_t mode) {
  if (mkdir(path, mode) == -1) {
    err(EXIT_FAILURE, "mkdir(%s)", path);
  }
}

int main(int argc, char* argv[]) {

  assert(geteuid() == UID_ROOT);

  char* home_path   = getenv("HOME");
  char* libcdm_path = getenv("FCDM_CDM_SO_PATH");
  char* worker_path = getenv("FCDM_WORKER_PATH");

  if (home_path == NULL) {
    errx(EXIT_FAILURE, "HOME is undefined");
  }

  if (access(home_path, R_OK | W_OK | X_OK) == -1) {
    err(EXIT_FAILURE, "can't access %s", home_path);
  }

  if (libcdm_path != NULL && access(libcdm_path, R_OK | X_OK) == -1) {
    err(EXIT_FAILURE, "can't access %s", libcdm_path);
  }

  if (worker_path != NULL && access(worker_path, R_OK | X_OK) == -1) {
    err(EXIT_FAILURE, "can't access %s", worker_path);
  }

  if (chdir(home_path) == -1) {
    err(EXIT_FAILURE, "chdir(%s)", home_path);
  }

  if (mkdir(FCDM_JAIL_DIR, 0555) == 0) {
    int err = chown(FCDM_JAIL_DIR, getuid(), getgid());
    assert(err == 0);
  }

  // doesn't look like tmpfs supports MNT_NOEXEC/MNT_NOSUID
  if (xmount("tmpfs", "tmpfs", FCDM_JAIL_DIR, MNT_NOCOVER)) {

      xchdir(FCDM_JAIL_DIR);

      xmkdir("bin",   0555);
      xmkdir("dev",   0555);
      xmkdir("etc",   0555);
      xmkdir("lib",   0555);
      xmkdir("lib64", 0555);
      xmkdir("proc",  0555);
      xmkdir("sys",   0555);
      xmkdir("usr",   0555);
      xmkdir("opt",   0755);

      //TODO: use compat.linux.emul_path
      xmount("nullfs",    "/compat/linux/bin",   "bin",   MNT_RDONLY | MNT_NOSUID);
      xmount("devfs",     "devfs",               "dev",   0);
      xmount("nullfs",    "/compat/linux/etc",   "etc",   MNT_RDONLY | MNT_NOSUID);
      xmount("nullfs",    "/compat/linux/lib",   "lib",   MNT_RDONLY | MNT_NOSUID);
      xmount("nullfs",    "/compat/linux/lib64", "lib64", MNT_RDONLY | MNT_NOSUID);
      xmount("linprocfs", "linprocfs",           "proc",  0);
      xmount("linsysfs",  "linsysfs",            "sys",   0);
      xmount("nullfs",    "/compat/linux/usr",   "usr",   MNT_RDONLY | MNT_NOSUID);

      if (libcdm_path != NULL) {
        touch("opt/libcdm.so", 0555);
        xmount("nullfs", libcdm_path, "opt/libcdm.so", MNT_RDONLY | MNT_NOSUID);
      }

      if (worker_path != NULL) {
        touch("opt/fcdm-worker", 0555);
        xmount("nullfs", worker_path, "opt/fcdm-worker", MNT_RDONLY | MNT_NOSUID);
      }

      touch(".setup-done", 0444);

      xchdir(home_path);

      xmount("tmpfs", "tmpfs", FCDM_JAIL_DIR, MNT_RDONLY | MNT_UPDATE);
  } else {
    // this is both a bit racy and doesn't take into account other potential reasons for EBUSY
    warnx("assuming %s is already mounted", FCDM_JAIL_DIR);
    if (access(FCDM_JAIL_DIR "/.setup-done", F_OK) == -1) {
      err(EXIT_FAILURE, "%s", FCDM_JAIL_DIR "/.setup-done");
    }
  }

  struct jailparam params[1];

  jailparam_init  (&params[0], "path");
  jailparam_import(&params[0], FCDM_JAIL_DIR);

  int jid = jailparam_set(params, nitems(params), JAIL_CREATE | JAIL_ATTACH);
  if (jid == -1) {
    errx(EXIT_FAILURE, "%s", jail_errmsg);
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

  if (argc > 1) {

    errno = 0;
    intmax_t socket_fd = strtoimax(argv[1], NULL, 10);
    assert(errno != ERANGE && errno != EINVAL);

    if (socket_fd > 3) {
      int err = close_range(3, socket_fd - 1, 0);
      assert(err == 0);
    }

    closefrom(socket_fd + 1);

    char* const env[] = { "FCDM_CDM_SO_PATH=/opt/libcdm.so", NULL };
    execve("/opt/fcdm-worker", argv, env);
  } else {
    char* const env[] = { "PATH=/bin", NULL };
    execve("/bin/sh", argv, env);
  }
  err(EXIT_FAILURE, "execve");
}
