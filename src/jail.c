#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
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

static bool wmount(const char* fstype, const char* from, const char* to, unsigned long long flags) {

  assert(((flags & ULL_HI_MASK) & ~MNT_NOCOVER) == 0);

  char errmsg[255];
  errmsg[0] = '\0';

  int capacity = 8;

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
  assert(close(open(path, O_WRONLY | O_CREAT, mode)) == 0);
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
    assert(chown(FCDM_JAIL_DIR, getuid(), getgid()) == 0);
  }

  // doesn't look like tmpfs supports MNT_NOEXEC/MNT_NOSUID
  if (wmount("tmpfs", "tmpfs", FCDM_JAIL_DIR, MNT_NOCOVER)) {

      assert(chdir(FCDM_JAIL_DIR) == 0);

      assert(mkdir("bin",   0555) == 0);
      assert(mkdir("dev",   0555) == 0);
      assert(mkdir("etc",   0555) == 0);
      assert(mkdir("lib",   0555) == 0);
      assert(mkdir("lib64", 0555) == 0);
      assert(mkdir("proc",  0555) == 0);
      assert(mkdir("sys",   0555) == 0);
      assert(mkdir("usr",   0555) == 0);
      assert(mkdir("opt",   0755) == 0);

      //TODO: use compat.linux.emul_path
      //TODO: we might get away with exposing just /dev/null and /dev/(u)random
      wmount("nullfs",    "/compat/linux/bin",   "bin",   MNT_RDONLY | MNT_NOSUID);
      wmount("devfs",     "devfs",               "dev",   0);
      wmount("nullfs",    "/compat/linux/etc",   "etc",   MNT_RDONLY | MNT_NOSUID);
      wmount("nullfs",    "/compat/linux/lib",   "lib",   MNT_RDONLY | MNT_NOSUID);
      wmount("nullfs",    "/compat/linux/lib64", "lib64", MNT_RDONLY | MNT_NOSUID);
      wmount("linprocfs", "linprocfs",           "proc",  0);
      wmount("linsysfs",  "linsysfs",            "sys",   0);
      wmount("nullfs",    "/compat/linux/usr",   "usr",   MNT_RDONLY | MNT_NOSUID);

      if (libcdm_path != NULL) {
        touch("opt/libcdm.so", 0555);
        wmount("nullfs", libcdm_path, "opt/libcdm.so", MNT_RDONLY | MNT_NOSUID);
      }

      if (worker_path != NULL) {
        touch("opt/fcdm-worker", 0555);
        wmount("nullfs", worker_path, "opt/fcdm-worker", MNT_RDONLY | MNT_NOSUID);
      }

      touch(".setup-done", 0222);

      assert(chdir(home_path) == 0);

      assert(wmount("tmpfs", "tmpfs", FCDM_JAIL_DIR, MNT_NOCOVER | MNT_RDONLY | MNT_UPDATE));
  } else {
    // this is both a bit racy and doesn't take into account other potential reasons for EBUSY
    warnx("assuming %s is already mounted", FCDM_JAIL_DIR);
    assert(access(FCDM_JAIL_DIR "/.setup-done", F_OK) == 0);
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

  //TODO: close unnecessary file descriptors before exec

  if (argc > 1) {
    char* const env[] = { "FCDM_CDM_SO_PATH=/opt/libcdm.so", NULL };
    execve("/opt/fcdm-worker", argv, env);
  } else {
    char* const env[] = { "PATH=/bin", NULL };
    execve("/bin/sh", argv, env);
  }
  err(EXIT_FAILURE, "execve");
}
