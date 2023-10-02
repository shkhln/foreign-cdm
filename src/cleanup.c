#include <assert.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/mount.h>
#include "config.h"

static const char* paths[] = {
  FCDM_JAIL_DIR "/bin",
  FCDM_JAIL_DIR "/dev",
  FCDM_JAIL_DIR "/etc",
  FCDM_JAIL_DIR "/lib",
  FCDM_JAIL_DIR "/lib64",
  FCDM_JAIL_DIR "/proc",
  FCDM_JAIL_DIR "/sys",
  FCDM_JAIL_DIR "/usr",
  FCDM_JAIL_DIR "/opt/fcdm-worker",
  FCDM_JAIL_DIR "/opt/libcdm.so",
  FCDM_JAIL_DIR
};

int main(int argc, char* argv[]) {

  assert(geteuid() == UID_ROOT);

  //TODO: make sure no fcdm jails are running

  char* home_path = getenv("HOME");

  if (home_path == NULL) {
    errx(EXIT_FAILURE, "HOME is undefined");
  }

  if (access(home_path, R_OK | X_OK) == -1) {
    err(EXIT_FAILURE, "can't access %s", home_path);
  }

  if (chdir(home_path) == -1) {
    err(EXIT_FAILURE, "chdir(%s)", home_path);
  }

  for (unsigned int i = 0; i < nitems(paths); i++) {
    if (unmount(paths[i], 0) == -1) {
      warn("can't unmount %s/%s", home_path, paths[i]);
    }
  }

  return 0;
}
