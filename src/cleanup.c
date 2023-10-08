#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/mount.h>
#include "config.h"

static const char* paths[] = {
  FCDM_JAIL_DIR "/.setup-done",
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

int main(int argc, char* argv[]) {

  assert(geteuid() == UID_ROOT);

  char* home_path = getenv("HOME");

  if (home_path == NULL) {
    errx(EXIT_FAILURE, "HOME is undefined");
  }

  if (access(home_path, R_OK | W_OK | X_OK) == -1) {
    err(EXIT_FAILURE, "can't access %s", home_path);
  }

  if (chdir(home_path) == -1) {
    err(EXIT_FAILURE, "chdir(%s)", home_path);
  }

  for (unsigned int i = 0; i < nitems(paths); i++) {
    if (unmount(paths[i], 0) == -1) {
      warn("can't unmount %s/%s", home_path, paths[i]);
      if (i == 0 && errno == EBUSY) {
        break;
      }
    }
  }

  return 0;
}
