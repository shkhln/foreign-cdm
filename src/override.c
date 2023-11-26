#define _GNU_SOURCE

#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>

#ifdef __FreeBSD__
#define FCDM_LIB_NAME "fcdm-fbsd.so"
#endif

#ifdef __linux__
#define FCDM_LIB_NAME "fcdm-linux.so"
#endif

static char fcdm_lib_path[MAXPATHLEN];
static void* (*libc_dlopen)(const char*, int) = NULL;

__attribute__((constructor))
static void init() {

  extern char* __progname;
  fprintf(stderr, "process: %s\n", __progname);

  char* build_dir = getenv("FCDM_BUILD_DIR_PATH");
  assert(build_dir != NULL);

  setenv("FCDM_BINDIR_PATH", build_dir, 1);

  int n = snprintf(fcdm_lib_path, MAXPATHLEN, "%s/%s", build_dir, FCDM_LIB_NAME);
  assert(n > 0 && n < MAXPATHLEN);

  libc_dlopen = dlsym(RTLD_NEXT, "dlopen");
  assert(libc_dlopen != dlopen);
}

void* dlopen(const char* path, int mode) {

  if (path != NULL && path[0] == '/') {

    int last_sep_pos = 0;
    for (int i = strlen(path); i >= 0; i--) {
      if (path[i] == '/') {
        last_sep_pos = i;
        break;
      }
    }

    if (strcmp(&path[last_sep_pos + 1], "libwidevinecdm.so") == 0) {
      fprintf(stderr, "%s: %s -> %s\n", __func__, path, fcdm_lib_path);
      return libc_dlopen(fcdm_lib_path, mode);
    }
  }

  return libc_dlopen(path, mode);
}

#ifdef __linux__
// Chrome tries to use PR_SET_NO_NEW_PRIVS
int prctl() {
  return 0;
}
#endif
