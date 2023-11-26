#!/bin/sh
script_dir="$(dirname $(realpath "$0"))"
export FCDM_CDM_SO_PATH=${FCDM_CDM_SO_PATH-/usr/local/lib/WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so}
export FCDM_BUILD_DIR_PATH="$script_dir/build"
export LD_PRELOAD="$script_dir/build/override-fbsd.so"
exec chrome
