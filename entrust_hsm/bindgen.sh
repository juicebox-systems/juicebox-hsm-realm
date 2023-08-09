#!/bin/sh

set -eu

# cd to script's directory
cd -P -- "$(dirname -- "$0")"

# this will give a warning
#   warning: 'HAVE_CONFIG_H' macro redefined [-Wmacro-redefined] which i beleive is safe to ignore
#
bindgen --use-core \
    --output src/seelib.rs \
    --allowlist-function "SEElib.*(init|InitComplete|AwaitJobEx|ReturnJob|Transact|FreeReply)" \
    --allowlist-var "SEELIB_JOB_REQUEUE|Command_flags_.*" \
    --no-prepend-enum-name \
    --with-derive-default \
    --impl-debug \
    --no-layout-tests \
    --no-doc-comments \
    --raw-line "#![allow(non_upper_case_globals)]" \
    --raw-line "#![allow(non_camel_case_types)]" \
    --raw-line "#![allow(non_snake_case)]" \
    --raw-line "#![allow(dead_code)]" \
    /opt/nfast/c/csd/include-see/module/seelib.h \
    -- \
    --target=powerpc-unknown-linux-gnu \
    -I /opt/nfast/c/csd/include-see/module/ \
    -I /opt/nfast/c/csd/include-see/module/rtlib \
    -I /opt/nfast/gcc/powerpc-codesafe-linux-gnu/include/ \
    -DNF_CROSSCC_PPC_GCC=1 \
    -fno-builtin \
    -nobuiltininc
