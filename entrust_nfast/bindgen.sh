#!/bin/sh

bindgen --use-core \
    --output src/nfastapp.rs \
    --allowlist-function "NF.*(Init|Connect|Disconnect|Transact|Submit|Query|Wait|Free_Reply|Lookup)|NFastApp_FreeACL|NFKM_(findkey|freekey|recordkey|cmd_loadblob|getinfo|.*newkey.*|loadadminkeys.*|cert.*|getusablemodule)|RQCard.*" \
    --allowlist-var ".*CreateSEEWorld_Args.*|.*LoadBuffer.*|NFastApp_ConnectionFlags.*|Key_flags_.*|Command_flags.*|.*_(enum)?table|.*PermissionGroup.*|Act_.*_Details_.*|FileDevice.*|Cmd_GenerateKey.*_flags.*|NFKM_NKF_.*" \
    --allowlist-type "M_SEEInitStatus|NFKM_(Admin.*|LoadAdminKeysHandle)|M_KeyMgmtEntType" \
    --no-prepend-enum-name \
    --with-derive-default \
    --impl-debug \
    --no-doc-comments \
    --raw-line "#![allow(non_upper_case_globals)]" \
    --raw-line "#![allow(non_camel_case_types)]" \
    --raw-line "#![allow(non_snake_case)]" \
    --raw-line "#![allow(dead_code)]" \
    src/bindgen.h \
    -- \
    -I /opt/nfast/c/csd/include-see/cutils/ \
    -I /opt/nfast/c/csd/gcc/include/cutils/ \
    -I /opt/nfast/c/csd/gcc/include/hilibs/ \
    -I /opt/nfast/c/csd/gcc/include/sworld/
