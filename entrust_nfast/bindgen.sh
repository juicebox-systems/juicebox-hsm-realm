#!/bin/sh

bindgen --use-core \
    --output src/nfastapp.rs \
    --allowlist-function "NF.*(Init|Connect|Disconnect|Transact|Free_Reply|Lookup)|NFKM_(findkey|cmd_loadblob|getinfo|recordkey|newkey_make.*|loadadminkeys.*|cert.*)|RQCard.*" \
    --allowlist-var ".*CreateSEEWorld_Args.*|.*LoadBuffer.*|NFastApp_ConnectionFlags.*|Act_NVMemOpPerms_Details_perms.*|Command_flags.*|.*_(enum)?table|Act_OpPermissions_Details.*|.*PermissionGroup.*|Act_MakeBlob_Details_flags.*|Act_FileCopy_Details.*|FileDevice.*|Cmd_GenerateKey_Reply_flags.*|NFKM_DEFOPPERMS.*|NFKM_NKF_.*" \
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
