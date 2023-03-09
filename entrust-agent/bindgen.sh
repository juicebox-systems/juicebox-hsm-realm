bindgen --use-core \
    --output src/nfastapp.rs \
    --allowlist-function "NF.*(Init|Connect|Disconnect|Transact|Free_Reply)" \
    --allowlist-var ".*CreateSEEWorld_Args.*|.*LoadBuffer.*|NFastApp_ConnectionFlags.*" \
    --allowlist-type "M_SEEInitStatus" \
    --no-prepend-enum-name \
    --with-derive-default \
    --impl-debug \
    --no-doc-comments \
    --raw-line "#![allow(non_upper_case_globals)]" \
    --raw-line "#![allow(non_camel_case_types)]" \
    --raw-line "#![allow(non_snake_case)]" \
    --raw-line "#![allow(dead_code)]" \
    /opt/nfast/c/csd/include-see/hilibs/nfastapp.h \
    -- \
    -I /opt/nfast/c/csd/include-see/cutils/ \
    -I /opt/nfast/c/csd/gcc/include/cutils/
