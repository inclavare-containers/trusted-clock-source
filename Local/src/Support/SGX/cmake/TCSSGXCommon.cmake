## Depend on Rats-TLS CMake files

include(SGXCommon)

function(tcs_sgx_add_executable target)
    set(multiValueArgs SRCS LIBS)
    cmake_parse_arguments("SGX" "${multiValueArgs}" ${ARGN})

    set(ULIB_LIST "")
    foreach(ULIB ${SGX_UNTRUSTED_LIBS})
        set (ULIB_LIST "${ULIB_LIST} ${ULIB}")
    endforeach()

    set(UNTRUSTED_LINK_FLAGS "-L${SGX_LIBRARY_PATH} ${ULIB_LIST} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB} -l${SGX_DACP_QL} -l${SGX_DACP_QUOTEVERIFY} -lsgx_ukey_exchange -L${INTEL_SGXSSL_LIB} -lsgx_usgxssl")

    set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_C_FLAGS})
    target_link_libraries(${target} ${UNTRUSTED_LINK_FLAGS})
endfunction(tcs_add_executable)
