# Project name
project(SGXServerEnclave)


list(APPEND CMAKE_MODULE_PATH "${RATS_TLS_CMAKE_DIR}")
include(CustomInstallDirs)
include(FindRatsTls)
if(NOT RATS_TLS_FOUND)
    message(FATAL_ERROR "Failed to find rats_tls!")
endif()
include(FindSGX)
if(NOT SGX_FOUND)
    message(FATAL_ERROR "Failed to find sgx!")
endif()
include(CompilerOptions)
include(SGXCommon)

set(INCLUDE_DIRS ${RATS_TLS_HEADER_DIR}
                    ${RATS_TLS_HEADER_DIR}/rats-tls
                    ${RATS_TLS_HEADER_DIR}/edl
                    ${RATS_TLS_HEADER_DIR}/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../../EnclaveUtils)

set(LIBRARY_DIRS ${RATS_TLS_LIB_DIR}
                ${RATS_TLS_LIB_DIR}/crypto_wrappers/nullcrypto
                ${RATS_TLS_LIB_DIR}/crypto_wrappers/openssl
                ${RATS_TLS_LIB_DIR}/tls_wrappers/nulltls
                ${RATS_TLS_LIB_DIR}/tls_wrappers/openssl
                ${RATS_TLS_LIB_DIR}/verifiers/nullverifier
                ${RATS_TLS_LIB_DIR}/verifiers/sgx-ecdsa-qve
                ${RATS_TLS_LIB_DIR}/verifiers/tdx-ecdsa
                ${RATS_TLS_LIB_DIR}/verifiers/sgx-la
                ${RATS_TLS_LIB_DIR}/attesters/nullattester
                ${RATS_TLS_LIB_DIR}/attesters/sgx-ecdsa
                ${RATS_TLS_LIB_DIR}/attesters/sgx-la
                ${RATS_TLS_LIB_DIR}/sgx/trust
                ${RATS_TLS_LIB_DIR}/sgx/untrust
                ${RATS_TLS_LIB_DIR}/external/libcbor/src/libcbor/lib
                ${RATS_TLS_LIB_DIR}/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/lib64)

set(EDL_SEARCH_PATHS ${RATS_TLS_HEADER_DIR}/edl)

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

set(E_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/ServerEnclave.c
           ${CMAKE_CURRENT_SOURCE_DIR}/../../../EnclaveUtils/EnclaveUtils.c)
set(EDLS ${CMAKE_CURRENT_SOURCE_DIR}/ServerEnclave.edl)
set(LDS ${CMAKE_CURRENT_SOURCE_DIR}/ServerEnclave.lds)
set(DEPEND_TRUSTED_LIBS crypto_wrapper_nullcrypto
                        crypto_wrapper_openssl
                        tls_wrapper_nulltls
                        tls_wrapper_openssl
                        attester_nullattester
                        attester_sgx_ecdsa
                        attester_sgx_la
                        verifier_nullverifier
                        verifier_sgx_la
                        verifier_sgx_ecdsa_qve
                        verifier_tdx_ecdsa
                        rats_tls
                        cbor
                        )

add_enclave_library(SGXServerEnclave SRCS ${E_SRCS} EDL ${EDLS} TRUSTED_LIBS ${DEPEND_TRUSTED_LIBS} EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} LDSCRIPT ${LDS})
enclave_sign(SGXServerEnclave KEY ServerEnclave.pem CONFIG ServerEnclave.xml)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/SGXServerEnclave.signed.so
        DESTINATION ${CMAKE_BINARY_DIR}/lib)
