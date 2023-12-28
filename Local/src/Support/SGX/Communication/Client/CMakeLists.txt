##
project(SGXTrustedClient)

set(SOURCES SGXTrustedClient.cpp)

set(INCLUDE_DIRS ${RATS_TLS_HEADER_DIR}
                 ${RATS_TLS_HEADER_DIR}/edl
                 ${RATS_TLS_HEADER_DIR}/rats-tls
                 ${RATS_TLS_HEADER_DIR}/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/include
)

list(APPEND LIBRARY_DIRS ${RATS_TLS_LIB_DIR}/sgx/untrust
                         ${RATS_TLS_LIB_DIR}/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/lib64
) # ${CMAKE_BINARY_DIR}/sgx-stub-enclave

set(EDL_SEARCH_PATHS ${RATS_TLS_HEADER_DIR}/edl 
                     ${CMAKE_CURRENT_SOURCE_DIR}/Enclave)

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

add_untrusted_library(${PROJECT_NAME} STATIC
                      SRCS ${SOURCES}
                      EDL ${CMAKE_CURRENT_SOURCE_DIR}/Enclave/ClientEnclave.edl
                      EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
)

add_dependencies(${PROJECT_NAME} SGXClientEnclave-sign)

add_subdirectory(Enclave)