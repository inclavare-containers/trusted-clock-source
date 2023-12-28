##
project(SGXTrustedComm)

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

add_subdirectory(Server)
add_subdirectory(Client)