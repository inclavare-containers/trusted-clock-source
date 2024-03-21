##
cmake_minimum_required(VERSION 3.5.1)

set(SGX 1)
add_definitions(-DSGX)

if (DEFINED TCS_DEPENDENCY_DIR)
else()
    set(TCS_DEPENDENCY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../Dependency")
endif()

if (EXISTS "${TCS_DEPENDENCY_DIR}")
else()
    message(FATAL_ERROR "The dependency directory '${TCS_DEPENDENCY_DIR}' doesn't exist!")
endif()

set(RATS_TLS_DIR "${TCS_DEPENDENCY_DIR}/rats-tls")
if (EXISTS "${RATS_TLS_DIR}")
else()
    message(FATAL_ERROR "The Rats-TLS directory '${RATS_TLS_DIR}' doesn't exist!")
endif()

set(RATS_TLS_HEADER_DIR "${RATS_TLS_DIR}/include")
if (EXISTS "${RATS_TLS_HEADER_DIR}")
else()
    message(FATAL_ERROR "The Rats-TLS header directory '${RATS_TLS_HEADER_DIR}' doesn't exist!")
endif()

set(RATS_TLS_CMAKE_DIR "${RATS_TLS_DIR}/cmake")
if (EXISTS "${RATS_TLS_CMAKE_DIR}")
else()
    message(FATAL_ERROR "The Rats-TLS cmake module directory '${RATS_TLS_CMAKE_DIR}' doesn't exist!")
endif()

set(RATS_TLS_LIB_DIR "${RATS_TLS_DIR}/lib")
if (EXISTS "${RATS_TLS_LIB_DIR}")
else()
    message(FATAL_ERROR "The Rats-TLS library directory '${RATS_TLS_LIB_DIR}' doesn't exist!")
endif()

if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(DEBUG 1)
    message(STATUS "Build Type: Debug")
elseif(CMAKE_BUILD_TYPE MATCHES "Prerelease")
    set(PRERELEASE 1)
    message(STATUS "Build Type: Prerelease")
else()
    set(RELEASE 1)
    message(STATUS "Build Type: Release")
endif()

option(SGX_HW "Run SGX on hardware, OFF for simulation" ON)
option(SGX_LVI_MITIGATION "Mitigation flag, default on" ON)

if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(DEBUG 1)
    set(SGX_DEBUG 1)
    set(RATS_TLS_LIB_DIR "${RATS_TLS_LIB_DIR}/Debug")
    message(STATUS "Build Type: Debug")
elseif(CMAKE_BUILD_TYPE MATCHES "Prerelease")
    set(PRERELEASE 1)
    set(SGX_PRERELEASE 1)
    set(RATS_TLS_LIB_DIR "${RATS_TLS_LIB_DIR}/Prerelease")
    message(STATUS "Build Type: Prerelease")
else()
    set(RELEASE 1)
    set(SGX_RELEASE 1)
    set(RATS_TLS_LIB_DIR "${RATS_TLS_LIB_DIR}/Release")
    message(STATUS "Build Type: Release")
endif()

if (EXISTS "${RATS_TLS_LIB_DIR}")
else()
    message(FATAL_ERROR "The Rats-TLS library directory '${RATS_TLS_LIB_DIR}' doesn't exist!")
endif()


list(APPEND CMAKE_MODULE_PATH "${RATS_TLS_CMAKE_DIR}")

include(CompilerOptions)
include(CustomInstallDirs)
include(FindRatsTls)
if(NOT RATS_TLS_FOUND)
    message(FATAL_ERROR "Failed to find rats_tls!")
endif()
include(FindSGX)
if(NOT SGX_FOUND)
    message(FATAL_ERROR "Failed to find sgx!")
endif()
include(SGXCommon)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(INCLUDE_DIRS ${RATS_TLS_HEADER_DIR}
                 ${RATS_TLS_HEADER_DIR}/edl
                 ${RATS_TLS_HEADER_DIR}/rats-tls
                 ${RATS_TLS_HEADER_DIR}/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/Module
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/Module/Utility
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/Module/Communication
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/Support
)

include_directories(${INCLUDE_DIRS})

add_subdirectory(InitClient)
add_subdirectory(InitServer)

## cmake -D CMAKE_BUILD_TYPE:STRING="Debug" -B Debug-build .
## make -C Debug-build clean all install