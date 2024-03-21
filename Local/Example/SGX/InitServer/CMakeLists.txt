##

project(InitServer)

if(DEBUG)
    set(TCS_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/Support/SGX/Debug-build/lib)
elseif(PRERELEASE)
    set(TCS_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/Support/SGX/Prerelease-build/lib)
else()
    set(TCS_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/Support/SGX/Release-build/lib)
endif()

list(APPEND LIBRARY_DIRS ${TCS_LIB_DIR}
                         ${RATS_TLS_LIB_DIR}/sgx/untrust
                         ${RATS_TLS_LIB_DIR}/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/lib64)

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})



set(SOURCES InitServer.cpp)

set(DEPEND_UNTRUSTED_LIBS ${TCS_LIB_DIR}/libSGXTrustedServer.a
                          ${RATS_TLS_LIB_DIR}/sgx/untrust/librats_tls_u.a)

# add_executable(${PROJECT_NAME} ${SOURCES})
# target_link_libraries(${PROJECT_NAME} SGXTrustedClient)

add_untrusted_executable(${PROJECT_NAME}
                         SRCS ${SOURCES}
                         UNTRUSTED_LIBS ${DEPEND_UNTRUSTED_LIBS})

install(TARGETS ${PROJECT_NAME}
    DESTINATION ${CMAKE_BINARY_DIR}/bin)
install(FILES ${TCS_LIB_DIR}/SGXServerEnclave.signed.so
    DESTINATION ${CMAKE_BINARY_DIR}/bin)