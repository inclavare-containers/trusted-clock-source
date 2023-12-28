/***
 *
 *
 *
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "rats-tls/api.h"

#include "sgx_trts.h"

#include "TCSMessage.h"

#include "ServerEnclave_t.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     \
    {                      \
        if (NULL != (ptr)) \
        {                  \
            free(ptr);     \
            (ptr) = NULL;  \
        }                  \
    }
#endif

typedef struct __ServerItemT
{
    int64_t m_socketHandler;
    rats_tls_handle m_ratsHandler;
    int64_t m_connHandler;
} ServerItemT;

static ServerItemT mainServerItem = {.m_socketHandler = 0, .m_ratsHandler = NULL, .m_connHandler = 0};

static char mainServerError[TCS_ERROR_INFO_MAX_LEN] = {'\0'};

static void storeErrorInfo(const char *__restrict__ _format, ...)
{
    va_list argptr;
    va_start(argptr, _format);
    snprintf(mainServerError, TCS_ERROR_INFO_MAX_LEN - 1, _format, argptr);
    va_end(argptr);
}

void ecallGetServerError(char *errorInfo, size_t infoLen)
{
    --infoLen;
    size_t rawInfoLen = strlen(mainServerError);
    size_t copiedInfoLen = rawInfoLen > infoLen ? infoLen : rawInfoLen;
    strncpy(errorInfo, mainServerError, copiedInfoLen);
    errorInfo[copiedInfoLen] = '\0';
}

int64_t ecallStartRatsServer(
    uint32_t netAddr,
    uint16_t netPort,
    unsigned flags,
    const char *attesterType,
    const char *verifierType,
    const char *tlsType,
    const char *cryptoType)
{
    rats_tls_conf_t conf;
    memset(&conf, 0, sizeof(conf));

    // conf.log_level = log_level;
    snprintf(conf.attester_type, sizeof(conf.attester_type), "%s", attesterType);
    snprintf(conf.verifier_type, sizeof(conf.verifier_type), "%s", verifierType);
    snprintf(conf.tls_type, sizeof(conf.tls_type), "%s", tlsType);
    snprintf(conf.crypto_type, sizeof(conf.crypto_type), "%s", cryptoType);
    conf.flags = flags;
    conf.cert_algo = RATS_TLS_CERT_ALGO_DEFAULT;

    /* Optional: Set some user-defined custom claims, which will be embedded in the certificate. */
    claim_t custom_claims[2] = {
        {.name = "key_0", .value = (uint8_t *)"value_0", .value_size = sizeof("value_0")},
        {.name = "key_1", .value = (uint8_t *)"value_1", .value_size = sizeof("value_1")},
    };
    conf.custom_claims = (claim_t *)custom_claims;
    conf.custom_claims_length = 2;

    int64_t sockFd;
    sgx_status_t result = ocall_socket(&sockFd, RTLS_AF_INET, RTLS_SOCK_STREAM, 0);
    if (result != SGX_SUCCESS || sockFd < 0)
    {
        storeErrorInfo("Failed to initialize socket. SGX status: 0x%.4x. Socket file handler: %lld.", result, sockFd);
        return -1;
    }

    int reuse = 1;
    int ocallResult = 0;
    result = ocall_setsockopt(&ocallResult, sockFd, RTLS_SOL_SOCKET, RTLS_SO_REUSEADDR,
                              (const void *)&reuse, sizeof(int));
    if (result != SGX_SUCCESS || ocallResult < 0)
    {
        storeErrorInfo("Failed to set socket option. SGX status: 0x%.4x. Function return: %d.", result, ocallResult);
        return -1;
    }

    /* Set keepalive options */
    int flag = 1;
    int tcp_keepalive_time = 30;
    int tcp_keepalive_intvl = 10;
    int tcp_keepalive_probes = 5;
    result = ocall_setsockopt(&ocallResult, sockFd, RTLS_SOL_SOCKET, RTLS_SO_KEEPALIVE, &flag,
                              sizeof(flag));
    if (result != SGX_SUCCESS || ocallResult < 0)
    {
        storeErrorInfo("Failed to set socket option. SGX status: 0x%.4x. Function return: %d.", result, ocallResult);
        return -1;
    }

    result = ocall_setsockopt(&ocallResult, sockFd, RTLS_SOL_TCP, RTLS_TCP_KEEPIDLE,
                              &tcp_keepalive_time, sizeof(tcp_keepalive_time));
    if (result != SGX_SUCCESS || ocallResult < 0)
    {
        storeErrorInfo("Failed to set socket option. SGX status: 0x%.4x. Function return: %d.", result, ocallResult);
        return -1;
    }

    result = ocall_setsockopt(&ocallResult, sockFd, RTLS_SOL_TCP, RTLS_TCP_KEEPINTVL,
                              &tcp_keepalive_intvl, sizeof(tcp_keepalive_intvl));
    if (result != SGX_SUCCESS || ocallResult < 0)
    {
        storeErrorInfo("Failed to set socket option. SGX status: 0x%.4x. Function return: %d.", result, ocallResult);
        return -1;
    }

    result = ocall_setsockopt(&ocallResult, sockFd, RTLS_SOL_TCP, RTLS_TCP_KEEPCNT,
                              &tcp_keepalive_probes, sizeof(tcp_keepalive_probes));
    if (result != SGX_SUCCESS || ocallResult < 0)
    {
        storeErrorInfo("Failed to set socket option. SGX status: 0x%.4x. Function return: %d.", result, ocallResult);
        return -1;
    }

    struct rtls_sockaddr_in s_addr;
    memset(&s_addr, 0, sizeof(s_addr));
    s_addr.sin_family = RTLS_AF_INET;
    s_addr.sin_addr.s_addr = netAddr;
    s_addr.sin_port = netPort;

    /* Bind the server socket */
    result = ocall_bind(&ocallResult, sockFd, &s_addr, sizeof(s_addr));
    if (result != SGX_SUCCESS || ocallResult == -1)
    {
        storeErrorInfo("Failed to bind address. SGX status: 0x%.4x. Function return: %d.", result, ocallResult);
        return -1;
    }

    /* Listen for a new connection, allow 5 pending connections */
    result = ocall_listen(&ocallResult, sockFd, 5);
    if (result != SGX_SUCCESS || ocallResult == -1)
    {
        storeErrorInfo("Failed to listen. SGX status: 0x%.4x. Function return: %d.", result, ocallResult);
        return -1;
    }

    /* rats-tls init */
    librats_tls_init();
    rats_tls_handle ratsHandler;
    rats_tls_err_t ratsResult = rats_tls_init(&conf, &ratsHandler);
    if (ratsResult != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to initialize Rats-TLS. Rats-TLS error: %d.", ratsResult);
        return -1;
    }

    ratsResult = rats_tls_set_verification_callback(&ratsHandler, NULL);
    if (ratsResult != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to set verification callback in Rats-TLS. Rats-TLS error: %d.", ratsResult);
        return -1;
    }

    mainServerItem.m_socketHandler = sockFd;
    mainServerItem.m_ratsHandler = ratsHandler;

    return 0;
}

int64_t ecallAcceptConn()
{
    if (!mainServerItem.m_socketHandler || !mainServerItem.m_ratsHandler)
    {
        storeErrorInfo("The Rats-TLS wasn't initialized.");
        return -1;
    }

    sgx_status_t SGXResult = SGX_SUCCESS;
    int ratsResult = 0;
    uint8_t *recvBuffer = NULL;
    uint8_t *respBuffer = NULL;

    struct rtls_sockaddr_in clientAddr;
    uint32_t clientAddrLenIn = sizeof(clientAddr);
    uint32_t clientAddrLenOut = 0;

    int64_t connHandler;
    SGXResult = ocall_accept(&connHandler, mainServerItem.m_socketHandler, &clientAddr, clientAddrLenIn, &clientAddrLenOut);
    if (SGXResult != SGX_SUCCESS || connHandler < 0)
    {
        storeErrorInfo("Failed to accept. SGX status: 0x%.4x. Connection handler: %lld.", SGXResult, connHandler);
        return -1;
    }

    ratsResult = rats_tls_negotiate(mainServerItem.m_ratsHandler, connHandler);
    if (ratsResult != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to negotiate with client in Rats-TLS. Rats-TLS error: %d.", ratsResult);
        return -1;
    }

    mainServerItem.m_connHandler = connHandler;

    // Receive initialization message
    recvBuffer = (uint8_t *)malloc(256);
    if (!recvBuffer)
    {
        storeErrorInfo("Failed to allocate memory for received buffer.");
        goto COMM_ERR;
    }
    size_t bufferSize = sizeof(256);
    ratsResult = rats_tls_receive(mainServerItem.m_ratsHandler, recvBuffer, &bufferSize);
    if (ratsResult != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to receive in Rats-TLS. Rats-TLS error: %d.", ratsResult);
        goto COMM_ERR;
    }
    if (bufferSize < sizeof(BaseMessage))
    {
        storeErrorInfo("From client: the sent message is invalid (too small).");
        goto COMM_INVALID;
    }

    BaseMessage *recvMsg = (BaseMessage *)recvBuffer;
    if (recvMsg->m_size != strlen(TCS_INIT_QUERY_STR) + 1 || bufferSize < sizeof(BaseMessage) + strlen(TCS_INIT_QUERY_STR) + 1)
    {
        storeErrorInfo("From client: the sent message is invalid (unequal feature).");
        goto COMM_INVALID;
    }
    char *recv_query_str = (char *)(recvMsg->m_body);
    recv_query_str[strlen(TCS_INIT_QUERY_STR)] = '\0';
    if (strcmp(recv_query_str, TCS_INIT_QUERY_STR))
    {
        storeErrorInfo("From client: the sent message is invalid (unequal feature).");
        goto COMM_INVALID;
    }

    uint64_t unique_conn_id = 0;

    // response //
    respBuffer = (uint8_t *)malloc(sizeof(BaseMessage) + sizeof(unique_conn_id));
    if (!respBuffer)
    {
        storeErrorInfo("Failed to allocate memory for response buffer.");
        goto COMM_ERR;
    }
    BaseMessage *respMsg = (BaseMessage *)respBuffer;
    BaseMessage errRespMsg;
    respMsg->m_category = TCS_BASIC_MESSAGE;
    respMsg->m_type = TCS_INITIALIZATION_MESSAGE;
    respMsg->m_reserved[0] = respMsg->m_reserved[1] = 1;
    respMsg->m_size = sizeof(unique_conn_id);
    memcpy(respMsg->m_body, (uint8_t *)(&unique_conn_id), sizeof(unique_conn_id));
    bufferSize = sizeof(BaseMessage) + respMsg->m_size;
    ratsResult = rats_tls_transmit(mainServerItem.m_ratsHandler, (void *)(&respMsg), &bufferSize);
    if (ratsResult != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to send initialization query response message in Rats-TLS. Rats-TLS error: %d.", ratsResult);
        goto COMM_ERR;
    }

    SAFE_FREE(recvBuffer);
    SAFE_FREE(respBuffer);

    return 0;

COMM_INVALID:
    errRespMsg.m_category = TCS_BASIC_MESSAGE;
    errRespMsg.m_type = TCS_INITIALIZATION_MESSAGE;
    errRespMsg.m_reserved[0] = errRespMsg.m_reserved[1] = 0;
    errRespMsg.m_size = 0;
    bufferSize = sizeof(errRespMsg);
    ratsResult = rats_tls_transmit(mainServerItem.m_ratsHandler, (void *)(&errRespMsg), &bufferSize);
    if (ratsResult != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to send initialization query response message (error feedback) in Rats-TLS. Rats-TLS error: %d.", ratsResult);
        goto COMM_ERR;
    }
    ocall_close(&ratsResult, connHandler);

    SAFE_FREE(recvBuffer);
    SAFE_FREE(respBuffer);

    return 1;

COMM_ERR:
    ocall_close(&ratsResult, connHandler);

    SAFE_FREE(recvBuffer);
    SAFE_FREE(respBuffer);

    return -1;
}

int64_t ecallCloseConn()
{
    int ret = 0;
    ocall_close(&ret, mainServerItem.m_connHandler);

    return 0;
}

int64_t ecallCloseRatsServer()
{
    int ret = 0;
    ocall_close(&ret, mainServerItem.m_connHandler);
    rats_tls_cleanup(mainServerItem.m_ratsHandler);

    return 0;
}