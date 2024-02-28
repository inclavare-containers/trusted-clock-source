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
#include "EnclaveUtils.h"

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
    MessageKey m_key;
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
    size_t bufferSize = 256;
    recvBuffer = (uint8_t *)malloc(bufferSize);
    if (!recvBuffer)
    {
        storeErrorInfo("Failed to allocate memory for received buffer for initialization message.");
        goto COMM_ERR;
    }
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
    bufferSize = sizeof(BaseMessage) + sizeof(unique_conn_id);
    respBuffer = (uint8_t *)malloc(bufferSize);
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
    ratsResult = rats_tls_transmit(mainServerItem.m_ratsHandler, respBuffer, &bufferSize);
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

int64_t ecallExchangeServerKey()
{
    int64_t connHandler = mainServerItem.m_connHandler;
    sgx_status_t sgxStatus = SGX_SUCCESS;
    int ratsResult = 0;
    uint8_t *recvBuffer = NULL;
    uint8_t *respBuffer = NULL;
    char *recvVerifyStr = NULL;
    BaseMessage errRespMsg;

    // Receive request message for key exchange
    size_t bufferSize = 256;
    recvBuffer = (uint8_t *)malloc(bufferSize);
    if (!recvBuffer)
    {
        storeErrorInfo("Failed to allocate memory for received buffer for key exchange.");
        goto COMM_ERR;
    }
    ratsResult = rats_tls_receive(mainServerItem.m_ratsHandler, recvBuffer, &bufferSize);
    if (ratsResult != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to receive in Rats-TLS for key exchange. Rats-TLS error: %d.", ratsResult);
        goto COMM_ERR;
    }
    if (bufferSize < sizeof(BaseMessage))
    {
        storeErrorInfo("From client: the sent message is invalid (too small).");
        goto COMM_INVALID;
    }

    BaseMessage *recvMsg = (BaseMessage *)recvBuffer;
    if (bufferSize < sizeof(BaseMessage) + recvMsg->m_size)
    {
        storeErrorInfo("From client: the sent message is invalid (too small).");
        goto COMM_INVALID;
    }
    if (recvMsg->m_size != TCS_AES_KEY_SIZE)
    {
        storeErrorInfo("From client: the sent message is invalid (invalid exchange key information).");
        goto COMM_INVALID;
    }

    MessageKey serverKey;
    generateRandomBytes(serverKey, TCS_AES_KEY_SIZE);

    for (int i = 0; i < TCS_AES_KEY_SIZE; ++i)
    {
        mainServerItem.m_key[i] = serverKey[i] ^ (recvMsg->m_body[i]);
    }

    bufferSize = sizeof(BaseMessage) + TCS_AES_KEY_SIZE;
    respBuffer = (uint8_t *)malloc(bufferSize);
    if (!respBuffer)
    {
        storeErrorInfo("Failed to allocate memory for response buffer.");
        goto COMM_ERR;
    }
    BaseMessage *respMsg = (BaseMessage *)respBuffer;
    respMsg->m_category = TCS_BASIC_MESSAGE;
    respMsg->m_type = TCS_KEY_EXCHANGE_MESSAGE;
    respMsg->m_reserved[0] = 1;
    respMsg->m_reserved[1] = 1;
    respMsg->m_size = TCS_AES_KEY_SIZE;
    memcpy(respMsg->m_body, serverKey, TCS_AES_KEY_SIZE);
    ratsResult = rats_tls_transmit(mainServerItem.m_ratsHandler, respBuffer, &bufferSize);
    if (ratsResult != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to send response message in Rats-TLS for key exchange. Rats-TLS error: %d.", ratsResult);
        goto COMM_ERR;
    }

    SAFE_FREE(recvBuffer);
    SAFE_FREE(respBuffer);
    SAFE_FREE(recvVerifyStr);

    // Receive request message for key verification
    bufferSize = 256;
    recvBuffer = (uint8_t *)malloc(bufferSize);
    if (!recvBuffer)
    {
        storeErrorInfo("Failed to allocate memory for received buffer for key exchange.");
        goto COMM_ERR;
    }
    ratsResult = rats_tls_receive(mainServerItem.m_ratsHandler, recvBuffer, &bufferSize);
    if (ratsResult != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to receive in Rats-TLS for key exchange. Rats-TLS error: %d.", ratsResult);
        goto COMM_ERR;
    }
    if (bufferSize < sizeof(EncMessage))
    {
        storeErrorInfo("From client: the sent message is invalid (too small).");
        goto COMM_INVALID;
    }

    EncMessage *recvEncMsg = (EncMessage *)recvBuffer;
    if (bufferSize < sizeof(EncMessage) + recvEncMsg->m_size)
    {
        storeErrorInfo("From client: the sent message is invalid (too small).");
        goto COMM_INVALID;
    }
    if (recvEncMsg->m_size != strlen(TCS_KEY_VERIFY_STR) + 1)
    {
        storeErrorInfo("From client: the sent message is invalid (invalid key verification information).");
        goto COMM_INVALID;
    }

    // decrypt the message
    recvVerifyStr = (char *)malloc(recvEncMsg->m_size);
    memset(recvVerifyStr, 0, recvEncMsg->m_size);
    sgxStatus = decryptData(
        &mainServerItem.m_key,
        &recvEncMsg->m_iv,
        &recvEncMsg->m_tag,
        recvEncMsg->m_body,
        recvEncMsg->m_size,
        (uint8_t *)recvVerifyStr);
    if (sgxStatus != SGX_SUCCESS)
    {
        storeErrorInfo("From client: the sent message is invalid (failed to decrypt the message; SGX: %.4x)", sgxStatus);
        goto COMM_INVALID;
    }

    if (strcmp(recvVerifyStr, TCS_KEY_VERIFY_STR) != 0)
    {
        storeErrorInfo("From client: the sent message is invalid (invalid key verification information).");
        goto COMM_INVALID;
    }

    bufferSize = sizeof(EncMessage) + strlen(TCS_KEY_VERIFY_STR) + 1;
    respBuffer = (uint8_t *)malloc(bufferSize);
    if (!respBuffer)
    {
        storeErrorInfo("Failed to allocate memory for response buffer.");
        goto COMM_ERR;
    }
    EncMessage *respEncMsg = (EncMessage *)respBuffer;
    respEncMsg->m_category = TCS_ENCRYPTED_MESSAGE;
    respEncMsg->m_type = TCS_KEY_EXCHANGE_MESSAGE;
    respEncMsg->m_reserved[0] = 1;
    respEncMsg->m_reserved[1] = 1;
    respEncMsg->m_size = strlen(TCS_KEY_VERIFY_STR) + 1;
    // generate a nonce
    generateRandomBytes(respEncMsg->m_nonce, TCS_ENC_NONCE_SIZE);
    // encrypt message
    sgxStatus = encryptData(
        &mainServerItem.m_key,
        &respEncMsg->m_iv,
        &respEncMsg->m_tag,
        (uint8_t *)TCS_KEY_VERIFY_STR,
        strlen(TCS_KEY_VERIFY_STR) + 1,
        respEncMsg->m_body);
    if (sgxStatus != SGX_SUCCESS)
    {
        storeErrorInfo("Failed to encrypt the response message for key verification. SGX: %.4x", sgxStatus);
        goto COMM_ERR;
    }
    ratsResult = rats_tls_transmit(mainServerItem.m_ratsHandler, respBuffer, &bufferSize);
    if (ratsResult != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to send response message in Rats-TLS for key verification. Rats-TLS error: %d.", ratsResult);
        goto COMM_ERR;
    }

    SAFE_FREE(recvBuffer);
    SAFE_FREE(respBuffer);
    SAFE_FREE(recvVerifyStr);

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
    SAFE_FREE(recvVerifyStr);

    return 1;

COMM_ERR:
    ocall_close(&ratsResult, connHandler);

    SAFE_FREE(recvBuffer);
    SAFE_FREE(respBuffer);
    SAFE_FREE(recvVerifyStr);

    return -1;
}