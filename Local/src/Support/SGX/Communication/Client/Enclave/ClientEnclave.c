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

#include "ClientEnclave_t.h"

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

typedef struct __ClientItemT
{
    rats_tls_handle m_ratsHandler;
    MessageKey m_key;
} ClientItemT;

static ClientItemT mainClientItem = {.m_ratsHandler = NULL};

static char mainClientError[TCS_ERROR_INFO_MAX_LEN] = {'\0'};

static void storeErrorInfo(const char *__restrict__ _format, ...)
{
    va_list argptr;
    va_start(argptr, _format);
    snprintf(mainClientError, TCS_ERROR_INFO_MAX_LEN - 1, _format, argptr);
    va_end(argptr);
}

void ecallGetClientError(char *errorInfo, size_t infoLen)
{
    --infoLen;
    size_t rawInfoLen = strlen(mainClientError);
    size_t copiedInfoLen = rawInfoLen > infoLen ? infoLen : rawInfoLen;
    strncpy(errorInfo, mainClientError, copiedInfoLen);
    errorInfo[copiedInfoLen] = '\0';
}

int user_callback(void *args)
{
    rtls_evidence_t *ev = (rtls_evidence_t *)args;

    printf("verify_callback called, claims %p, claims_size %zu, args %p\n", ev->custom_claims,
           ev->custom_claims_length, args);
    for (size_t i = 0; i < ev->custom_claims_length; ++i)
    {
        printf("custom_claims[%zu] -> name: '%s' value_size: %zu value: '%.*s'\n", i,
               ev->custom_claims[i].name, ev->custom_claims[i].value_size,
               (int)ev->custom_claims[i].value_size, ev->custom_claims[i].value);
    }
    return 1;
}

int64_t ecallStartRatsClient(
    uint32_t serverAddr,
    uint16_t serverPort,
    unsigned flags,
    const char *attesterType,
    const char *verifierType,
    const char *tlsType,
    const char *cryptoType)
{
    sgx_status_t sgxStatus = SGX_SUCCESS;
    int ocallReturn = 0;
    rats_tls_err_t ratsReturn = RATS_TLS_ERR_NONE;
    rats_tls_conf_t conf;

    memset(&conf, 0, sizeof(conf));

    snprintf(conf.attester_type, sizeof(conf.attester_type), "%s", attesterType);
    snprintf(conf.verifier_type, sizeof(conf.verifier_type), "%s", verifierType);
    snprintf(conf.tls_type, sizeof(conf.tls_type), "%s", tlsType);
    snprintf(conf.crypto_type, sizeof(conf.crypto_type), "%s", cryptoType);
    conf.flags = flags;
    conf.cert_algo = RATS_TLS_CERT_ALGO_DEFAULT;

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol.
     */
    int64_t sockFd;
    sgxStatus = ocall_socket(&sockFd, RTLS_AF_INET, RTLS_SOCK_STREAM, 0);
    if (sgxStatus != SGX_SUCCESS || sockFd < 0)
    {
        storeErrorInfo("Failed to initialize socket. SGX status: 0x%.4x. Socket file handler: %lld.", sgxStatus, sockFd);
        return -1;
    }

    struct rtls_sockaddr_in s_addr;
    memset(&s_addr, 0, sizeof(s_addr));
    s_addr.sin_family = RTLS_AF_INET;
    s_addr.sin_addr.s_addr = serverAddr;
    s_addr.sin_port = serverPort;

    /* Connect to the server */
    sgxStatus = ocall_connect(&ocallReturn, sockFd, &s_addr, sizeof(s_addr));
    if (sgxStatus != SGX_SUCCESS || ocallReturn == -1)
    {
        storeErrorInfo("Failed to connect. SGX status: 0x%.4x. OCall function return: %d.", sgxStatus, ocallReturn);
        return -1;
    }

    /* rats-tls init */
    librats_tls_init();
    rats_tls_handle ratsHandler;
    ratsReturn = rats_tls_init(&conf, &ratsHandler);
    if (ratsReturn != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to initialize Rats-TLS. Rats-TLS error: %d.", ratsReturn);
        return -1;
    }

    ratsReturn = rats_tls_set_verification_callback(&ratsHandler, user_callback);
    if (ratsReturn != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to set up verification callback in Rats-TLS. Rats-TLS error: %d.", ratsReturn);
        return -1;
    }

    ratsReturn = rats_tls_negotiate(ratsHandler, (int)sockFd);
    if (ratsReturn != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to negotiate in Rats-TLS. Rats-TLS error: %d.", ratsReturn);
        goto COMM_ERR;
    }

    mainClientItem.m_ratsHandler = ratsHandler;

    uint8_t *sendBuffer = NULL;
    uint8_t *recvBuffer = NULL;

    size_t sendBufferSize = sizeof(BaseMessage) + strlen(TCS_INIT_QUERY_STR) + 1;
    sendBuffer = (uint8_t *)malloc(sendBufferSize);
    if (!sendBuffer)
    {
        storeErrorInfo("Failed to allocate memory for sent buffer.");
        goto COMM_MSG_ERR;
    }
    BaseMessage *sendMsg = (BaseMessage *)sendBuffer;
    sendMsg->m_category = TCS_BASIC_MESSAGE;
    sendMsg->m_type = TCS_INITIALIZATION_MESSAGE;
    sendMsg->m_size = strlen(TCS_INIT_QUERY_STR) + 1;
    sendMsg->m_reserved[0] = sendMsg->m_reserved[1] = 1;
    strncpy((char *)(sendMsg->m_body), TCS_INIT_QUERY_STR, strlen(TCS_INIT_QUERY_STR));
    sendMsg->m_body[strlen(TCS_INIT_QUERY_STR)] = '\0';

    size_t tmpBufferSize = sendBufferSize;
    ratsReturn = rats_tls_transmit(ratsHandler, (void *)sendBuffer, &tmpBufferSize);
    if (ratsReturn != RATS_TLS_ERR_NONE || tmpBufferSize != sendBufferSize)
    {
        storeErrorInfo("Failed to send initialization query in Rats-TLS. Rats-TLS error: %d.", ratsReturn);
        goto COMM_MSG_ERR;
    }

    recvBuffer = (uint8_t *)malloc(512);
    if (!recvBuffer)
    {
        storeErrorInfo("Failed to allocate memory for received buffer.");
        goto COMM_MSG_ERR;
    }
    tmpBufferSize = 512;
    ratsReturn = rats_tls_receive(ratsHandler, recvBuffer, &tmpBufferSize);
    if (tmpBufferSize < sizeof(BaseMessage))
    {
        storeErrorInfo("The received message is invalid (too small).");
        goto COMM_MSG_ERR;
    }
    BaseMessage *recvMsg = (BaseMessage *)recvBuffer;
    if (tmpBufferSize < sizeof(BaseMessage) + recvMsg->m_size)
    {
        storeErrorInfo("The received message is invalid (too small).");
        goto COMM_MSG_ERR;
    }
    if (recvMsg->m_reserved[0] == 0)
    {
        storeErrorInfo("From server: the sent message is invalid.");
        goto COMM_MSG_ERR;
    }

    SAFE_FREE(sendBuffer);
    SAFE_FREE(recvBuffer);

    return 0;

COMM_MSG_ERR:
    rats_tls_cleanup(ratsHandler);

    SAFE_FREE(sendBuffer);
    SAFE_FREE(recvBuffer);

    return -2;

COMM_ERR:
    rats_tls_cleanup(ratsHandler);
    return -1;
}

int64_t ecallStopRatsClient()
{
    rats_tls_cleanup(mainClientItem.m_ratsHandler);

    return 0;
}

int64_t ecallExchangeClientKey()
{
    uint8_t *sendBuffer = NULL;
    uint8_t *recvBuffer = NULL;
    char *recvVerifyStr = NULL;
    sgx_status_t sgxStatus = SGX_SUCCESS;
    rats_tls_err_t ratsReturn = RATS_TLS_ERR_NONE;

    MessageKey clientKey;
    generateRandomBytes(clientKey, TCS_AES_KEY_SIZE);

    /* Message to be sent */
    size_t bufferSize = sizeof(BaseMessage) + TCS_AES_KEY_SIZE;
    sendBuffer = (uint8_t *)malloc(bufferSize);
    if (!sendBuffer)
    {
        storeErrorInfo("Failed to allocate memory for sent buffer");
        goto COMM_ERR;
    }
    BaseMessage *sendBaseMsg = (BaseMessage *)sendBuffer;
    sendBaseMsg->m_category = TCS_BASIC_MESSAGE;
    sendBaseMsg->m_type = TCS_KEY_EXCHANGE_MESSAGE;
    sendBaseMsg->m_reserved[0] = 1;
    sendBaseMsg->m_reserved[1] = 1;
    sendBaseMsg->m_size = TCS_AES_KEY_SIZE;
    memcpy(sendBaseMsg->m_body, clientKey, TCS_AES_KEY_SIZE);

    /* Send message */
    ratsReturn = rats_tls_transmit(mainClientItem.m_ratsHandler, sendBuffer, &bufferSize);
    if (ratsReturn != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to send key exchange request message. Rats-TLS return: %d", ratsReturn);
        goto COMM_SERVER_ERR;
    }

    /* Receive message */
    bufferSize = 256;
    recvBuffer = (uint8_t *)malloc(bufferSize);
    if (!recvBuffer)
    {
        storeErrorInfo("Failed to allocate memory for received buffer");
        goto COMM_ERR;
    }
    ratsReturn = rats_tls_receive(mainClientItem.m_ratsHandler, recvBuffer, &bufferSize);
    if (ratsReturn != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to receive key exchange response message. Rats-TLS return: %d", ratsReturn);
        goto COMM_ERR;
    }
    if (bufferSize < sizeof(BaseMessage) + TCS_AES_KEY_SIZE)
    {
        storeErrorInfo("Server Error: received invalid message for key exchange.");
        goto COMM_SERVER_ERR;
    }

    /* Message received */
    BaseMessage *recvBaseMsg = (BaseMessage *)recvBuffer;
    if (recvBaseMsg->m_size != TCS_AES_KEY_SIZE || recvBaseMsg->m_category != TCS_BASIC_MESSAGE || recvBaseMsg->m_type != TCS_KEY_EXCHANGE_MESSAGE)
    {
        storeErrorInfo("Server Error: received invalid message for key exchange.");
        goto COMM_SERVER_ERR;
    }
    if (recvBaseMsg->m_reserved[0] == 0)
    {
        storeErrorInfo("From server: invalid request message for key exchange.");
        goto COMM_SERVER_ERR;
    }

    /* Message Key */
    for (int i = 0; i < TCS_AES_KEY_SIZE; ++i)
    {
        mainClientItem.m_key[i] = clientKey[i] ^ recvBaseMsg->m_body[i];
    }

    SAFE_FREE(sendBuffer);
    SAFE_FREE(recvBuffer);
    SAFE_FREE(recvVerifyStr);

    bufferSize = sizeof(EncMessage) + strlen(TCS_KEY_VERIFY_STR) + 1;
    sendBuffer = (uint8_t *)malloc(bufferSize);
    if (!sendBuffer)
    {
        storeErrorInfo("Failed to allocate memory for sent buffer");
        goto COMM_ERR;
    }
    EncMessage *sendEncMsg = (EncMessage *)sendBuffer;
    sendEncMsg->m_category = TCS_ENCRYPTED_MESSAGE;
    sendEncMsg->m_type = TCS_KEY_EXCHANGE_MESSAGE;
    sendEncMsg->m_reserved[0] = 1;
    sendEncMsg->m_reserved[1] = 1;
    sendEncMsg->m_size = strlen(TCS_KEY_VERIFY_STR) + 1;
    /* Encrypt message */
    sgxStatus = encryptData(
        &mainClientItem.m_key,
        &sendEncMsg->m_iv,
        &sendEncMsg->m_tag,
        (uint8_t *)TCS_KEY_VERIFY_STR,
        strlen(TCS_KEY_VERIFY_STR) + 1,
        sendEncMsg->m_body);
    if (sgxStatus != SGX_SUCCESS)
    {
        storeErrorInfo("Failed to encrypt the response message for key verification. SGX error: %.4x", sgxStatus);
        goto COMM_ERR;
    }

    /* Send encrypted message */
    ratsReturn = rats_tls_transmit(mainClientItem.m_ratsHandler, sendBuffer, &bufferSize);
    if (ratsReturn != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to send key verification request message. Rats-TLS return: %d", ratsReturn);
        goto COMM_SERVER_ERR;
    }

    bufferSize = 256;
    recvBuffer = (uint8_t *)malloc(bufferSize);
    if (!recvBuffer)
    {
        storeErrorInfo("Failed to allocate memory for received buffer");
        goto COMM_ERR;
    }

    /* Receive */
    ratsReturn = rats_tls_receive(mainClientItem.m_ratsHandler, recvBuffer, &bufferSize);
    if (ratsReturn != RATS_TLS_ERR_NONE)
    {
        storeErrorInfo("Failed to receive key verification response message. Rats-TLS return: %d", ratsReturn);
        goto COMM_SERVER_ERR;
    }
    if (bufferSize < sizeof(EncMessage) + strlen(TCS_KEY_VERIFY_STR) + 1)
    {
        storeErrorInfo("Server Error: received invalid message for key verification.");
        goto COMM_SERVER_ERR;
    }

    EncMessage *recvEncMsg = (EncMessage *)recvBuffer;
    if (recvEncMsg->m_size != strlen(TCS_KEY_VERIFY_STR) + 1 || recvEncMsg->m_category != TCS_ENCRYPTED_MESSAGE || recvEncMsg->m_type != TCS_KEY_EXCHANGE_MESSAGE)
    {
        storeErrorInfo("Server Error: received invalid message for key verification.");
        goto COMM_SERVER_ERR;
    }
    if (recvEncMsg->m_reserved[0] == 0)
    {
        storeErrorInfo("From server: invalid request message for key exchange.");
        goto COMM_SERVER_ERR;
    }

    recvVerifyStr = (char *)malloc(strlen(TCS_KEY_VERIFY_STR) + 1);
    if (!recvVerifyStr)
    {
        storeErrorInfo("Failed to allocate memory for strings");
        goto COMM_ERR;
    }
    sgxStatus = decryptData(
        &mainClientItem.m_key,
        &recvEncMsg->m_iv,
        &recvEncMsg->m_tag,
        recvEncMsg->m_body,
        recvEncMsg->m_size,
        (uint8_t *)recvVerifyStr);
    if (sgxStatus != SGX_SUCCESS)
    {
        storeErrorInfo("Failed to decrypt the received message for key verification.");
        goto COMM_SERVER_ERR;
    }
    if (strcmp(recvVerifyStr, TCS_KEY_VERIFY_STR) != 0)
    {
        storeErrorInfo("Failed to verify key.");
        goto COMM_SERVER_ERR;
    }

    SAFE_FREE(sendBuffer);
    SAFE_FREE(recvBuffer);
    SAFE_FREE(recvVerifyStr);

    return 0;

COMM_SERVER_ERR:

    SAFE_FREE(sendBuffer);
    SAFE_FREE(recvBuffer);
    SAFE_FREE(recvVerifyStr);

    return 1;

COMM_ERR:

    SAFE_FREE(sendBuffer);
    SAFE_FREE(recvBuffer);
    SAFE_FREE(recvVerifyStr);

    rats_tls_cleanup(mainClientItem.m_ratsHandler);
    return -1;
}