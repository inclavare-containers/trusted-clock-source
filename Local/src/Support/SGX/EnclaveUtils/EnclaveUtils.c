/**
 *
 *
 *
 */

#include "EnclaveUtils.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"

void generateRandomBytes(uint8_t *_byteArr, size_t _size)
{
    for (size_t i = 0; i < _size; ++i)
    {
        if (SGX_SUCCESS == sgx_read_rand((_byteArr + i), sizeof(uint8_t)))
            *(_byteArr + i) = 0;
    }
}

sgx_status_t decryptData(
    const MessageKey *pKey,
    const MessageInitVector *pInitVector,
    const MessageTag *pTag,
    const uint8_t *srcData,
    size_t srcSize,
    uint8_t *dstData)
{
    return sgx_rijndael128GCM_decrypt(
        (const sgx_aes_gcm_128bit_key_t *)pKey,
        srcData,
        srcSize,
        dstData,
        *pInitVector,
        TCS_AES_IV_SIZE,
        NULL,
        0,
        (const sgx_aes_gcm_128bit_tag_t *)pTag);
}

sgx_status_t encryptData(
    const MessageKey *pKey,
    MessageInitVector *pInitVector,
    MessageTag *pTag,
    const uint8_t *srcData,
    size_t srcSize,
    uint8_t *dstData)
{
    generateRandomBytes(*pInitVector, TCS_AES_IV_SIZE);
    return sgx_rijndael128GCM_encrypt(
        (const sgx_aes_gcm_128bit_key_t *)pKey,
        srcData,
        srcSize,
        dstData,
        *pInitVector,
        TCS_AES_IV_SIZE,
        NULL,
        0,
        (sgx_aes_gcm_128bit_tag_t *)pTag);
}