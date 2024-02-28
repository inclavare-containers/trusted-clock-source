/**
 *
 *
 *
 */

#ifndef TCS_ENCLAVEUTILS_H_
#define TCS_ENCLAVEUTILS_H_

#include "TCSMessage.h"

#include "sgx_trts.h"

void generateRandomBytes(uint8_t *_byteArr, size_t _size);

sgx_status_t decryptData(
    const MessageKey *pKey,
    const MessageInitVector *pInitVector,
    const MessageTag *pTag,
    const uint8_t *srcData,
    size_t srcSize,
    uint8_t *dstData);

sgx_status_t encryptData(
    const MessageKey *pKey,
    MessageInitVector *pInitVector,
    MessageTag *pTag,
    const uint8_t *srcData,
    size_t srcSize,
    uint8_t *dstData);

#endif