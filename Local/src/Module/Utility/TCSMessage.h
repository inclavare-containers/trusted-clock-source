/**
 *
 *
 *
 */

#ifndef TCS_TCSMESSAGE_H_
#define TCS_TCSMESSAGE_H_

#include <stdint.h>
#include <stddef.h>

#define TCS_AES_KEY_SIZE 16
#define TCS_AES_TAG_SIZE 16
#define TCS_AES_IV_SIZE 12
#define TCS_ENC_NONCE_SIZE 12

#define TCS_INIT_QUERY_STR "__QUERY__"
#define TCS_KEY_VERIFY_STR "__KEY_VERIFY__"

#define TCS_ERROR_INFO_MAX_LEN 4096

typedef uint8_t MessageKey[TCS_AES_KEY_SIZE];
typedef uint8_t MessageInitVector[TCS_AES_IV_SIZE];
typedef uint8_t MessageTag[TCS_AES_TAG_SIZE];
typedef uint8_t MessageNonce[TCS_ENC_NONCE_SIZE];

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum __MsgCategory
    {
        TCS_BASIC_MESSAGE = 0,
        TCS_ENCRYPTED_MESSAGE
    } MsgCategory;

    typedef enum __MsgType
    {
        TCS_INITIALIZATION_MESSAGE = 0,
        TCS_KEY_EXCHANGE_MESSAGE
    } MsgType;

    typedef struct __BaseMessage
    {
        uint8_t m_category;
        uint8_t m_type;
        uint8_t m_reserved[2];
        uint32_t m_size;
        uint8_t m_body[];
    } BaseMessage;

    typedef struct __EncMessage
    {
        uint8_t m_category;
        uint8_t m_type;
        uint8_t m_reserved[2];
        uint32_t m_size;
        MessageNonce m_nonce;
        MessageInitVector m_iv;
        MessageTag m_tag;
        uint8_t m_body[];
    } EncMessage;

#ifdef __cplusplus
}
#endif

#endif