/**
 *
 *
 *
 */

#ifndef TCS_TCSMESSAGE_H_
#define TCS_TCSMESSAGE_H_

#include <stdint.h>

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
        uint8_t m_body[];
    } EncMessage;

#define TCS_INIT_QUERY_STR "QUERY"

#define TCS_ERROR_INFO_MAX_LEN 4096

#ifdef __cplusplus
}
#endif

#endif