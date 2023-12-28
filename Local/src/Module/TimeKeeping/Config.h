/**
 *
 */

#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define AES_IV_SIZE 12
#define AES_TAG_SIZE 16
#define AES_KEY_SIZE 16

    /* Message Struct */
    typedef struct __message_t
    {
        uint8_t type;        // A 8-bit message type
        uint8_t reserved[3]; // Reserved for future use
        uint32_t size;       // Body size
        uint8_t body[];      // Message body
    } message_t;

    /* Encrypted Body Struct */
    typedef struct __enc_body_t
    {
        uint8_t iv[AES_IV_SIZE];   // Initialization vector
        uint8_t tag[AES_TAG_SIZE]; // Tag
        uint32_t size;             // Payload size
        uint8_t payload[];         // Payload
    } enc_body_t;

    /* Struct of Timestamp */
    typedef struct __timestamp_t
    {
        union
        {
            struct
            {
                uint32_t era_n;           // Era number
                uint32_t sec_since_epoch; // Seconds since era epoch
            };
            uint64_t low_value; // Low bytes
        };
        union
        {
            uint64_t fraction;   // Fraction of second
            uint64_t high_value; // High bytes
        };
    } timestamp_t;

    /* Struct of Timestamp Group */
    typedef struct __timestamp_group_t
    {
        uint32_t size;
        timestamp_t group[];
    } timestamp_group_t;

    /**
     * Get the delta time (ns) of two timestamps
     * = (t1 - t2)
     */
    int64_t get_delta_time_ns(const timestamp_t *t1, const timestamp_t *t2);

#ifdef __cplusplus
}
#endif

#endif