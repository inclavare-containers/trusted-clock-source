/**
 *
 *
 *
 */

#ifndef TCS_COMMUTILS_H_
#define TCS_COMMUTILS_H_

#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>

namespace TCS
{
    uint32_t parseIPv4Address(const std::string &ipv4_addr)
    {
        return inet_addr(ipv4_addr.c_str());
    }

    uint16_t convertToNetPort(uint16_t port)
    {
        return htons(port);
    }
}

#endif