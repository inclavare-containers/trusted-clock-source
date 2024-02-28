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

#include "TCSExcept.hpp"

namespace TCS
{
    inline uint32_t parseIPv4Address(const std::string &ipv4_addr)
    {
        uint32_t returnAddr = inet_addr(ipv4_addr.c_str());
        if (returnAddr == INADDR_NONE)
            throw InvalidArgumentException("Wrong IPv4 address", ipv4_addr);
        return inet_addr(ipv4_addr.c_str());
    }

    inline uint16_t convertToNetPort(uint16_t port)
    {
        return htons(port);
    }
}

#endif