/**
 *
 *
 *
 */

#ifndef TCS_TRUSTEDCOMM_H_
#define TCS_TRUSTEDCOMM_H_

#include <cstdint>
#include <string>

#include "CommUtils.hpp"

namespace TCS
{
    class TrustedComm
    {
    private:
    public:
        TrustedComm() = default;
        ~TrustedComm() = default;

        virtual void start() = 0;
        virtual void stop() = 0;
    };

    class TrustedServer : public TrustedComm
    {
    protected:
        uint16_t m_port;

    public:
        TrustedServer() : m_port(2333) {}
        TrustedServer(uint16_t _port) : m_port(_port) {}
        ~TrustedServer() = default;

        virtual void start(uint16_t _port) = 0;
    };

    class TrustedClient : public TrustedComm
    {
    protected:
        std::string m_serverAddr;
        uint16_t m_serverPort;

    public:
        TrustedClient() = default;

        /// @brief Constructor for `TrustedClient` using a address string
        /// @param _addr
        /// @param _port
        /// @exception
        TrustedClient(const std::string &_addr, uint16_t _port) : m_serverAddr(_addr), m_serverPort(_port) {}

        ~TrustedClient() = default;
    };

}

#endif