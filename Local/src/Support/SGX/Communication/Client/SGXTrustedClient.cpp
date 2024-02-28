/**
 *
 *
 *
 */

#include "SGXTrustedClient.h"
#include "SGXUtils.hpp"

#include "ClientEnclave_u.h"

#ifndef TCS_RATS_GLOBAL_INIT
#include "rats-tls/log.h"
rats_tls_log_level_t global_log_level = RATS_TLS_LOG_LEVEL_DEFAULT;
#define TCS_RATS_GLOBAL_INIT
#endif

// debug
#include <iostream>

namespace TCS
{
    namespace SGX_UP
    {
        void SGXTrustedClient::start(const std::string &_addr, uint16_t _port)
        {
            m_serverAddr = _addr;
            m_serverPort = _port;
            this->start();
        }

        void SGXTrustedClient::start()
        {
            uint32_t serverAddr = parseIPv4Address(m_serverAddr);
            uint16_t serverPort = convertToNetPort(m_serverPort);

            bool isDebugEnclave = false;
            m_enclaveID = loadEnclave(m_enclaveFilePath, isDebugEnclave);
            if (m_enclaveID == 0)
            {
                // // debug
                // printf("Failed to load enclave\n");

                throw SGXErrorException("Failed to load enclave '" + m_enclaveFilePath + "'");
            }

            unsigned flags = 0;
            if (m_mutualAtte)
                flags |= RATS_TLS_CONF_FLAGS_MUTUAL;

            int64_t ecallRet = 0;
            sgx_status_t sgxStatus = ecallStartRatsClient(
                m_enclaveID,
                &ecallRet,
                serverAddr,
                serverPort,
                flags,
                m_attesterType.c_str(),
                m_verifierType.c_str(),
                m_tlsType.c_str(),
                m_cryptoType.c_str());

            if (sgxStatus != SGX_SUCCESS)
            {
                // // debug
                // printf("Failed to call 'ecallStartRatsClient'\n");

                throw SGXErrorException("Failed to start Rats-TLS server", sgxStatus);
            }

            if (ecallRet < 0)
            {
                std::string errInfo = getErrorInfoFromEnclave(m_enclaveID, ecallGetClientError);

                // // debug
                // printf("'ecallStartRatsClient' returns %d. Error: %s\n", ecallRet, errInfo.c_str());

                if (ecallRet == -1)
                    throw ECallErrorException("start Rats-TLS server", errInfo);
                else if (ecallRet == -2)
                    throw ECallErrorException("send initialization information to Rats-TLS server", errInfo);
            }
        }

        void SGXTrustedClient::stop()
        {
            if (m_enclaveID == 0)
                throw UnInitializedException("In function 'SGXTrustedClient::stop'", "m_enclaveID");

            int64_t ecallRet = 0;
            sgx_status_t sgxStatus = ecallStopRatsClient(m_enclaveID, &ecallRet);

            if (sgxStatus != SGX_SUCCESS)
                throw SGXErrorException("Failed to start Rats-TLS server", sgxStatus);

            if (ecallRet == -1)
                throw ECallErrorException("stop Rats-TLS client", getErrorInfoFromEnclave(m_enclaveID, ecallGetClientError));
        }

        void SGXTrustedClient::exchangeKey()
        {
            if (m_enclaveID == 0)
                throw UnInitializedException("In function 'SGXTrustedClient::exchangeKey'", "m_enclaveID");

            int64_t ecallRet = 0;
            sgx_status_t sgxStatus = ecallExchangeClientKey(m_enclaveID, &ecallRet);

            if (sgxStatus != SGX_SUCCESS)
                throw SGXErrorException("Failed to exchange key for Rats-TLS client", sgxStatus);

            if (ecallRet)
            {
                std::string clientErrorInfo = getErrorInfoFromEnclave(m_enclaveID, ecallGetClientError);

                if (ecallRet == -1)
                    throw ECallErrorException("exchange key for Rats-TLS client", clientErrorInfo);
                else if (ecallRet == 1)
                {
                    // debug
                    std::cerr << "[TCS DEBUG] " << clientErrorInfo << std::endl;
                }
            }
        }
    }
}