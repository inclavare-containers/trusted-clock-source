/**
 *
 *
 */

#include "SGXTrustedServer.h"

#include "SGXExcept.hpp"
#include "SGXUtils.hpp"

#include "CommUtils.hpp"

#include <cstring>
#include <string>

#include "sgx_urts.h"

#include "rats-tls/api.h"

#include "ServerEnclave_u.h"

// debug
#include <iostream>

namespace TCS
{
    namespace SGX_UP
    {
        void SGXTrustedServer::start(uint16_t _port)
        {
            m_port = _port;
            this->start();
        }

        void SGXTrustedServer::start()
        {
            uint32_t serverIP = parseIPv4Address(m_localIP);
            uint16_t serverPort = convertToNetPort(m_port);

            bool isDebugEnclave = false;
            m_enclaveID = loadEnclave(m_enclaveFilePath, isDebugEnclave);
            if (m_enclaveID == 0)
                throw SGXErrorException("Failed to load enclave '" + m_enclaveFilePath + "'");

            unsigned long flags = 0;
            flags |= RATS_TLS_CONF_FLAGS_SERVER;
            if (m_mutualAtte)
                flags |= RATS_TLS_CONF_FLAGS_MUTUAL;

            int64_t ecallRet = 0;
            sgx_status_t sgxStatus = ecallStartRatsServer(
                m_enclaveID,
                &ecallRet,
                parseIPv4Address(m_localIP),
                convertToNetPort(m_port),
                flags,
                m_attesterType.c_str(),
                m_verifierType.c_str(),
                m_tlsType.c_str(),
                m_cryptoType.c_str());

            if (sgxStatus != SGX_SUCCESS)
                throw SGXErrorException("Failed to start Rats-TLS server", sgxStatus);

            if (ecallRet == -1)
                throw ECallErrorException("start Rats-TLS server", getErrorInfoFromEnclave(m_enclaveID, ecallGetServerError));
        }

        void SGXTrustedServer::accept()
        {
            if (m_enclaveID == 0)
                throw UnInitializedException("In function 'SGXTrustedServer::accept'", "m_enclaveID");

            int64_t ecallRet = 0;
            sgx_status_t sgxStatus = ecallAcceptConn(m_enclaveID, &ecallRet);

            if (sgxStatus != SGX_SUCCESS)
                throw SGXErrorException("Failed to accept connection on Rats-TLS server", sgxStatus);
            if (ecallRet == -1)
                throw ECallErrorException("Rats-TLS server accept connection", getErrorInfoFromEnclave(m_enclaveID, ecallGetServerError));
            else if (ecallRet == 1)
            {
                std::string clientErrorInfo = getErrorInfoFromEnclave(m_enclaveID, ecallGetServerError);

                // debug
                std::cerr << "[DEBUG] " << clientErrorInfo << std::endl;
            }
        }

        void SGXTrustedServer::close()
        {
            int64_t ecallRet = 0;
            sgx_status_t sgxStatus = ecallCloseConn(m_enclaveID, &ecallRet);

            if (sgxStatus != SGX_SUCCESS)
                throw SGXErrorException("Failed to stop Rats-TLS server", sgxStatus);
            if (ecallRet == -1)
                throw ECallErrorException("stop Rats-TLS server", getErrorInfoFromEnclave(m_enclaveID, ecallGetServerError));
        }

        void SGXTrustedServer::stop()
        {
            int64_t ecallRet = 0;
            sgx_status_t sgxStatus = ecallCloseRatsServer(m_enclaveID, &ecallRet);

            if (sgxStatus != SGX_SUCCESS)
                throw SGXErrorException("Failed to stop Rats-TLS server", sgxStatus);
            if (ecallRet == -1)
                throw ECallErrorException("stop Rats-TLS server", getErrorInfoFromEnclave(m_enclaveID, ecallGetServerError));
        }
    }
}