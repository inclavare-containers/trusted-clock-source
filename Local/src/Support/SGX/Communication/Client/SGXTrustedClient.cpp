/**
 *
 *
 *
 */

#include "SGXTrustedClient.h"
#include "SGXUtils.hpp"

#include "ClientEnclave_u.h"

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
                throw SGXErrorException("Failed to load enclave '" + m_enclaveFilePath + "'");

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
                throw SGXErrorException("Failed to start Rats-TLS server", sgxStatus);

            if (ecallRet == -1)
                throw ECallErrorException("start Rats-TLS server", getErrorInfoFromEnclave(m_enclaveID, ecallGetClientError));
        }

        void SGXTrustedClient::stop()
        {
            int64_t ecallRet = 0;
            sgx_status_t sgxStatus = ecallStopRatsClient(m_enclaveID, &ecallRet);

            if (sgxStatus != SGX_SUCCESS)
                throw SGXErrorException("Failed to start Rats-TLS server", sgxStatus);

            if (ecallRet == -1)
                throw ECallErrorException("stop Rats-TLS client", getErrorInfoFromEnclave(m_enclaveID, ecallGetClientError));
        }
    }
}