/**
 *
 *
 *
 */

#ifndef TCS_SGXTRUSTEDSERVER_H_
#define TCS_SGXTRUSTEDSERVER_H_

#include "TrustedComm.hpp"

#include "sgx_urts.h"

namespace TCS
{
    namespace SGX_UP
    {
        class SGXTrustedServer : public TrustedServer
        {
        private:
            const std::string m_localIP = "127.0.0.1";

            const std::string m_attesterType = "sgx_ecdsa";
            const std::string m_verifierType = "sgx_ecdsa_qve";
            const std::string m_tlsType = "openssl";
            const std::string m_cryptoType = "openssl";

            const bool m_mutualAtte = true;

            std::string m_enclaveFilePath;
            sgx_enclave_id_t m_enclaveID;

        public:
            SGXTrustedServer() : TrustedServer(), m_enclaveID(0){};
            SGXTrustedServer(uint16_t _port) : TrustedServer(_port), m_enclaveID(0) {}
            SGXTrustedServer(const std::string &_enclave) : TrustedServer(), m_enclaveFilePath(_enclave), m_enclaveID(0) {}
            SGXTrustedServer(uint16_t _port, const std::string &_enclave) : TrustedServer(_port), m_enclaveFilePath(_enclave), m_enclaveID(0) {}
            ~SGXTrustedServer() = default;

            /// @brief Start Rats-TLS server based on Intel SGX
            /// @exception `SGXErrorException`
            void start();

            /// @brief Start Rats-TLS server based on Intel SGX
            /// @param _port
            /// @exception `SGXErrorException`
            /// @exception `ECallErrorException`
            void start(uint16_t _port);

            /// @brief Accept connection from a client
            /// @exception `SGXErrorException`
            /// @exception `ECallErrorException`
            /// @exception `UnInitializedException`
            void accept();

            /// @brief Exchange server key
            /// @exception `SGXErrorException`
            /// @exception `ECallErrorException`
            /// @exception `UnInitializedException`
            void exchangeKey();

            /// @brief Close the connection
            /// @exception `SGXErrorException`
            /// @exception `ECallErrorException`
            /// @exception `UnInitializedException`
            void close();

            /// @brief Stop the server
            /// @exception `SGXErrorException`
            /// @exception `ECallErrorException`
            /// @exception `UnInitializedException`
            void stop();
        };
    }
}

#endif