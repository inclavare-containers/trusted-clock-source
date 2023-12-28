/**
 *
 *
 *
 */

#ifndef TCS_SGXTRUSTEDCLIENT_H_
#define TCS_SGXTRUSTEDCLIENT_H_

#include "TrustedComm.hpp"

#include "sgx_urts.h"

namespace TCS
{
    namespace SGX_UP
    {
        class SGXTrustedClient : public TrustedClient
        {
        private:
            std::string m_enclaveFilePath;
            sgx_enclave_id_t m_enclaveID;

            const bool m_mutualAtte = true;

            const std::string m_attesterType = "sgx_ecdsa";
            const std::string m_verifierType = "sgx_ecdsa_qve";
            const std::string m_tlsType = "openssl";
            const std::string m_cryptoType = "openssl";

        public:
            SGXTrustedClient() : TrustedClient(){};
            SGXTrustedClient(const std::string &_addr, uint16_t _port) : TrustedClient(_addr, _port) {}
            ~SGXTrustedClient() = default;

            /// @brief Start Rats-TLS client based on Intel SGX
            /// @exception `SGXErrorException`
            void start();

            /// @brief Start Rats-TLS client based on Intel SGX
            /// @param _addr
            /// @param _port
            /// @exception `SGXErrorException`
            /// @exception `ECallErrorException`
            void start(const std::string &_addr, uint16_t _port);

            /// @brief Stop the client
            /// @exception `SGXErrorException`
            /// @exception `ECallErrorException`
            void stop();
        };
    }
}

#endif