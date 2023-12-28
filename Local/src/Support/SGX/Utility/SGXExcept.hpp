/**
 *
 *
 *
 */

#ifndef TCS_SGXEXCEPT_H_
#define TCS_SGXEXCEPT_H_

#include "TCSExcept.hpp"

#include "sgx_error.h"

namespace TCS
{
    namespace SGX_UP
    {
        class SGXErrorException : public TCSExcept
        {
        private:
            std::string m_statement;
            sgx_status_t m_sgxStatus;

        public:
            SGXErrorException(const std::string &_state)
            {
                m_statement = _state;
                TCSExcept("SGX Error. Code: none. Statement: " + m_statement);
            }

            SGXErrorException(const std::string &_state, sgx_status_t _status)
            {
                m_statement = _state;
                m_sgxStatus = _status;
                TCSExcept(std::string("SGX Error. Code: ") + std::to_string(m_sgxStatus) + ". Statement: " + m_statement);
            }
        };

        class ECallErrorException : public TCSExcept
        {
        public:
            ECallErrorException(const std::string &funcName, const std::string &content)
            {
                if (content.empty())
                    TCSExcept(std::string("In procedure '") + funcName + "': Error: none. It seems the error information cannot be grasped from the enclave.");
                else
                    TCSExcept(std::string("In procedure '") + funcName + "': Error: " + content);
            }
        };

    }
}

#endif