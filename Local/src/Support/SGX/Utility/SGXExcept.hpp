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

            void fillErrorStatement(const std::string &_state, sgx_status_t _status = SGX_SUCCESS)
            {
                m_statement = "SGX Error. Code: ";
                if (_status == SGX_SUCCESS)
                    m_statement += "none";
                else
                {
                    char hexStr[11] = {'\0'};
                    snprintf(hexStr, 10, "0x%.4x", (uint32_t)_status);
                    m_statement += hexStr;
                }
                m_statement += ". Statement: " + _state;
            }

        public:
            SGXErrorException(const std::string &_state) : TCSExcept()
            {
                fillErrorStatement(_state);
            }

            SGXErrorException(const std::string &_state, sgx_status_t _status) : TCSExcept()
            {
                fillErrorStatement(_state, _status);
            }

            virtual const char *what() const noexcept override
            {
                return m_statement.c_str();
            }
        };

        class ECallErrorException : public TCSExcept
        {
        private:
            std::string m_statement;

        public:
            ECallErrorException(const std::string &funcName, const std::string &content) : TCSExcept()
            {
                if (content.empty())
                    m_statement = std::string("In procedure '") + funcName + "': Error: none. It seems the error information cannot be grasped from the enclave.";
                else
                    m_statement = std::string("In procedure '") + funcName + "': Error: " + content;
            }

            virtual const char *what() const noexcept override
            {
                return m_statement.c_str();
            }
        };

    }
}

#endif