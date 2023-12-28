/**
 *
 *
 *
 */

#ifndef TCS_SGXUTILS_H_
#define TCS_SGXUTILS_H_

#include <cstring>
#include <string>
#include <functional>

#include "SGXExcept.hpp"

#include "TCSMessage.h"

#include "sgx_urts.h"

namespace TCS
{
    namespace SGX_UP
    {
        /// @brief Load an signed enclave library file
        /// @param _enclave
        /// @param isDebugEnclave
        /// @return enclave ID
        /// @exception `SGXErrorException`
        sgx_enclave_id_t loadEnclave(const std::string &_enclave, bool isDebugEnclave)
        {
            sgx_launch_token_t launchToken;
            memset(launchToken, 0, sizeof(launchToken));

            sgx_enclave_id_t enclaveID;
            int tokenUpdated = 0;
            sgx_status_t result = sgx_create_enclave(_enclave.c_str(), isDebugEnclave, &launchToken, &tokenUpdated, &enclaveID, NULL);
            if (result != SGX_SUCCESS)
                throw SGXErrorException("Failed to load enclave '" + _enclave + "'", result);

            return enclaveID;
        }

        std::string getErrorInfoFromEnclave(sgx_enclave_id_t enclaveID, const std::function<sgx_status_t(sgx_enclave_id_t, char *, size_t)> &ecallGetErrorInfoFunc)
        {
            if (ecallGetErrorInfoFunc)
            {
                char errorInfoBuffer[TCS_ERROR_INFO_MAX_LEN] = {'\0'};
                sgx_status_t sgxStatus = ecallGetErrorInfoFunc(enclaveID, errorInfoBuffer, TCS_ERROR_INFO_MAX_LEN);
                if (sgxStatus != SGX_SUCCESS)
                    return "";
                else
                    return std::string(errorInfoBuffer);
            }
            else
                return "";
        }
    }
}

#endif