/**
 *
 *
 *
 */

#include <iostream>
#include <string>

#include "SGX/Communication/Server/SGXTrustedServer.h"
#include "SGX/Utility/SGXExcept.hpp"

#include "Utility/TCSExcept.hpp"

#ifndef SGX_ENCLAVE_NAME
#define SGX_ENCLAVE_NAME "SGXServerEnclave.signed.so"
#endif

int main(int argc, char **argv)
{
    std::string enclaveSearchPath = ".";
    if (argc > 1)
        enclaveSearchPath = argv[1];
    std::string enclaveFilePath = enclaveSearchPath + "/" + SGX_ENCLAVE_NAME;

    try
    {
        TCS::SGX_UP::SGXTrustedServer sgxServer(enclaveFilePath);

        uint16_t port = 2333;
        std::cout << "[I] Start SGX Rats-TLS server on port " << port << std::endl;
        sgxServer.start(port);

        while (true)
        {
            sgxServer.accept();
            std::cout << "[I] Accepted a connection" << std::endl;

            sgxServer.exchangeKey();
            std::cout << "[I] Exchanged server key" << std::endl;
        }

        sgxServer.stop();
    }
    catch (const TCS::InvalidArgumentException &ie)
    {
        std::cerr << "Error: " << ie.what() << std::endl;
        exit(1);
    }
    catch (const TCS::SGX_UP::SGXErrorException &see)
    {
        std::cerr << "Error: " << see.what() << std::endl;
        exit(1);
    }
    catch (const TCS::SGX_UP::ECallErrorException &eee)
    {
        std::cerr << "Error: " << eee.what() << std::endl;
        exit(1);
    }
    catch (const TCS::TCSExcept &te)
    {
        std::cerr << "Error: " << te.what() << std::endl;
        exit(1);
    }

    return 0;
}