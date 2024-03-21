/**
 *
 *
 *
 */
#include <iostream>
#include <string>
#include <cstring>

#include "SGX/Communication/Client/SGXTrustedClient.h"
#include "SGX/Utility/SGXExcept.hpp"

#include "Utility/TCSExcept.hpp"

#ifndef SGX_ENCLAVE_NAME
#define SGX_ENCLAVE_NAME "SGXClientEnclave.signed.so"
#endif

int main(int argc, char **argv)
{
    if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")))
    {
        std::cout << "Client dependent on Rats-TLS and Intel SGX" << std::endl;
        return 0;
    }

    std::string enclaveSearchPath = ".";
    if (argc > 1)
        enclaveSearchPath = argv[1];
    std::string enclaveFilePath = enclaveSearchPath + "/" + SGX_ENCLAVE_NAME;

    TCS::SGX_UP::SGXTrustedClient sgxClient(enclaveFilePath);

    try
    {
        sgxClient.start("127.0.0.1", 2333);
        std::cout << "[I] Started SGX client" << std::endl;

        sgxClient.exchangeKey();
        std::cout << "[I] Exchanged client key" << std::endl;

        sgxClient.stop();
        std::cout << "[I] Stopped SGX client" << std::endl;
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