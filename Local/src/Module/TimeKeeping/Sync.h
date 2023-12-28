/**
 *
 */

#ifndef SYNCHRONIZATION_H_
#define SYNCHRONIZATION_H_

#include "Config.h"

#include "Util.h"

#ifdef __cplusplus

namespace TCS
{

    class Sync
    {
    private:
        uint64_t m_tmp;

    public:
        Sync() {}
        ~Sync() = default;

        void getTimestampAsInt(Vector<uint64_t> &timestamps, uint32_t maxCount);

        void getTimestampAsInt(Vector<uint64_t> &timestamps, uint32_t maxCount, uint64_t &median);

        uint32_t getEraNumber();
    };
}

#endif

#endif