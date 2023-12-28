/**
 *
 *
 */

#ifndef TCSALGORITHM_H_
#define TCSALGORITHM_H_

#include "Util.h"

#ifdef __cplusplus

namespace TCS
{
    class Filter
    {
    private:
    public:
        Filter() {}

        uint64_t perform(const Vector<uint64_t> &elements, size_t size);
    };
}

#endif

#endif