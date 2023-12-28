/**
 *
 *
 */

#include "Util.h"

namespace TCS
{
    void CopyVector(Vector<uint64_t> &vec1, const Vector<uint64_t> &vec2, size_t count)
    {
        for (size_t i = 0; i < count && i < vec1.size() && i < vec2.size(); ++i)
        {
            vec1[i] = vec2[i];
        }
    }
}