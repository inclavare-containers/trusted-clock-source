/**
 *
 *
 */

#ifndef TCSUTIL_H_
#define TCSUTIL_H_

#ifdef __cplusplus

#include <cstdint>
#include <vector>
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <atomic>
#include <stdexcept>

namespace TCS
{
    template <class _Tp>
    struct Hash
    {
        size_t operator()(const _Tp &t) const
        {
            std::hash<_Tp> h;
            return h(t);
        }
    };

    template <typename _Tp, typename _Alloc = std::allocator<_Tp>>
    using Vector = std::vector<_Tp, _Alloc>;

    template <typename _Tp, typename _Alloc = std::allocator<_Tp>>
    using List = std::list<_Tp, _Alloc>;

    template <typename _Key, typename _Hash = Hash<_Key>,
              typename _KeyEqual = std::equal_to<_Key>,
              typename _Alloc = std::allocator<_Key>>
    using Set = std::unordered_set<_Key, _Hash, _KeyEqual, _Alloc>;

    template <typename _Key, typename _Value, typename _Hash = Hash<_Key>,
              typename _KeyEqual = std::equal_to<_Key>,
              typename _Alloc = std::allocator<_Key>>
    using Map = std::unordered_map<_Key, _Value, _Hash, _KeyEqual, _Alloc>;

    using Thread = std::thread;
    using Mutex = std::mutex;
    using UniqueLock = std::unique_lock<Mutex>;

    template <typename _Tp>
    using Atomic = std::atomic<_Tp>;

    template <typename _Tp1, typename _Tp2>
    using Pair = std::pair<_Tp1, _Tp2>;

    using Exception = std::exception;

    namespace MeasureUnit
    {
        const uint64_t SEC_TO_NSEC = 1000000000ull;
    }

    void
    CopyVector(Vector<uint64_t> &vec1, const Vector<uint64_t> &vec2, size_t count);
}

#endif

#endif