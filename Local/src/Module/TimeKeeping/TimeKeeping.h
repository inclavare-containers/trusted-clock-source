/**
 *
 */

#ifndef TIMEKEEPING_H_
#define TIMEKEEPING_H_

#include "Config.h"

#include "Sync.h"
#include "Algorithm.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Set up the configuration including multiple statistics.
     *
     * @param __subtick_counter_loop_max_count__ The subtick counter uses
     *      a loop to measure a period of time. This parameter represents the
     *      count of the loop.
     * @param __subticks_per_sec__ Subticks per second. It's a statistical
     *      magnitude based on `__subtick_counter_loop_max_count__`. It's also
     *      influenced by the resource usage on the local machine and other
     *      possible factors.
     * @param __sync_wait_subtick_count__ Each binding sync thread has a waiting
     *      in an infinite loop. This parameter represents the waiting subticks
     *      in the binding sync thread.
     * @param __received_timestamps_max_count__ The limit of timestamps a thread
     *      can receive from the remote.
     *
     * @return 0 if success
     */
    int setup_config(
        uint64_t __subtick_counter_loop_max_count__,
        uint64_t __subticks_per_sec__,
        uint64_t __sync_wait_subtick_count__,
        uint32_t __received_timestamps_max_count__);

    /**
     * Launch several timekeeping threads.
     *
     * @param __thread_count Thread count.
     *
     * @return 0 if success
     */
    int launch_timekeeping_threads(unsigned __thread_count);

    /**
     * Destroy the existing timekeeping threads
     *
     * @return 0 if success
     */
    int destroy_timekeeping_threads();

    /**
     * Get trusted time.
     *
     * @param __trusted_ts The trusted timetstamp.
     *
     * @return 0 if success
     */
    int get_trusted_time(timestamp_t *__trusted_ts);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include "Util.h"

namespace TCS
{
    const uint32_t DefaultRecvMaxTimestamps = 20u;

    class TimeKeeping
    {
    private:
        struct ThreadItem
        {
            Vector<uint64_t> m_Timestamps;
            Atomic<uint32_t> m_TSCount = {0u};
            Atomic<uint64_t> m_SubtickCount = {0ull};
            Atomic<int64_t> m_ErrDelta = {0ll};

            Mutex m_TSMutex;

            Atomic<uint64_t> m_LastMedian = {0ull};

            ThreadItem();
            ThreadItem(uint32_t _recvMaxTS);
            ThreadItem(const ThreadItem &_other);
        };

    private:
        bool m_Init;

        Atomic<bool> m_KeepRunningFlag;
        uint64_t m_SubtickCounterMaxLoop;
        uint64_t m_SubticksPerSecond;
        uint64_t m_SyncWaitMaxSubtick;
        uint32_t m_RecvMaxTimestamps;

        List<ThreadItem> m_ThreadItems;
        Vector<Pair<Thread, Thread>> m_TKeepThreads;
        Vector<uint64_t> m_AllTimestamps;

        Sync m_sync;
        Filter m_filter;

    private:
        void SubtickCounter();

        void ThreadSync(const List<ThreadItem>::iterator &itemIter) noexcept;

        void ThreadCounter(const List<ThreadItem>::iterator &itemIter) noexcept;

        void StartTKeepThreads(unsigned threadCount);

        void StopTKeepThreads();

        uint64_t GetTimetstampAsInt();

    public:
        TimeKeeping();
        TimeKeeping(uint64_t subtickCounterMaxLoop,
                    uint64_t subticksPerSec,
                    uint64_t syncWaitSubtickCount,
                    uint32_t recvTimestampsMaxCount);
        TimeKeeping(const TimeKeeping &_other);
        ~TimeKeeping() = default;

        void SetUp(uint64_t subtickCounterMaxLoop,
                   uint64_t subticksPerSec,
                   uint64_t syncWaitSubtickCount,
                   uint32_t recvTimestampsMaxCount);

        void Launch(unsigned threadCount);

        void Destroy();

        void GetTrustedTime(timestamp_t *trustedTime);
    };
}

#endif

#endif