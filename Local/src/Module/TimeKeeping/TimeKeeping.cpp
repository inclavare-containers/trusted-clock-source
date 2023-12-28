/**
 *
 */

#include "Config.h"
#include "Sync.h"
#include "TimeKeeping.h"

#include "TCSExcept.hpp"

#include <iostream>
#include <chrono>
#include <cstdint>
#include <cstdlib>

using namespace std;

namespace TCS
{

    // static uint64_t FilterOut(const Vector<uint64_t> &elements, size_t length)
    // {
    //     // TODO
    //     return elements[length / 2];
    // }

    TimeKeeping::ThreadItem::ThreadItem()
    {
        m_TSCount = 0u;
        m_SubtickCount = 0u;
        m_ErrDelta = 0ll;
        m_LastMedian = 0ull;

        m_Timestamps = Vector<uint64_t>(DefaultRecvMaxTimestamps, 0ull);
    }

    TimeKeeping::ThreadItem::ThreadItem(uint32_t _recvMaxTS)
    {
        m_TSCount = 0u;
        m_SubtickCount = 0u;
        m_ErrDelta = 0ll;
        m_LastMedian = 0ull;

        m_Timestamps = Vector<uint64_t>(_recvMaxTS, 0ull);
    }

    TimeKeeping::ThreadItem::ThreadItem(const ThreadItem &_other)
    {
        m_TSCount.store(_other.m_TSCount.load());
        m_SubtickCount.store(_other.m_SubtickCount);
        m_ErrDelta.store(_other.m_ErrDelta.load());
        m_LastMedian.store(_other.m_LastMedian.load());

        m_Timestamps = _other.m_Timestamps;
    }

    void TimeKeeping::SubtickCounter()
    {
        for (uint64_t i = 0; i < m_SubtickCounterMaxLoop; ++i)
        {
        }
    }

    void TimeKeeping::ThreadSync(const List<ThreadItem>::iterator &itemIter) noexcept
    {
        // initialization
        Vector<uint64_t> ownedTimestamps = Vector<uint64_t>(m_RecvMaxTimestamps);

        // wait for initialization of `ThreadCounter()`
        do
        {
            UniqueLock locker(itemIter->m_TSMutex);
            if (itemIter->m_LastMedian > 0ull)
                break;
        } while (m_KeepRunningFlag);

        // Update timestamps in an infinite loop
        do
        {
            for (uint64_t i = 0; i < m_SyncWaitMaxSubtick; i++)
            {
                if (m_KeepRunningFlag)
                    SubtickCounter();
                else
                    return;
            }

            // sync
            uint64_t median = 0ull;
            uint64_t subticks1 = itemIter->m_SubtickCount;
            m_sync.getTimestampAsInt(ownedTimestamps, ownedTimestamps.size(), median);
            uint64_t subticks2 = itemIter->m_SubtickCount;

            if (!ownedTimestamps.empty() && m_KeepRunningFlag)
            {
                // average subtick count
                auto avgSubticks = (subticks1 + subticks2) / 2;
                // calculate the updated error delta time
                auto newErrDelta = (int64_t(avgSubticks * MeasureUnit::SEC_TO_NSEC / m_SubticksPerSecond) - int64_t(median - itemIter->m_LastMedian.load())) / (int64_t)avgSubticks;

                // move updated values to the list item
                {
                    UniqueLock locker(itemIter->m_TSMutex);
                    CopyVector(itemIter->m_Timestamps, ownedTimestamps, ownedTimestamps.size());
                    itemIter->m_TSCount.store(ownedTimestamps.size());
                    itemIter->m_ErrDelta.store(newErrDelta);
                    itemIter->m_SubtickCount.store(0ull);
                }

                itemIter->m_LastMedian.store(median);
            }
        } while (m_KeepRunningFlag);
    }

    void TimeKeeping::ThreadCounter(const List<ThreadItem>::iterator &itemIter) noexcept
    {
        // initialization
        Vector<uint64_t> ownedTimestamps = Vector<uint64_t>(m_RecvMaxTimestamps);

        // synchronize
        uint64_t median = 0ull;
        m_sync.getTimestampAsInt(ownedTimestamps, ownedTimestamps.size(), median);
        if (!ownedTimestamps.empty())
        {
            UniqueLock locker(itemIter->m_TSMutex);
            CopyVector(itemIter->m_Timestamps, ownedTimestamps, ownedTimestamps.size());
            itemIter->m_TSCount.store(ownedTimestamps.size());
            itemIter->m_LastMedian.store(median);
        }
        else
        {
            // When some errors occur, there is no choice
            // but to rely on timestamps from the OS
            // TODO
        }

        // increase subticks
        do
        {
            itemIter->m_SubtickCount++;
        } while (m_KeepRunningFlag);
    }

    void TimeKeeping::StartTKeepThreads(unsigned threadCount)
    {
        m_ThreadItems.clear();
        m_AllTimestamps.resize(threadCount * m_RecvMaxTimestamps, 0ull);

        while (threadCount--)
        {
            m_ThreadItems.push_back(ThreadItem(m_RecvMaxTimestamps));
            m_TKeepThreads.emplace_back(Thread([this](const List<ThreadItem>::iterator &itemIter)
                                               { this->ThreadCounter(itemIter); },
                                               --m_ThreadItems.end()),
                                        Thread([this](const List<ThreadItem>::iterator &itemIter)
                                               { this->ThreadSync(itemIter); },
                                               --m_ThreadItems.end()));
        }
        // TODO: check thread status
        for (auto &tkThread : m_TKeepThreads)
        {
            if (!tkThread.second.joinable())
            {
                // this thread came across some errors
                std::cerr << "Sync thread is not joinable" << std::endl;
            }
            if (!tkThread.first.joinable())
            {
                // this thread came across some errors
                std::cerr << "Counter thread is not joinable" << std::endl;
            }
        }
    }

    void TimeKeeping::StopTKeepThreads()
    {
        m_KeepRunningFlag = false;
        for (auto &tkThread : m_TKeepThreads)
        {
            if (tkThread.second.joinable())
                tkThread.second.join();
            if (tkThread.first.joinable())
                tkThread.first.join();
        }
    }

    uint64_t TimeKeeping::GetTimetstampAsInt()
    {
        // get multiple timestamps from timekeeping threads
        size_t index = 0ul;
        for (auto iter = m_ThreadItems.begin(); iter != m_ThreadItems.end(); ++iter)
        {
            UniqueLock locker(iter->m_TSMutex);
            int64_t tmpDeltaTime = int64_t(iter->m_SubtickCount.load() * MeasureUnit::SEC_TO_NSEC / m_SubtickCounterMaxLoop) - iter->m_ErrDelta.load();
            for (uint32_t i = 0u; i < iter->m_TSCount; i++)
            {
                m_AllTimestamps[index++] = int64_t(iter->m_Timestamps[i]) + tmpDeltaTime;
            }
        }

        // filter out
        // test: median
        // debug
        return m_filter.perform(m_AllTimestamps, index);
    }

    void TimeKeeping::Launch(unsigned threadCount)
    {
        if (!m_Init)
        {
            throw UnInitializedException("Class", "TimeKeeping");
        }
        else if (threadCount <= 0)
        {
            throw InvalidArgumentException("Non-Positive Thread Count", "threadCount");
        }
        else
        {
            StartTKeepThreads(threadCount);
        }
    }

    void TimeKeeping::Destroy()
    {
        if (!m_Init)
        {
            throw UnInitializedException("Class", "TimeKeeping");
        }
        else
        {
            StopTKeepThreads();
        }
    }

    void TimeKeeping::GetTrustedTime(timestamp_t *trustedTime)
    {
        if (!m_Init)
        {
            throw UnInitializedException("Class", "TimeKeeping");
        }
        else if (!trustedTime)
        {
            throw InvalidArgumentException("Null Pointer", "trustedTime");
        }
        else
        {
            uint64_t tsInt = GetTimetstampAsInt();
            trustedTime->era_n = m_sync.getEraNumber();
            trustedTime->sec_since_epoch = tsInt / MeasureUnit::SEC_TO_NSEC;
            trustedTime->fraction = tsInt % MeasureUnit::SEC_TO_NSEC;
        }
    }

    void TimeKeeping::SetUp(uint64_t subtickCounterMaxLoop,
                            uint64_t subticksPerSec,
                            uint64_t syncWaitSubtickCount,
                            uint32_t recvTimestampsMaxCount)
    {
        m_Init = true;

        m_SubtickCounterMaxLoop = subtickCounterMaxLoop;
        m_SubticksPerSecond = subticksPerSec;
        m_SyncWaitMaxSubtick = syncWaitSubtickCount;
        m_RecvMaxTimestamps = recvTimestampsMaxCount;
    }

    TimeKeeping::TimeKeeping()
    {
        m_Init = false;

        m_KeepRunningFlag = true;
        m_SubtickCounterMaxLoop = 0;
        m_SubticksPerSecond = 0;
        m_SyncWaitMaxSubtick = 0;
        m_RecvMaxTimestamps = 0;
    }

    TimeKeeping::TimeKeeping(uint64_t subtickCounterMaxLoop,
                             uint64_t subticksPerSec,
                             uint64_t syncWaitSubtickCount,
                             uint32_t recvTimestampsMaxCount)
    {
        m_Init = true;

        m_KeepRunningFlag = true;
        m_SubtickCounterMaxLoop = subtickCounterMaxLoop;
        m_SubticksPerSecond = subticksPerSec;
        m_SyncWaitMaxSubtick = syncWaitSubtickCount;
        m_RecvMaxTimestamps = recvTimestampsMaxCount;
    }

    TimeKeeping::TimeKeeping(const TimeKeeping &_other)
    {
        m_Init = false;

        m_KeepRunningFlag.store(_other.m_KeepRunningFlag.load());
        m_SubtickCounterMaxLoop = _other.m_SubtickCounterMaxLoop;
        m_SubticksPerSecond = _other.m_SubticksPerSecond;
        m_SyncWaitMaxSubtick = _other.m_SyncWaitMaxSubtick;
        m_RecvMaxTimestamps = _other.m_RecvMaxTimestamps;
    }
}

static TCS::TimeKeeping TKeepEntity;

int launch_timekeeping_threads(unsigned __thread_count)
{
    try
    {
        TKeepEntity.Launch(__thread_count);
    }
    catch (TCS::Exception e)
    {
        return -1;
    }

    return 0;
}

int destroy_timekeeping_threads()
{
    try
    {
        TKeepEntity.Destroy();
    }
    catch (TCS::Exception e)
    {
        return -1;
    }
    return 0;
}

int get_trusted_time(timestamp_t *trusted_ts)
{
    try
    {
        TKeepEntity.GetTrustedTime(trusted_ts);
    }
    catch (TCS::Exception e)
    {
        return -1;
    }

    return 0;
}

int setup_config(
    uint64_t __subtick_counter_loop_max_count__,
    uint64_t __subticks_per_sec__,
    uint64_t __sync_wait_subtick_count__,
    uint32_t __received_timestamps_max_count__)
{
    try
    {
        TKeepEntity.SetUp(__subtick_counter_loop_max_count__, __subticks_per_sec__, __sync_wait_subtick_count__, __received_timestamps_max_count__);
    }
    catch (TCS::Exception e)
    {
        return -1;
    }
    return 0;
}