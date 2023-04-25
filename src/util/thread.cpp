#include <atomic>

#include "./log/log.h"

#include "thread.h"

#include "util_likely.h"
#include "util_string.h"

#ifdef _WIN32

namespace dxvk {

  struct PROCESSOR_RELATIONSHIP {
    BYTE Flags;
    BYTE EfficiencyClass;
    BYTE Reserved[20];
    WORD GroupCount;
    GROUP_AFFINITY GroupMask[ANYSIZE_ARRAY];
  };


  struct CpuGroupTopology {
    dxvk::mutex       mutex;
    GROUP_AFFINITY    ccd0Cores;

    std::atomic<bool> initialized = { false };
  };


  struct CpuThreadAffinityMap {
    std::mutex mutex;
    std::unordered_map<DWORD, GROUP_AFFINITY> map;
  };


  static CpuGroupTopology g_topology;
  static CpuThreadAffinityMap g_affinityMap;


  void initCpuTopology() {
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");

    if (!kernel32) {
      Logger::warn("Failed to load kernel32.dll");
      return;
    }

    using PFN_GetLogicalProcessorInformationEx = BOOL (WINAPI*)(
      LOGICAL_PROCESSOR_RELATIONSHIP, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*, DWORD*);

    auto GetLogicalProcessorInformationEx = reinterpret_cast<PFN_GetLogicalProcessorInformationEx>(
      GetProcAddress(kernel32, "GetLogicalProcessorInformationEx"));

    if (!GetLogicalProcessorInformationEx) {
      Logger::warn("Failed to query GetLogicalProcessorInformationEx");
      return;
    }

    std::vector<char> buffer;
    DWORD bufferSize = 0;

    GetLogicalProcessorInformationEx(RelationAll, nullptr, &bufferSize);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      Logger::warn("GetLogicalProcessorInformationEx failed");
      return;
    }

    buffer.resize(bufferSize);

    if (!GetLogicalProcessorInformationEx(RelationAll,
        reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data()), &bufferSize)) {
      Logger::warn("GetLogicalProcessorInformationEx failed");
      return;
    }

    std::vector<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*> infos;
    const char* data = buffer.data();

    while (data != buffer.data() + bufferSize) {
      auto info = reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(data);
      data += info->Size;

      infos.push_back(info);
    }

    BYTE maxEfficiencyClass = 0;
    GROUP_AFFINITY maxEfficiencyGroup = { };

    // Find core set with the highest efficiency class
    for (auto info : infos) {
      if (info->Relationship == RelationProcessorCore) {
        if (!info->Processor.GroupCount)
          continue;

        // MinGW headers do not have the EfficiencyClass member at this time
        BYTE efficiencyClass = 0;
        std::memcpy(&efficiencyClass, reinterpret_cast<const char*>(&info->Processor.Flags) + 1, sizeof(efficiencyClass));

        if (efficiencyClass > maxEfficiencyClass) {
          maxEfficiencyClass = efficiencyClass;
          maxEfficiencyGroup = info->Processor.GroupMask[0];
        } else if (efficiencyClass == maxEfficiencyClass) {
          for (uint32_t i = 0; i < info->Processor.GroupCount; i++) {
            if (maxEfficiencyGroup.Group == info->Processor.GroupMask[i].Group)
              maxEfficiencyGroup.Mask |= info->Processor.GroupMask[i].Mask;
          }
        }
      }
    }

    // Find largest core set within the highest efficiency
    // class that shares a common last-level cache
    uint32_t maxCacheLevel = 0;
    GROUP_AFFINITY maxCacheGroup = { };

    for (auto info : infos) {
      if (info->Relationship == RelationCache) {
        if (info->Cache.Level < maxCacheLevel)
          continue;

        if (info->Cache.GroupMask.Group == maxEfficiencyGroup.Group) {
          auto mask = info->Cache.GroupMask.Mask & maxEfficiencyGroup.Mask;

          if (bit::popcnt(uint64_t(mask)) > bit::popcnt(uint64_t(maxCacheGroup.Mask))) {
            maxCacheGroup = info->Cache.GroupMask;
            maxCacheGroup.Mask &= maxEfficiencyGroup.Mask;
          }
        }
      }
    }

    // Ensure we only pin threads if the number of
    // threads in the group is reasonably high
    if (bit::popcnt(uint64_t(maxCacheGroup.Mask)) >= 4) {
      g_topology.ccd0Cores = maxCacheGroup;

      Logger::info(str::format("Logical core mask for worker threads: ", std::dec, maxCacheGroup.Group, ":", std::hex, maxCacheGroup.Mask));
    }
  }


  const CpuGroupTopology* getCpuTopology() {
    if (g_topology.initialized.load(std::memory_order_acquire))
      return &g_topology;

    std::lock_guard lock(g_topology.mutex);

    if (g_topology.initialized.load())
      return &g_topology;

    initCpuTopology();

    g_topology.initialized.store(true, std::memory_order_release);
    return &g_topology;
  }


  void setThreadAffinity(dxvk::thread::id threadId, ThreadAffinity affinity) {
    auto topology = getCpuTopology();

    std::lock_guard lock(g_affinityMap.mutex);

    GROUP_AFFINITY newAffinity = { };
    GROUP_AFFINITY oldAffinity = { };

    switch (affinity) {
      case ThreadAffinity::Ccd0: {
        if (!topology->ccd0Cores.Mask)
          return;

        newAffinity = topology->ccd0Cores;
      } break;

      case ThreadAffinity::Default: {
        auto entry = g_affinityMap.map.find(threadId);

        // If we don't have an affinity mask stored, the thread already
        // uses its default affinity, which is exactly what we want
        if (entry == g_affinityMap.map.end())
          return;

        newAffinity = entry->second;
        g_affinityMap.map.erase(entry);
      } break;

      default:
        Logger::warn(str::format("Invalid affinity type ", uint32_t(affinity)));
        return;
    }

    HANDLE threadHandle = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, threadId);

    if (!threadHandle) {
      Logger::warn(str::format("Failed to query thread handle for thread ", threadId));
      return;
    }

    if (!SetThreadGroupAffinity(threadHandle, &newAffinity, &oldAffinity)) {
      Logger::warn(str::format("Failed to set thread affinity for thread ", threadId));
      return;
    }

    if (!threadHandle)
      CloseHandle(threadHandle);

    // Do not retry if the insertion into the hash map fails. This
    // way we preserve the initial affinity mask of the thread.
    if (affinity != ThreadAffinity::Default)
      g_affinityMap.map.insert({ threadId, oldAffinity });

    Logger::info(str::format("Set affinity for thread ", threadId, " to ", std::dec, newAffinity.Group, ":", std::hex, newAffinity.Mask));
  }


  thread::thread(ThreadProc&& proc)
  : m_data(new ThreadData(std::move(proc))) {
    m_data->handle = ::CreateThread(nullptr, 0x100000,
      thread::threadProc, m_data, STACK_SIZE_PARAM_IS_A_RESERVATION,
      &m_data->id);

    if (!m_data->handle) {
      delete m_data;
      throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again), "Failed to create thread");
    }
  }


  thread::~thread() {
    if (joinable())
      std::terminate();
  }


  void thread::join() {
    if (!joinable())
      throw std::system_error(std::make_error_code(std::errc::invalid_argument), "Thread not joinable");

    if (get_id() == this_thread::get_id())
      throw std::system_error(std::make_error_code(std::errc::resource_deadlock_would_occur), "Cannot join current thread");

    if(::WaitForSingleObjectEx(m_data->handle, INFINITE, FALSE) == WAIT_FAILED)
      throw std::system_error(std::make_error_code(std::errc::invalid_argument), "Joining thread failed");

    detach();
  }


  void thread::set_priority(ThreadPriority priority) {
    int32_t value;
    switch (priority) {
      default:
      case ThreadPriority::Normal: value = THREAD_PRIORITY_NORMAL; break;
      case ThreadPriority::Lowest: value = THREAD_PRIORITY_LOWEST; break;
    }

    if (m_data)
      ::SetThreadPriority(m_data->handle, int32_t(value));
  }


  uint32_t thread::hardware_concurrency() {
    SYSTEM_INFO info = { };
    ::GetSystemInfo(&info);
    return info.dwNumberOfProcessors;
  }


  DWORD WINAPI thread::threadProc(void* arg) {
    auto data = reinterpret_cast<ThreadData*>(arg);
    DWORD exitCode = 0;

    try {
      data->proc();
    } catch (...) {
      exitCode = 1;
    }

    data->decRef();
    return exitCode;
  }

}


namespace dxvk::this_thread {

  bool isInModuleDetachment() {
    using PFN_RtlDllShutdownInProgress = BOOLEAN (WINAPI *)();

    static auto RtlDllShutdownInProgress = reinterpret_cast<PFN_RtlDllShutdownInProgress>(
      ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "RtlDllShutdownInProgress"));

    return RtlDllShutdownInProgress();
  }

}

#else

namespace dxvk {

  struct ThreadIdMap {
    dxvk::mutex mutex;
    std::unordered_map<std::thread::id, dxvk::thread::id> map;
    uint32_t nextThreadId = 0;

    uint32_t lookupThreadId(std::thread::id id) {
      std::lock_guard lock(mutex);

      auto entry = map.find(id);

      if (entry != map.end())
        return entry->second;

      uint32_t result = ++nextThreadId;
      map.insert({ id, result });
      return result;
    }
  };


  static ThreadIdMap g_threadIdMap;


  uint32_t thread::get_id() const {
    return g_threadIdMap.lookupThreadId(std::thread::get_id());
  }


  void setThreadAffinity(dxvk::thread::id threadId, ThreadAffinity affinity) {
    // Stub
  }

}


namespace dxvk::this_thread {

  static thread_local dxvk::thread::id g_threadId = dxvk::thread::id();

  // This implementation returns thread ids unique to the current instance.
  // ie. if you use this across multiple .so's then you might get conflicting ids.
  //
  // This isn't an issue for us, as it is only used by the spinlock implementation,
  // but may be for you if you use this elsewhere.
  uint32_t get_id() {
    if (unlikely(!g_threadId))
      g_threadId = g_threadIdMap.lookupThreadId(std::this_thread::get_id());

    return g_threadId;
  }

}

#endif
