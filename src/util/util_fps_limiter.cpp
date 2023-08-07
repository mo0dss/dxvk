#include <charconv>
#include <thread>

#include "thread.h"
#include "util_env.h"
#include "util_fps_limiter.h"
#include "util_sleep.h"
#include "util_string.h"

#include "./log/log.h"

using namespace std::chrono_literals;

namespace dxvk {
  
  FpsLimiter::FpsLimiter() {
    std::string env = env::getEnvVar("DXVK_FRAME_RATE");

    if (!env.empty()) {
      try {
        double f = 0.0f;
        std::from_chars(env.data(), env.data() + env.size(), f);
        setTargetFrameRate(f);
        m_envOverride = true;
      } catch (const std::invalid_argument&) {
        // no-op
      }
    }
  }


  FpsLimiter::~FpsLimiter() {

  }


  void FpsLimiter::setTargetFrameRate(double frameRate) {
    std::lock_guard<dxvk::mutex> lock(m_mutex);

    if (!m_envOverride) {
      if (frameRate > 0.0) {
        m_targetInterval = TimerDuration(int64_t(double(TimerDuration::period::den) / frameRate));
      } else {
        m_targetInterval = TimerDuration::zero();
        m_nextDeadline = TimePoint();
      }
    }
  }


  void FpsLimiter::delay(bool vsyncEnabled) {
    std::lock_guard<dxvk::mutex> lock(m_mutex);

    if (!isEnabled())
      return;

    TimePoint now = dxvk::high_resolution_clock::now();

    if (m_nextDeadline == TimePoint())
      m_nextDeadline = now;

    if (m_nextDeadline > now) {
      Sleep::sleepUntil(now, m_nextDeadline);
      m_nextDeadline += m_targetInterval;
    } else {
      uint64_t nFrames = TimerDuration(now - m_nextDeadline).count() / m_targetInterval.count();
      m_nextDeadline += (1 + nFrames) * m_targetInterval;
    }
  }

}
