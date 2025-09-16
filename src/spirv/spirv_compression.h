#pragma once

#include <vector>

#include "spirv_code_buffer.h"

namespace dxvk {

  /**
   * \brief Compressed SPIR-V code buffer
   *
   * Implements a fast in-memory compression
   * to keep memory footprint low.
   */
  class SpirvCompressedBuffer {

  public:
    explicit SpirvCompressedBuffer(SpirvCodeBuffer& code);

    ~SpirvCompressedBuffer() = default;

    /**
     * \brief Code size, in dwords
     * \returns Code size, in dwords
     */
    uint32_t dwords() const {
      return m_size;
    }

    /**
     * \brief Code size, in bytes
     * \returns Code size, in bytes
     */
    size_t size() const {
      return dwords() * sizeof(uint32_t);
    }

    SpirvCodeBuffer decompress() const;

  private:
    uint32_t  m_size            = 0;

    alignas(CACHE_LINE_SIZE)
    std::vector<uint8_t> m_compressed_code;
    size_t               m_compressed_size = 0;
  };

}