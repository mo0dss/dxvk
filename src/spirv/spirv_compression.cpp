#include "spirv_compression.h"

extern "C" {
#include "streamvbyte.h"
}

namespace dxvk {
  SpirvCompressedBuffer::SpirvCompressedBuffer(SpirvCodeBuffer& code)
  : m_size(code.dwords()),
    m_compressed_code(std::vector<uint8_t>(streamvbyte_max_compressedbytes(m_size))),
    m_compressed_size(streamvbyte_encode_0124(code.data(), m_size, m_compressed_code.data())) {}

  SpirvCodeBuffer SpirvCompressedBuffer::decompress() const {
    SpirvCodeBuffer code(dwords());
    if (streamvbyte_decode_0124(
        m_compressed_code.data(),
        code.data(),
        dwords()) != m_compressed_size) {
      Logger::err("SpirvCompressedBuffer::decompress: code buffer size does not match");
    }
    return code;
  }

}