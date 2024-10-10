#include <cstring>

#include "d3d11_context_imm.h"
#include "d3d11_device.h"
#include "d3d11_initializer.h"

namespace dxvk {

  D3D11Initializer::D3D11Initializer(
          D3D11Device*                pParent)
  : m_parent(pParent),
    m_device(pParent->GetDXVKDevice()),
    m_stagingBuffer(m_device, StagingBufferSize),
    m_stagingSignal(new sync::Fence(0)),
    m_csChunk(m_parent->AllocCsChunk(DxvkCsChunkFlag::SingleUse)) {

  }

  
  D3D11Initializer::~D3D11Initializer() {

  }


  void D3D11Initializer::NotifyContextFlush() {
    std::lock_guard<dxvk::mutex> lock(m_mutex);
    NotifyContextFlushLocked();
  }


  void D3D11Initializer::InitBuffer(
          D3D11Buffer*                pBuffer,
    const D3D11_SUBRESOURCE_DATA*     pInitialData) {
    if (!(pBuffer->Desc()->MiscFlags & D3D11_RESOURCE_MISC_TILED)) {
      VkMemoryPropertyFlags memFlags = pBuffer->GetBuffer()->memFlags();

      (memFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)
        ? InitHostVisibleBuffer(pBuffer, pInitialData)
        : InitDeviceLocalBuffer(pBuffer, pInitialData);
    }
  }
  

  void D3D11Initializer::InitTexture(
          D3D11CommonTexture*         pTexture,
    const D3D11_SUBRESOURCE_DATA*     pInitialData) {
    if (pTexture->Desc()->MiscFlags & D3D11_RESOURCE_MISC_TILED)
      InitTiledTexture(pTexture);
    else if (pTexture->GetMapMode() == D3D11_COMMON_TEXTURE_MAP_MODE_DIRECT)
      InitHostVisibleTexture(pTexture, pInitialData);
    else
      InitDeviceLocalTexture(pTexture, pInitialData);

    SyncSharedTexture(pTexture);
  }


  void D3D11Initializer::InitUavCounter(
          D3D11UnorderedAccessView*   pUav) {
    auto counterView = pUav->GetCounterView();

    if (counterView == nullptr)
      return;

    std::lock_guard<dxvk::mutex> lock(m_mutex);
    m_transferCommands += 1;

    EmitCs([
      cCounterSlice = DxvkBufferSlice(counterView)
    ] (DxvkContext* ctx) {
      const uint32_t zero = 0;
      ctx->updateBuffer(
        cCounterSlice.buffer(),
        cCounterSlice.offset(),
        sizeof(zero), &zero);
    });
  }


  void D3D11Initializer::InitDeviceLocalBuffer(
          D3D11Buffer*                pBuffer,
    const D3D11_SUBRESOURCE_DATA*     pInitialData) {
    std::lock_guard<dxvk::mutex> lock(m_mutex);

    Rc<DxvkBuffer> buffer = pBuffer->GetBuffer();

    if (pInitialData != nullptr && pInitialData->pSysMem != nullptr) {
      auto stagingSlice = m_stagingBuffer.alloc(buffer->info().size);
      std::memcpy(stagingSlice.mapPtr(0), pInitialData->pSysMem, stagingSlice.length());

      m_transferCommands += 1;

      EmitCs([
        cBuffer       = buffer,
        cStagingSlice = std::move(stagingSlice)
      ] (DxvkContext* ctx) {
        ctx->uploadBuffer(cBuffer,
          cStagingSlice.buffer(),
          cStagingSlice.offset());
      });
    } else {
      m_transferCommands += 1;

      EmitCs([
        cBuffer       = buffer
      ] (DxvkContext* ctx) {
        ctx->initBuffer(cBuffer);
      });
    }

    ThrottleAllocationLocked();
  }


  void D3D11Initializer::InitHostVisibleBuffer(
          D3D11Buffer*                pBuffer,
    const D3D11_SUBRESOURCE_DATA*     pInitialData) {
    // If the buffer is mapped, we can write data directly
    // to the mapped memory region instead of doing it on
    // the GPU. Same goes for zero-initialization.
    DxvkBufferSlice bufferSlice = pBuffer->GetBufferSlice();

    if (pInitialData != nullptr && pInitialData->pSysMem != nullptr) {
      std::memcpy(
        bufferSlice.mapPtr(0),
        pInitialData->pSysMem,
        bufferSlice.length());
    } else {
      std::memset(
        bufferSlice.mapPtr(0), 0,
        bufferSlice.length());
    }
  }


  void D3D11Initializer::InitDeviceLocalTexture(
          D3D11CommonTexture*         pTexture,
    const D3D11_SUBRESOURCE_DATA*     pInitialData) {
    std::lock_guard<dxvk::mutex> lock(m_mutex);
    
    // Image migt be null if this is a staging resource
    Rc<DxvkImage> image = pTexture->GetImage();

    auto mapMode = pTexture->GetMapMode();
    auto desc = pTexture->Desc();

    VkFormat packedFormat = m_parent->LookupPackedFormat(desc->Format, pTexture->GetFormatMode()).Format;
    auto formatInfo = lookupFormatInfo(packedFormat);

    if (pInitialData != nullptr && pInitialData->pSysMem != nullptr) {
      // Compute data size for all subresources and allocate staging buffer memory
      DxvkBufferSlice stagingSlice;

      if (mapMode != D3D11_COMMON_TEXTURE_MAP_MODE_STAGING) {
        VkDeviceSize dataSize = 0u;

        for (uint32_t mip = 0; mip < image->info().mipLevels; mip++) {
          dataSize += image->info().numLayers * util::computeImageDataSize(
            packedFormat, image->mipLevelExtent(mip), formatInfo->aspectMask);
        }

        stagingSlice = m_stagingBuffer.alloc(dataSize);
      }

      // Copy initial data for each subresource into the staging buffer,
      // as well as the mapped per-subresource buffers if available.
      VkDeviceSize dataOffset = 0u;

      for (uint32_t mip = 0; mip < desc->MipLevels; mip++) {
        for (uint32_t layer = 0; layer < desc->ArraySize; layer++) {
          uint32_t index = D3D11CalcSubresource(mip, layer, desc->MipLevels);
          VkExtent3D mipLevelExtent = pTexture->MipLevelExtent(mip);

          if (mapMode != D3D11_COMMON_TEXTURE_MAP_MODE_STAGING) {
            VkDeviceSize mipSizePerLayer = util::computeImageDataSize(
              packedFormat, image->mipLevelExtent(mip), formatInfo->aspectMask);

            m_transferCommands += 1;

            util::packImageData(stagingSlice.mapPtr(dataOffset),
              pInitialData[index].pSysMem, pInitialData[index].SysMemPitch, pInitialData[index].SysMemSlicePitch,
              0, 0, pTexture->GetVkImageType(), mipLevelExtent, 1, formatInfo, formatInfo->aspectMask);

            dataOffset += mipSizePerLayer;
          }

          if (mapMode != D3D11_COMMON_TEXTURE_MAP_MODE_NONE) {
            util::packImageData(pTexture->GetMappedBuffer(index)->mapPtr(0),
              pInitialData[index].pSysMem, pInitialData[index].SysMemPitch, pInitialData[index].SysMemSlicePitch,
              0, 0, pTexture->GetVkImageType(), mipLevelExtent, 1, formatInfo, formatInfo->aspectMask);
          }
        }
      }

      // Upload all subresources of the image in one go
      if (mapMode != D3D11_COMMON_TEXTURE_MAP_MODE_STAGING) {
        EmitCs([
          cImage        = std::move(image),
          cStagingSlice = std::move(stagingSlice),
          cFormat       = packedFormat
        ] (DxvkContext* ctx) {
          ctx->uploadImage(cImage,
            cStagingSlice.buffer(),
            cStagingSlice.offset(),
            cFormat);
        });
      }
    } else {
      if (mapMode != D3D11_COMMON_TEXTURE_MAP_MODE_STAGING) {
        m_transferCommands += 1;
        
        // While the Microsoft docs state that resource contents are
        // undefined if no initial data is provided, some applications
        // expect a resource to be pre-cleared.
        EmitCs([
          cImage = std::move(image)
        ] (DxvkContext* ctx) {
          ctx->initImage(cImage,
            cImage->getAvailableSubresources(),
            VK_IMAGE_LAYOUT_UNDEFINED);
        });
      }

      if (mapMode != D3D11_COMMON_TEXTURE_MAP_MODE_NONE) {
        for (uint32_t i = 0; i < pTexture->CountSubresources(); i++) {
          auto buffer = pTexture->GetMappedBuffer(i);
          std::memset(buffer->mapPtr(0), 0, buffer->info().size);
        }
      }
    }

    ThrottleAllocationLocked();
  }


  void D3D11Initializer::InitHostVisibleTexture(
          D3D11CommonTexture*         pTexture,
    const D3D11_SUBRESOURCE_DATA*     pInitialData) {
    Rc<DxvkImage> image = pTexture->GetImage();

    for (uint32_t layer = 0; layer < image->info().numLayers; layer++) {
      for (uint32_t level = 0; level < image->info().mipLevels; level++) {
        VkImageSubresource subresource;
        subresource.aspectMask = image->formatInfo()->aspectMask;
        subresource.mipLevel   = level;
        subresource.arrayLayer = layer;

        VkExtent3D blockCount = util::computeBlockCount(
          image->mipLevelExtent(level),
          image->formatInfo()->blockSize);

        VkSubresourceLayout layout = image->querySubresourceLayout(subresource);

        auto initialData = pInitialData
          ? &pInitialData[D3D11CalcSubresource(level, layer, image->info().mipLevels)]
          : nullptr;

        for (uint32_t z = 0; z < blockCount.depth; z++) {
          for (uint32_t y = 0; y < blockCount.height; y++) {
            auto size = blockCount.width * image->formatInfo()->elementSize;
            auto dst = image->mapPtr(layout.offset + y * layout.rowPitch + z * layout.depthPitch);

            if (initialData) {
              auto src = reinterpret_cast<const char*>(initialData->pSysMem)
                       + y * initialData->SysMemPitch
                       + z * initialData->SysMemSlicePitch;
              std::memcpy(dst, src, size);
            } else {
              std::memset(dst, 0, size);
            }
          }
        }
      }
    }

    // Initialize the image on the GPU
    std::lock_guard<dxvk::mutex> lock(m_mutex);

    EmitCs([
      cImage = std::move(image)
    ] (DxvkContext* ctx) {
      ctx->initImage(cImage,
        cImage->getAvailableSubresources(),
        VK_IMAGE_LAYOUT_PREINITIALIZED);
    });

    m_transferCommands += 1;
    ThrottleAllocationLocked();
  }


  void D3D11Initializer::InitTiledTexture(
          D3D11CommonTexture*         pTexture) {
    std::lock_guard<dxvk::mutex> lock(m_mutex);

    EmitCs([
      cImage = pTexture->GetImage()
    ] (DxvkContext* ctx) {
      ctx->initSparseImage(cImage);
    });

    m_transferCommands += 1;
    ThrottleAllocationLocked();
  }


  void D3D11Initializer::ThrottleAllocationLocked() {
    DxvkStagingBufferStats stats = m_stagingBuffer.getStatistics();

    // If the amount of memory in flight exceeds the limit, stall the
    // calling thread and wait for some memory to actually get released.
    VkDeviceSize stagingMemoryInFlight = stats.allocatedTotal - m_stagingSignal->value();

    if (stagingMemoryInFlight > MaxMemoryInFlight) {
      ExecuteFlushLocked();

      m_stagingSignal->wait(stats.allocatedTotal - MaxMemoryInFlight);
    } else if (m_transferCommands >= MaxCommandsPerSubmission || stats.allocatedSinceLastReset >= MaxMemoryPerSubmission) {
      // Flush pending commands if there are a lot of updates in flight
      // to keep both execution time and staging memory in check.
      ExecuteFlushLocked();
    }
  }


  void D3D11Initializer::ExecuteFlush() {
    std::lock_guard lock(m_mutex);

    ExecuteFlushLocked();
  }


  void D3D11Initializer::ExecuteFlushLocked() {
    DxvkStagingBufferStats stats = m_stagingBuffer.getStatistics();

    EmitCs([
      cSignal       = m_stagingSignal,
      cSignalValue  = stats.allocatedTotal
    ] (DxvkContext* ctx) {
      ctx->signal(cSignal, cSignalValue);
      ctx->flushCommandList(nullptr);
    });

    FlushCsChunk();

    NotifyContextFlushLocked();
  }


  void D3D11Initializer::SyncSharedTexture(D3D11CommonTexture* pResource) {
    if (!(pResource->Desc()->MiscFlags & (D3D11_RESOURCE_MISC_SHARED | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX | D3D11_RESOURCE_MISC_SHARED_NTHANDLE)))
      return;

    // Ensure that initialization commands are submitted and waited on before
    // returning control to the application in order to avoid race conditions
    // in case the texture is used immediately on a secondary device.
    auto mapMode = pResource->GetMapMode();

    if (mapMode == D3D11_COMMON_TEXTURE_MAP_MODE_NONE
     || mapMode == D3D11_COMMON_TEXTURE_MAP_MODE_BUFFER) {
      ExecuteFlush();

      m_device->waitForResource(pResource->GetImage(), DxvkAccess::Write);
    }

    // If a keyed mutex is used, initialize that to the correct state as well.
    Com<IDXGIKeyedMutex> keyedMutex;

    if (SUCCEEDED(pResource->GetInterface()->QueryInterface(
        __uuidof(IDXGIKeyedMutex), reinterpret_cast<void**>(&keyedMutex)))) {
      keyedMutex->AcquireSync(0, 0);
      keyedMutex->ReleaseSync(0);
    }
  }


  void D3D11Initializer::FlushCsChunkLocked() {
    m_parent->GetContext()->InjectCsChunk(std::move(m_csChunk), false);
    m_csChunk = m_parent->AllocCsChunk(DxvkCsChunkFlag::SingleUse);
  }


  void D3D11Initializer::NotifyContextFlushLocked() {
    m_stagingBuffer.reset();
    m_transferCommands = 0;
  }

}
