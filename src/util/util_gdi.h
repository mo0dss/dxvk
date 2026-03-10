#pragma once

#include <d3d9.h>
#include <dxgi.h>
#include <d3d11_4.h>
#include <d3d12.h>

#ifndef _WIN32
#define EXTERN_C
#define WINBASEAPI
#endif

namespace dxvk {
  using NTSTATUS = LONG;
  using D3DDDIFORMAT = D3DFORMAT;
  using D3DKMT_HANDLE = UINT;
  using D3DGPU_VIRTUAL_ADDRESS = ULONGLONG;

  typedef struct _D3DKMT_ACQUIREKEYEDMUTEX
  {
      D3DKMT_HANDLE hKeyedMutex;
      UINT64 Key;
      LARGE_INTEGER *pTimeout;
      UINT64 FenceValue;
  } D3DKMT_ACQUIREKEYEDMUTEX;

  typedef struct _D3DKMT_CLOSEADAPTER
  {
      D3DKMT_HANDLE hAdapter;
  } D3DKMT_CLOSEADAPTER;

  typedef struct _D3DKMT_CREATEDCFROMMEMORY
  {
      void *pMemory;
      D3DDDIFORMAT Format;
      UINT Width;
      UINT Height;
      UINT Pitch;
      HDC hDeviceDc;
      PALETTEENTRY *pColorTable;
      HDC hDc;
      HANDLE hBitmap;
  } D3DKMT_CREATEDCFROMMEMORY;

  typedef struct _D3DKMT_CREATEDEVICEFLAGS
  {
      UINT LegacyMode : 1;
      UINT RequestVSync : 1;
      UINT DisableGpuTimeout : 1;
      UINT Reserved : 29;
  } D3DKMT_CREATEDEVICEFLAGS;

  typedef struct _D3DDDI_ALLOCATIONLIST
  {
      D3DKMT_HANDLE hAllocation;
      union
      {
          struct
          {
              UINT WriteOperation : 1;
              UINT DoNotRetireInstance : 1;
              UINT OfferPriority : 3;
              UINT Reserved : 27;
          } DUMMYSTRUCTNAME;
          UINT Value;
      } DUMMYUNIONNAME;
  } D3DDDI_ALLOCATIONLIST;

  typedef struct _D3DDDI_PATCHLOCATIONLIST
  {
      UINT AllocationIndex;
      union
      {
          struct
          {
              UINT SlotId : 24;
              UINT Reserved : 8;
          } DUMMYSTRUCTNAME;
          UINT Value;
      } DUMMYUNIONNAME;
      UINT DriverId;
      UINT AllocationOffset;
      UINT PatchOffset;
      UINT SplitOffset;
  } D3DDDI_PATCHLOCATIONLIST;

  typedef struct _D3DKMT_CREATEDEVICE
  {
      union
      {
          D3DKMT_HANDLE hAdapter;
          VOID *pAdapter;
      } DUMMYUNIONNAME;
      D3DKMT_CREATEDEVICEFLAGS Flags;
      D3DKMT_HANDLE hDevice;
      VOID *pCommandBuffer;
      UINT CommandBufferSize;
      D3DDDI_ALLOCATIONLIST *pAllocationList;
      UINT AllocationListSize;
      D3DDDI_PATCHLOCATIONLIST *pPatchLocationList;
      UINT PatchLocationListSize;
  } D3DKMT_CREATEDEVICE;

  typedef struct _D3DKMT_CREATEKEYEDMUTEX2_FLAGS
  {
      union
      {
          struct
          {
              UINT NtSecuritySharing : 1;
              UINT Reserved : 31;
          };
          UINT Value;
      };
  } D3DKMT_CREATEKEYEDMUTEX2_FLAGS;

  typedef struct _D3DKMT_CREATEKEYEDMUTEX2
  {
      UINT64 InitialValue;
      D3DKMT_HANDLE hSharedHandle;
      D3DKMT_HANDLE hKeyedMutex;
      void *pPrivateRuntimeData;
      UINT PrivateRuntimeDataSize;
      D3DKMT_CREATEKEYEDMUTEX2_FLAGS Flags;
  } D3DKMT_CREATEKEYEDMUTEX2;

  typedef struct _D3DKMT_DESTROYALLOCATION
  {
      D3DKMT_HANDLE hDevice;
      D3DKMT_HANDLE hResource;
      const D3DKMT_HANDLE *phAllocationList;
      UINT AllocationCount;
  } D3DKMT_DESTROYALLOCATION;

  typedef struct _D3DKMT_DESTROYDCFROMMEMORY
  {
      HDC hDc;
      HANDLE hBitmap;
  } D3DKMT_DESTROYDCFROMMEMORY;

  typedef struct _D3DKMT_DESTROYDEVICE
  {
      D3DKMT_HANDLE hDevice;
  } D3DKMT_DESTROYDEVICE;

  typedef struct _D3DKMT_DESTROYKEYEDMUTEX
  {
      D3DKMT_HANDLE hKeyedMutex;
  } D3DKMT_DESTROYKEYEDMUTEX;

  typedef struct _D3DKMT_DESTROYSYNCHRONIZATIONOBJECT
  {
      D3DKMT_HANDLE hSyncObject;
  } D3DKMT_DESTROYSYNCHRONIZATIONOBJECT;

  typedef enum _D3DKMT_ESCAPETYPE
  {
      D3DKMT_ESCAPE_UPDATE_RESOURCE_WINE = 0x80000000,
      D3DKMT_ESCAPE_SET_PRESENT_RECT_WINE = 0x80000001,
  } D3DKMT_ESCAPETYPE;

  typedef struct _D3DDDI_ESCAPEFLAGS
  {
      union
      {
          struct
          {
              UINT HardwareAccess :1;
              UINT Reserved       :31;
          };
          UINT Value;
      };
  } D3DDDI_ESCAPEFLAGS;

  typedef struct _D3DKMT_ESCAPE
  {
      D3DKMT_HANDLE      hAdapter;
      D3DKMT_HANDLE      hDevice;
      D3DKMT_ESCAPETYPE  Type;
      D3DDDI_ESCAPEFLAGS Flags;
      void              *pPrivateDriverData;
      UINT               PrivateDriverDataSize;
      D3DKMT_HANDLE      hContext;
  } D3DKMT_ESCAPE;

  typedef struct _D3DKMT_OPENADAPTERFROMLUID
  {
      LUID AdapterLuid;
      D3DKMT_HANDLE hAdapter;
  } D3DKMT_OPENADAPTERFROMLUID;

  typedef struct _D3DKMT_OPENKEYEDMUTEX
  {
      D3DKMT_HANDLE hSharedHandle;
      D3DKMT_HANDLE hKeyedMutex;
  } D3DKMT_OPENKEYEDMUTEX;

  typedef struct _D3DDDI_OPENALLOCATIONINFO
  {
      D3DKMT_HANDLE hAllocation;
      const void *pPrivateDriverData;
      UINT PrivateDriverDataSize;
  } D3DDDI_OPENALLOCATIONINFO;

  typedef struct _D3DDDI_OPENALLOCATIONINFO2
  {
      D3DKMT_HANDLE hAllocation;
      const void *pPrivateDriverData;
      UINT PrivateDriverDataSize;
      D3DGPU_VIRTUAL_ADDRESS GpuVirtualAddress;
      ULONG_PTR Reserved[6];
  } D3DDDI_OPENALLOCATIONINFO2;

  typedef struct _D3DKMT_OPENRESOURCE
  {
      D3DKMT_HANDLE hDevice;
      D3DKMT_HANDLE hGlobalShare;
      UINT NumAllocations;
      union
      {
          D3DDDI_OPENALLOCATIONINFO *pOpenAllocationInfo;
          D3DDDI_OPENALLOCATIONINFO2 *pOpenAllocationInfo2;
      };
      void *pPrivateRuntimeData;
      UINT PrivateRuntimeDataSize;
      void *pResourcePrivateDriverData;
      UINT ResourcePrivateDriverDataSize;
      void *pTotalPrivateDriverDataBuffer;
      UINT TotalPrivateDriverDataBufferSize;
      D3DKMT_HANDLE hResource;
  } D3DKMT_OPENRESOURCE;

  typedef struct _D3DKMT_OPENRESOURCEFROMNTHANDLE
  {
      D3DKMT_HANDLE hDevice;
      HANDLE hNtHandle;
      UINT NumAllocations;
      D3DDDI_OPENALLOCATIONINFO2 *pOpenAllocationInfo2;
      UINT PrivateRuntimeDataSize;
      void *pPrivateRuntimeData;
      UINT ResourcePrivateDriverDataSize;
      void *pResourcePrivateDriverData;
      UINT TotalPrivateDriverDataBufferSize;
      void *pTotalPrivateDriverDataBuffer;
      D3DKMT_HANDLE hResource;
      D3DKMT_HANDLE hKeyedMutex;
      void *pKeyedMutexPrivateRuntimeData;
      UINT KeyedMutexPrivateRuntimeDataSize;
      D3DKMT_HANDLE hSyncObject;
  } D3DKMT_OPENRESOURCEFROMNTHANDLE;

  typedef struct _D3DKMT_OPENSYNCHRONIZATIONOBJECT
  {
      D3DKMT_HANDLE hSharedHandle;
      D3DKMT_HANDLE hSyncObject;
      UINT64 Reserved[8];
  } D3DKMT_OPENSYNCHRONIZATIONOBJECT;

  typedef struct _D3DKMT_OPENSYNCOBJECTFROMNTHANDLE
  {
      HANDLE hNtHandle;
      D3DKMT_HANDLE hSyncObject;
  } D3DKMT_OPENSYNCOBJECTFROMNTHANDLE;

  typedef struct _D3DKMT_QUERYRESOURCEINFO
  {
      D3DKMT_HANDLE hDevice;
      D3DKMT_HANDLE hGlobalShare;
      void *pPrivateRuntimeData;
      UINT PrivateRuntimeDataSize;
      UINT TotalPrivateDriverDataSize;
      UINT ResourcePrivateDriverDataSize;
      UINT NumAllocations;
  } D3DKMT_QUERYRESOURCEINFO;

  typedef struct _D3DKMT_QUERYRESOURCEINFOFROMNTHANDLE
  {
      D3DKMT_HANDLE hDevice;
      HANDLE hNtHandle;
      void *pPrivateRuntimeData;
      UINT PrivateRuntimeDataSize;
      UINT TotalPrivateDriverDataSize;
      UINT ResourcePrivateDriverDataSize;
      UINT NumAllocations;
  } D3DKMT_QUERYRESOURCEINFOFROMNTHANDLE;

  typedef enum _KMTQUERYADAPTERINFOTYPE {
      KMTQAITYPE_UMDRIVERPRIVATE,
      KMTQAITYPE_UMDRIVERNAME,
      KMTQAITYPE_UMOPENGLINFO,
      KMTQAITYPE_GETSEGMENTSIZE,
      KMTQAITYPE_ADAPTERGUID,
      KMTQAITYPE_FLIPQUEUEINFO,
      KMTQAITYPE_ADAPTERADDRESS,
      KMTQAITYPE_SETWORKINGSETINFO,
      KMTQAITYPE_ADAPTERREGISTRYINFO,
      KMTQAITYPE_CURRENTDISPLAYMODE,
      KMTQAITYPE_MODELIST,
      KMTQAITYPE_CHECKDRIVERUPDATESTATUS,
      KMTQAITYPE_VIRTUALADDRESSINFO,
      KMTQAITYPE_DRIVERVERSION,
      KMTQAITYPE_ADAPTERTYPE,
      KMTQAITYPE_OUTPUTDUPLCONTEXTSCOUNT,
      KMTQAITYPE_WDDM_1_2_CAPS,
      KMTQAITYPE_UMD_DRIVER_VERSION,
      KMTQAITYPE_DIRECTFLIP_SUPPORT,
      KMTQAITYPE_MULTIPLANEOVERLAY_SUPPORT,
      KMTQAITYPE_DLIST_DRIVER_NAME,
      KMTQAITYPE_WDDM_1_3_CAPS,
      KMTQAITYPE_MULTIPLANEOVERLAY_HUD_SUPPORT,
      KMTQAITYPE_WDDM_2_0_CAPS,
      KMTQAITYPE_NODEMETADATA,
      KMTQAITYPE_CPDRIVERNAME,
      KMTQAITYPE_XBOX,
      KMTQAITYPE_INDEPENDENTFLIP_SUPPORT,
      KMTQAITYPE_MIRACASTCOMPANIONDRIVERNAME,
      KMTQAITYPE_PHYSICALADAPTERCOUNT,
      KMTQAITYPE_PHYSICALADAPTERDEVICEIDS,
      KMTQAITYPE_DRIVERCAPS_EXT,
      KMTQAITYPE_QUERY_MIRACAST_DRIVER_TYPE,
      KMTQAITYPE_QUERY_GPUMMU_CAPS,
      KMTQAITYPE_QUERY_MULTIPLANEOVERLAY_DECODE_SUPPORT,
      KMTQAITYPE_QUERY_HW_PROTECTION_TEARDOWN_COUNT,
      KMTQAITYPE_QUERY_ISBADDRIVERFORHWPROTECTIONDISABLED,
      KMTQAITYPE_MULTIPLANEOVERLAY_SECONDARY_SUPPORT,
      KMTQAITYPE_INDEPENDENTFLIP_SECONDARY_SUPPORT,
      KMTQAITYPE_PANELFITTER_SUPPORT,
      KMTQAITYPE_PHYSICALADAPTERPNPKEY,
      KMTQAITYPE_GETSEGMENTGROUPSIZE,
      KMTQAITYPE_MPO3DDI_SUPPORT,
      KMTQAITYPE_HWDRM_SUPPORT,
      KMTQAITYPE_MPOKERNELCAPS_SUPPORT,
      KMTQAITYPE_MULTIPLANEOVERLAY_STRETCH_SUPPORT,
      KMTQAITYPE_GET_DEVICE_VIDPN_OWNERSHIP_INFO,
      KMTQAITYPE_QUERYREGISTRY,
      KMTQAITYPE_KMD_DRIVER_VERSION,
      KMTQAITYPE_BLOCKLIST_KERNEL,
      KMTQAITYPE_BLOCKLIST_RUNTIME,
      KMTQAITYPE_ADAPTERGUID_RENDER,
      KMTQAITYPE_ADAPTERADDRESS_RENDER,
      KMTQAITYPE_ADAPTERREGISTRYINFO_RENDER,
      KMTQAITYPE_CHECKDRIVERUPDATESTATUS_RENDER,
      KMTQAITYPE_DRIVERVERSION_RENDER,
      KMTQAITYPE_ADAPTERTYPE_RENDER,
      KMTQAITYPE_WDDM_1_2_CAPS_RENDER,
      KMTQAITYPE_WDDM_1_3_CAPS_RENDER,
      KMTQAITYPE_QUERY_ADAPTER_UNIQUE_GUID,
      KMTQAITYPE_NODEPERFDATA,
      KMTQAITYPE_ADAPTERPERFDATA,
      KMTQAITYPE_ADAPTERPERFDATA_CAPS,
      KMTQUITYPE_GPUVERSION,
      KMTQAITYPE_DRIVER_DESCRIPTION,
      KMTQAITYPE_DRIVER_DESCRIPTION_RENDER,
      KMTQAITYPE_SCANOUT_CAPS,
      KMTQAITYPE_DISPLAY_UMDRIVERNAME,
      KMTQAITYPE_PARAVIRTUALIZATION_RENDER,
      KMTQAITYPE_SERVICENAME,
      KMTQAITYPE_WDDM_2_7_CAPS,
      KMTQAITYPE_TRACKEDWORKLOAD_SUPPORT,
      KMTQAITYPE_HYBRID_DLIST_DLL_SUPPORT,
      KMTQAITYPE_DISPLAY_CAPS,
      KMTQAITYPE_WDDM_2_9_CAPS,
      KMTQAITYPE_CROSSADAPTERRESOURCE_SUPPORT,
      KMTQAITYPE_WDDM_3_0_CAPS,
      KMTQAITYPE_WSAUMDIMAGENAME,
      KMTQAITYPE_VGPUINTERFACEID,
      KMTQAITYPE_WDDM_3_1_CAPS,
      KMTQAITYPE_HYBRID_DLIST_DLL_MUX_SUPPORT
  } KMTQUERYADAPTERINFOTYPE;

  typedef struct _D3DKMT_QUERYADAPTERINFO
  {
      D3DKMT_HANDLE           hAdapter;
      KMTQUERYADAPTERINFOTYPE Type;
      VOID                    *pPrivateDriverData;
      UINT                    PrivateDriverDataSize;
  } D3DKMT_QUERYADAPTERINFO;

  typedef struct _D3DKMT_FLIPINFOFLAGS {
      UINT FlipInterval : 1;
      UINT Reserved : 31;
  } D3DKMT_FLIPINFOFLAGS;

  typedef struct _D3DKMT_FLIPQUEUEINFO {
       UINT                 MaxHardwareFlipQueueLength;
       UINT                 MaxSoftwareFlipQueueLength;
       D3DKMT_FLIPINFOFLAGS FlipFlags;
  } D3DKMT_FLIPQUEUEINFO;

  typedef struct _D3DKMT_WDDM_3_0_CAPS {
      union {
        struct {
          UINT HwFlipQueueSupportState : 2;
          UINT HwFlipQueueEnabled : 1;
          UINT DisplayableSupported : 1;
          UINT Reserved : 28;
        };
        UINT Value;
      };
  } D3DKMT_WDDM_3_0_CAPS;

  #define DXGK_FEATURE_SUPPORT_ALWAYS_OFF 0
  #define DXGK_FEATURE_SUPPORT_EXPERIMENTAL 1
  #define DXGK_FEATURE_SUPPORT_STABLE 2
  #define DXGK_FEATURE_SUPPORT_ALWAYS_ON 3

  typedef struct _D3DKMT_RELEASEKEYEDMUTEX
  {
      D3DKMT_HANDLE hKeyedMutex;
      UINT64 Key;
      UINT64 FenceValue;
  } D3DKMT_RELEASEKEYEDMUTEX;

  typedef struct _UNICODE_STRING {
      USHORT Length;        /* bytes */
      USHORT MaximumLength; /* bytes */
      WCHAR *Buffer;
  } UNICODE_STRING;

  typedef struct _OBJECT_ATTRIBUTES {
      ULONG Length;
      HANDLE RootDirectory;
      UNICODE_STRING *ObjectName;
      ULONG Attributes;
      void *SecurityDescriptor;
      void *SecurityQualityOfService;
  } OBJECT_ATTRIBUTES;

  #define OBJ_CASE_INSENSITIVE 0x00000040

  /* undocumented D3D runtime data descriptors */

  struct d3dkmt_dxgi_desc
  {
      UINT                        size;
      UINT                        version;
      UINT                        width;
      UINT                        height;
      DXGI_FORMAT                 format;
      UINT                        unknown_0;
      UINT                        unknown_1;
      UINT                        keyed_mutex;
      D3DKMT_HANDLE               mutex_handle;
      D3DKMT_HANDLE               sync_handle;
      UINT                        nt_shared;
      UINT                        unknown_2;
      UINT                        unknown_3;
      UINT                        unknown_4;
  };

  struct d3dkmt_d3d9_desc
  {
      struct d3dkmt_dxgi_desc     dxgi;
      D3DFORMAT                   format;
      D3DRESOURCETYPE             type;
      UINT                        usage;
      union
      {
          struct
          {
              UINT                unknown_0;
              UINT                width;
              UINT                height;
              UINT                levels;
              UINT                depth;
          } texture;
          struct
          {
              UINT                unknown_0;
              UINT                unknown_1;
              UINT                unknown_2;
              UINT                width;
              UINT                height;
          } surface;
          struct
          {
              UINT                unknown_0;
              UINT                width;
              UINT                format;
              UINT                unknown_1;
              UINT                unknown_2;
          } buffer;
      };
  };

  static_assert( sizeof(struct d3dkmt_d3d9_desc) == 0x58 );

  struct d3dkmt_d3d11_desc
  {
      struct d3dkmt_dxgi_desc     dxgi;
      D3D11_RESOURCE_DIMENSION    dimension;
      union
      {
          D3D11_BUFFER_DESC       d3d11_buf;
          D3D11_TEXTURE1D_DESC    d3d11_1d;
          D3D11_TEXTURE2D_DESC    d3d11_2d;
          D3D11_TEXTURE3D_DESC    d3d11_3d;
      };
  };

  static_assert( sizeof(struct d3dkmt_d3d11_desc) == 0x68 );

  typedef struct D3D12_MIP_REGION
  {
      UINT Width;
      UINT Height;
      UINT Depth;
  } D3D12_MIP_REGION;

  typedef struct D3D12_RESOURCE_DESC1
  {
      D3D12_RESOURCE_DIMENSION Dimension;
      UINT64 Alignment;
      UINT64 Width;
      UINT Height;
      UINT16 DepthOrArraySize;
      UINT16 MipLevels;
      DXGI_FORMAT Format;
      DXGI_SAMPLE_DESC SampleDesc;
      D3D12_TEXTURE_LAYOUT Layout;
      D3D12_RESOURCE_FLAGS Flags;
      D3D12_MIP_REGION SamplerFeedbackMipRegion;
  } D3D12_RESOURCE_DESC1;

  struct d3dkmt_d3d12_desc
  {
      struct d3dkmt_d3d11_desc    d3d11;
      UINT                        unknown_5[4];
      UINT                        resource_size;
      UINT                        unknown_6[7];
      UINT                        resource_align;
      UINT                        unknown_7[9];
      union
      {
          D3D12_RESOURCE_DESC     desc;
          D3D12_RESOURCE_DESC1    desc1;
          UINT                    __pad[16];
      };
      UINT64                      unknown_8[1];
  };

  static_assert( sizeof(struct d3dkmt_d3d12_desc) == 0x108 );

  union d3dkmt_desc
  {
      struct d3dkmt_dxgi_desc     dxgi;
      struct d3dkmt_d3d9_desc     d3d9;   /* if dxgi.size == sizeof(d3d9)  && dxgi.version == 1 && sizeof(desc) == sizeof(d3d9) */
      struct d3dkmt_d3d11_desc    d3d11;  /* if dxgi.size == sizeof(d3d11) && dxgi.version == 4 && sizeof(desc) >= sizeof(d3d11) */
      struct d3dkmt_d3d12_desc    d3d12;  /* if dxgi.size == sizeof(d3d11) && dxgi.version == 0 && sizeof(desc) == sizeof(d3d12) */
  };

  typedef UINT D3DDDI_VIDEO_PRESENT_SOURCE_ID;

  typedef struct _D3DKMT_QUERYREMOTEVIDPNSOURCEFROMGDIDISPLAYNAME {
        WCHAR                          DeviceName[32];
        D3DDDI_VIDEO_PRESENT_SOURCE_ID VidPnSourceId;
  } D3DKMT_QUERYREMOTEVIDPNSOURCEFROMGDIDISPLAYNAME;

  typedef struct _D3DKMT_WAITFORVERTICALBLANKEVENT {
       D3DKMT_HANDLE                  hAdapter;
       D3DKMT_HANDLE                  hDevice;
       D3DDDI_VIDEO_PRESENT_SOURCE_ID VidPnSourceId;
  } D3DKMT_WAITFORVERTICALBLANKEVENT;

  NTSTATUS WINAPI D3DKMTAcquireKeyedMutex(D3DKMT_ACQUIREKEYEDMUTEX *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTCloseAdapter(const D3DKMT_CLOSEADAPTER *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTCreateDCFromMemory(D3DKMT_CREATEDCFROMMEMORY *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTCreateDevice(D3DKMT_CREATEDEVICE *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTCreateKeyedMutex2(D3DKMT_CREATEKEYEDMUTEX2 *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTDestroyAllocation(const D3DKMT_DESTROYALLOCATION *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTDestroyDCFromMemory(const D3DKMT_DESTROYDCFROMMEMORY *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTDestroyDevice(const D3DKMT_DESTROYDEVICE *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTDestroyKeyedMutex(const D3DKMT_DESTROYKEYEDMUTEX *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTDestroySynchronizationObject(const D3DKMT_DESTROYSYNCHRONIZATIONOBJECT *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTEscape(const D3DKMT_ESCAPE *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTOpenAdapterFromLuid(D3DKMT_OPENADAPTERFROMLUID *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTOpenKeyedMutex(D3DKMT_OPENKEYEDMUTEX *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTOpenResource2(D3DKMT_OPENRESOURCE *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTOpenResourceFromNtHandle(D3DKMT_OPENRESOURCEFROMNTHANDLE *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTOpenSynchronizationObject(D3DKMT_OPENSYNCHRONIZATIONOBJECT *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTOpenSyncObjectFromNtHandle(D3DKMT_OPENSYNCOBJECTFROMNTHANDLE *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTQueryResourceInfo(D3DKMT_QUERYRESOURCEINFO *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTQueryResourceInfoFromNtHandle(D3DKMT_QUERYRESOURCEINFOFROMNTHANDLE *desc);
  EXTERN_C WINBASEAPI NTSTATUS D3DKMTQueryAdapterInfo(const D3DKMT_QUERYADAPTERINFO *unnamedParam1);
  NTSTATUS WINAPI D3DKMTReleaseKeyedMutex(D3DKMT_RELEASEKEYEDMUTEX *desc);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTShareObjects(UINT count, const D3DKMT_HANDLE *handles, OBJECT_ATTRIBUTES *attr, UINT access, HANDLE *handle);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTQueryRemoteVidPnSourceFromGdiDisplayName(D3DKMT_QUERYREMOTEVIDPNSOURCEFROMGDIDISPLAYNAME *unnamedParam1);
  EXTERN_C WINBASEAPI NTSTATUS WINAPI D3DKMTWaitForVerticalBlankEvent(const D3DKMT_WAITFORVERTICALBLANKEVENT *unnamedParam1);
}
