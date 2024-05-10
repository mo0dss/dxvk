spirv_src = files([
  'spirv_code_buffer.cpp',
  'spirv_compression.cpp',
  'spirv_module.cpp',
])

dep_streamvbyte = dependency(
  'streamvbyte',
  version: ['v1.0.0'],
  fallback: ['streamvbyte', 'dep_streamvbyte'],
  default_options: ['default_library=static'],
  method: 'cmake'
)

spirv_lib = static_library(
  'spirv', spirv_src,
  dependencies        : [ dep_streamvbyte   ],
  include_directories : [ dxvk_include_path ],
)
