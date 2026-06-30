#[=======================================================================[.rst:
FindCryptopp.cmake
-------

查找 Crypto++ 库

导入目标
^^^^^^^^

``cryptopp::cryptopp``
  该库提供了以下导入目标（如果找到）：

结果变量
^^^^^^^^

``Cryptopp_FOUND``
  如果找到库，则为 True。

``Cryptopp_INCLUDE_DIRS``
  包含头文件的目录。

``Cryptopp_LIBRARIES``
  要链接的库文件。

提示
^^^^^^^^

``CRYPTOPP_ROOT``
  可以设置此环境变量或 CMake 变量来指定库的安装前缀。

``CRYPTOPP_LIBRARY_TYPE``
  可以设置此环境变量或 CMake 变量来指定库的类型。
#]=======================================================================]

# 寻找头文件
find_path(Cryptopp_INCLUDE_DIR
  NAMES cryptopp/cryptlib.h
  HINTS ${CRYPTOPP_ROOT} ENV CRYPTOPP_ROOT
  PATH_SUFFIXES include
)

# 寻找库文件
if(CRYPTOPP_LIBRARY_TYPE STREQUAL "STATIC")
  set(CMAKE_FIND_LIBRARY_SUFFIXES .a)           # 只找 .a
elseif(CRYPTOPP_LIBRARY_TYPE STREQUAL "SHARED")
  set(CMAKE_FIND_LIBRARY_SUFFIXES .so .so.8)    # 只找 .so
endif()

find_library(Cryptopp_LIBRARY
  NAMES cryptopp                                # 基础名，CMake 自动拼前缀和后缀
  HINTS
    ${CRYPTOPP_ROOT}                            # 用户指定路径
    ENV CRYPTOPP_ROOT                           # 环境变量
    ${PC_Cryptopp_LIBRARY_DIRS}                 # pkg-config 路径
  PATH_SUFFIXES
    lib                                         # 标准路径
    lib64                                       # 64 位系统
    lib/x86_64-linux-gnu                        # Debian/Ubuntu 多架构
  DOC "Crypto++ library path"
)

# 恢复原始后缀
set(CMAKE_FIND_LIBRARY_SUFFIXES ${_cryptopp_saved_suffixes})

# 标准化结果处理
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Cryptopp
  REQUIRED_VARS Cryptopp_LIBRARY Cryptopp_INCLUDE_DIR
)

if(Cryptopp_FOUND AND NOT TARGET Cryptopp::Cryptopp)
  add_library(Cryptopp::Cryptopp UNKNOWN IMPORTED)
  set_target_properties(Cryptopp::Cryptopp PROPERTIES
    IMPORTED_LOCATION "${Cryptopp_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${Cryptopp_INCLUDE_DIR}"
  )

endif()

if(Cryptopp_FOUND)
  message(STATUS "Cryptopp found:")
  message(STATUS "  Include: ${Cryptopp_INCLUDE_DIR}")
  message(STATUS "  Library: ${Cryptopp_LIBRARY}")
else()
  message(STATUS "Cryptopp not found")
endif()

mark_as_advanced(Cryptopp_INCLUDE_DIR Cryptopp_LIBRARY)
