PROJECT (libdnf C)
CMAKE_MINIMUM_REQUIRED (VERSION 2.4)
CMAKE_POLICY (SET CMP0005 OLD)
# Avoid a warning because "hth" links to
# the in-tree libhawkey, but uses pkg-config to find
# GLib.  There may be a better way to do this...
CMAKE_POLICY(SET CMP0003 NEW)

set(CMAKE_INCLUDE_PATH /opt/local/include ${CMAKE_INCLUDE_PATH})
set(CMAKE_LIBRARY_PATH /opt/local/lib ${CMAKE_LIBRARY_PATH})

include (VERSION.cmake)
message ("Building libdnf version: ${LIBDNF_VERSION}")

IF (APPLE)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wcast-align -Wno-uninitialized -Wmissing-declarations -Wredundant-decls -Wcast-align -Wwrite-strings -Wreturn-type -Wformat-nonliteral -Wmissing-format-attribute -Wsign-compare -Wtype-limits -Wuninitialized -Waggregate-return -Wshadow -Winline -Wall -Werror=implicit-function-declaration")
ELSE (APPLE)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wcast-align -Wno-uninitialized -Wmissing-declarations -Wredundant-decls -Wcast-align -Wwrite-strings -Wreturn-type -Wformat-nonliteral -Wmissing-format-attribute -Wsign-compare -Wtype-limits -Wuninitialized -Waggregate-return -Wshadow -Winline -Wall -Werror=implicit-function-declaration -Wl,--as-needed")
ENDIF (APPLE)

set (CMAKE_C_FLAGS_DEBUG	"${CMAKE_C_FLAGS} -ggdb -O0")
IF(NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE DEBUG)
ENDIF(NOT CMAKE_BUILD_TYPE)

ADD_DEFINITIONS(-DG_LOG_DOMAIN=\\"libdnf\\")

INCLUDE_DIRECTORIES (${CMAKE_SOURCE_DIR})

IF (MACOSX)
  MESSAGE(STATUS "Building for Mac OS X")
  SET (CMAKE_MACOSX_RPATH "1")
  ADD_DEFINITIONS (-DMACOSX)
ENDIF (MACOSX)

OPTION (ENABLE_SOLV_URPMREORDER "Build with support for URPM-like solution reordering?" OFF)

# hawkey dependencies
find_package (PkgConfig REQUIRED)
SET (CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
PKG_CHECK_MODULES(GLIB gio-unix-2.0>=2.44.0 REQUIRED)
#find_package (LibSolv 0.6.21 REQUIRED COMPONENTS ext)
find_package (LibSolv 0.6.23 REQUIRED COMPONENTS ext)
pkg_check_modules (CHECK REQUIRED check)
pkg_check_modules (REPO REQUIRED librepo)
FIND_PROGRAM (VALGRIND_PROGRAM NAMES valgrind PATH /usr/bin /usr/local/bin)

# TODO handle yumdb / dnfdb for libdnf
ADD_DEFINITIONS(-DBUILDOPT_USE_DNF_YUMDB=1)

IF (ENABLE_SOLV_URPMREORDER)
   ADD_DEFINITIONS(-DLIBSOLV_FLAG_URPMREORDER=1)
ENDIF()

INCLUDE_DIRECTORIES(${GLIB_INCLUDE_DIRS})

# rpm:
IF (RPM5)

  MESSAGE (STATUS "Enabling RPM 5 support")
  ADD_DEFINITIONS (-DRPM5)
  PKG_CHECK_MODULES (RPM REQUIRED rpm)
  INCLUDE_DIRECTORIES (${RPM_INCLUDE_DIRS})
  SET(RPMDB_LIBRARY ${RPM_LDFLAGS})
  message("Using system RPM: ${RPMDB_LIBRARY}")

ELSE (RPM5)

  FIND_LIBRARY (RPMDB_LIBRARY NAMES rpmdb)
  IF (NOT RPMDB_LIBRARY)
    FIND_LIBRARY (RPMDB_LIBRARY NAMES rpm)
  ENDIF (NOT RPMDB_LIBRARY)
  FIND_LIBRARY (RPMIO_LIBRARY NAMES rpmio)
  IF (RPMIO_LIBRARY)
    SET(RPMDB_LIBRARY ${RPMIO_LIBRARY} ${RPMDB_LIBRARY})
  ENDIF (RPMIO_LIBRARY)
  message("Using system RPM: ${RPMDB_LIBRARY}")

ENDIF (RPM5)

if (NOT PYTHON_DESIRED)
    set (PYTHON_DESIRED "2")
endif()

ADD_DEFINITIONS(-DTESTDATADIR=\\"${CMAKE_SOURCE_DIR}/data/tests\\")
ADD_DEFINITIONS(-DPACKAGE_VERSION=\\"${LIBDNF_VERSION}\\")

IF (CMAKE_SIZEOF_VOID_P MATCHES "8")
  SET (LIB_SUFFIX "64")
ENDIF (CMAKE_SIZEOF_VOID_P MATCHES "8")
SET (LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}")

ADD_SUBDIRECTORY (libdnf)
ENABLE_TESTING()
ADD_SUBDIRECTORY (tests)
ADD_SUBDIRECTORY (python/hawkey)
ADD_SUBDIRECTORY (docs/hawkey)
ADD_SUBDIRECTORY (docs/libdnf)
