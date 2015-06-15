CMAKE_MINIMUM_REQUIRED(VERSION 3.1)
CMAKE_POLICY(SET CMP0048 NEW)

PROJECT(
	pwsafe
	VERSION 0.2.1
	LANGUAGES CXX C
)

IF (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
	MESSAGE(FATAL_ERROR "Please run CMake in a separate directory.")
ENDIF()

#
# Options
#
OPTION(GETOPT_LONG "Use getopt_long to parse arguments" ON)
OPTION(USE_X11 "Support copying to the X11 clipboard" ON)

#
# Required CMake modules
#
INCLUDE(CheckIncludeFile)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckTypeSize)

#
# Locate OpenSSL
#
FIND_PACKAGE(OpenSSL REQUIRED)

#
# Locate required headers
#
CHECK_INCLUDE_FILE(unistd.h HAVE_UNISTD_H)
CHECK_INCLUDE_FILE(sys/param.h HAVE_SYS_PARAM_H)
CHECK_INCLUDE_FILE(sys/time.h HAVE_SYS_TIME_H)
CHECK_INCLUDE_FILE(time.h HAVE_TIME_H)
CHECK_INCLUDE_FILE(sys/types.h HAVE_SYS_TYPES_H)
CHECK_INCLUDE_FILE(sys/mkdev.h HAVE_SYS_MKDEV_H)
CHECK_INCLUDE_FILE(sys/sysmacros.h HAVE_SYS_SYSMACROS_H)
CHECK_INCLUDE_FILE(string.h HAVE_STRING_H)
CHECK_INCLUDE_FILE(memory.h HAVE_MEMORY_H)
CHECK_INCLUDE_FILE(fcntl.h HAVE_FCNTL_H)
CHECK_INCLUDE_FILE(dirent.h HAVE_DIRENT_H)
CHECK_INCLUDE_FILE(sys/ndir.h HAVE_SYS_NDIR_H)
CHECK_INCLUDE_FILE(ndir.h HAVE_NDIR_H)
CHECK_INCLUDE_FILE(alloca.h HAVE_ALLOCA_H)
CHECK_INCLUDE_FILE(locale.h HAVE_LOCALE_H)
CHECK_INCLUDE_FILE(fcntl.h HAVE_FCNTL_H)
CHECK_INCLUDE_FILE(signal.h HAVE_SIGNAL_H)
CHECK_INCLUDE_FILE(sys/select.h HAVE_SYS_SELECT_H)
CHECK_INCLUDE_FILE(sys/resource.h HAVE_SYS_RESOURCE_H)
CHECK_INCLUDE_FILE(sys/socket.h HAVE_SYS_SOCKET_H)
CHECK_INCLUDE_FILE(sys/un.h HAVE_SYS_UN_H)
CHECK_INCLUDE_FILE(sys/mman.h HAVE_SYS_MMAN_H)
CHECK_INCLUDE_FILE(stdint.h HAVE_STDINT_H)
CHECK_INCLUDE_FILE(errno.h HAVE_ERRNO_H)
CHECK_INCLUDE_FILE(termios.h HAVE_TERMIOS_H)
CHECK_INCLUDE_FILE(getopt.h HAVE_GETOPT_H)
CHECK_INCLUDE_FILE(openssl/sha.h HAVE_OPENSSL_SHA_H)
CHECK_INCLUDE_FILE(openssl/blowfish.h HAVE_OPENSSL_BLOWFISH_H)
CHECK_INCLUDE_FILE(openssl/rand.h HAVE_OPENSSL_RAND_H)
CHECK_INCLUDE_FILE(netinet/in.h HAVE_NETINET_IN_H)

#
# Check whether socklen_t is defined
# (it should be, according to POSIX)
#
SET(CMAKE_EXTRA_INCLUDE_FILES "sys/socket.h")
CHECK_TYPE_SIZE(socklen_t HAVE_SOCKLEN_T)

#
# Check whether we want getopt_long
#
IF(${GETOPT_LONG})
	CHECK_FUNCTION_EXISTS(getopt_long HAS_GETOPT_LONG)
ENDIF()

#
# Check whether we do have AND want X11
#
FIND_PACKAGE(X11)
IF(NOT X11-FOUND OR NOT USE_X11)
	SET(X_DISPLAY_MISSING 1)
ENDIF()

#
# Generate config.h
#
CONFIGURE_FILE(
	${CMAKE_SOURCE_DIR}/cmake-config.h.in
	${CMAKE_BINARY_DIR}/config.h
)

#
# CFLAGS
#
ADD_DEFINITIONS(
	-DHAVE_CONFIG_H
	-Wall
	-Werror
)

#
# OpenSSL APIs are deprecated on OSX
#
IF(APPLE)
	ADD_DEFINITIONS(
		-Wno-deprecated-declarations
	)
ENDIF()

#
# Set include directories
#
INCLUDE_DIRECTORIES(
	${CMAKE_BINARY_DIR}
	${OPENSSL_INCLUDE_DIR}
)

#
# Build executable
#
ADD_EXECUTABLE(
	pwsafe
	pwsafe.cpp
)

#
# Librarie
#
TARGET_LINK_LIBRARIES(
	pwsafe
	${OPENSSL_LIBRARIES}
)

#
# Tests - move .dat files into binary dir
#
FOREACH(datfile test.dat testv2.dat) 
	ADD_CUSTOM_COMMAND(
		OUTPUT "${CMAKE_BINARY_DIR}/${datfile}" 
		COMMAND
			cmake -E copy
				"${CMAKE_SOURCE_DIR}/${datfile}"
			   	"${CMAKE_BINARY_DIR}/${datfile}"
		DEPENDS
			"${CMAKE_SOURCE_DIR}/${datfile}" 
		) 
	LIST(APPEND DATFILES "${CMAKE_BINARY_DIR}/${datfile}") 
ENDFOREACH()
ADD_CUSTOM_TARGET(datfiles ALL DEPENDS ${DATFILES}) 

ENABLE_TESTING()
FOREACH (test read create edit merge)
	ADD_TEST(
		NAME ${test}
		COMMAND ${CMAKE_SOURCE_DIR}/test/${test}
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
	)
ENDFOREACH()
