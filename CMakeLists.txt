#Require a minimum version
cmake_minimum_required(VERSION 3.10)

project(andy-net)

# Check if we are in emscripten
if(EMSCRIPTEN)
else()
	set(ANDY_NET_BACKEND "asio")
endif()

if(ANDY_NET_BACKEND)
	set(ANDY_NET_SOURCES
		${CMAKE_CURRENT_LIST_DIR}/src/response.cpp

		${CMAKE_CURRENT_LIST_DIR}/src/asio/http.cpp
		${CMAKE_CURRENT_LIST_DIR}/src/asio/response.cpp
	)

	add_library(andy-net OBJECT
		${ANDY_NET_SOURCES}
	)
endif()


find_package(Threads REQUIRED)

set(ANDY_NET_LIBRARIES
	${CMAKE_THREAD_LIBS_INIT}
)

find_package(Threads REQUIRED)

# find_package(OpenSSL QUIET)
# include_directories(${OPENSSL_INCLUDE_DIR})

include_directories(${CMAKE_CURRENT_LIST_DIR}/include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/modules/asio/asio/include)

if(WIN32)
	get_filename_component(OPENSSL_ROOT ${OPENSSL_INCLUDE_DIR} DIRECTORY)
endif()

if(ANDY_NET_BACKEND)
	andy_tests_configure(andy-net)
endif()