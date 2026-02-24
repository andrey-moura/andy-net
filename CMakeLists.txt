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

	find_package(Threads REQUIRED)

	target_link_libraries(andy-net PUBLIC ${CMAKE_DL_LIBS} Threads::Threads)
endif()

set(ANDY_NET_LIBRARIES
	${CMAKE_THREAD_LIBS_INIT}
)

# find_package(OpenSSL QUIET)
# include_directories(${OPENSSL_INCLUDE_DIR})

include_directories(${CMAKE_CURRENT_LIST_DIR}/include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/modules/asio/asio/include)

if(WIN32)
	get_filename_component(OPENSSL_ROOT ${OPENSSL_INCLUDE_DIR} DIRECTORY)
    target_link_libraries(andy-net PUBLIC ws2_32)
endif()

if(ANDY_NET_BACKEND)
	andy_tests_configure(andy-net)
endif()