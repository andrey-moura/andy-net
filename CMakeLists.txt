#Require a minimum version
cmake_minimum_required(VERSION 3.10)

project(andy-net)

set(ANDY_NET_SOURCES
	${CMAKE_CURRENT_LIST_DIR}/src/response.cpp

	${CMAKE_CURRENT_LIST_DIR}/src/asio/http.cpp
	${CMAKE_CURRENT_LIST_DIR}/src/asio/response.cpp
)

add_library(andy-net OBJECT
	${ANDY_NET_SOURCES}
)

find_package(Threads REQUIRED)
# target_link_libraries(andy-net ${CMAKE_THREAD_LIBS_INIT})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
# target_link_libraries(andy-net ${OPENSSL_LIBRARIES})

include_directories(${CMAKE_CURRENT_LIST_DIR}/include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/modules/asio/asio/include)

if(WIN32)
	get_filename_component(OPENSSL_ROOT ${OPENSSL_INCLUDE_DIR} DIRECTORY)
endif()

andy_tests_configure(andy-net)