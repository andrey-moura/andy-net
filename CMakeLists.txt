#Require a minimum version
cmake_minimum_required(VERSION 3.10)

project(uva-networking)

add_library(uva-networking
	${CMAKE_CURRENT_LIST_DIR}/src/web_application.cpp
	${CMAKE_CURRENT_LIST_DIR}/src/web_client.cpp
	${CMAKE_CURRENT_LIST_DIR}/src/networking.cpp
)

include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories("${CMAKE_CURRENT_LIST_DIR}/include/asio/asio/include")

set(NETWORKING_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})
include(${NETWORKING_ROOT_DIR}/networking.cmake)

# tools
include("${CMAKE_CURRENT_LIST_DIR}/networking/CMakeLists.txt")

# samples
include("${CMAKE_CURRENT_LIST_DIR}/samples/basic_web_client/CMakeLists.txt")

target_link_libraries(uva-networking uva-binary)

if(OpenSSL)
	include_directories(${OPENSSL_INCLUDE_DIR})
	target_link_libraries(uva-networking ${OPENSSL_LIBRARIES})
endif()

if(WIN32)
	get_filename_component(OPENSSL_ROOT ${OPENSSL_INCLUDE_DIR} DIRECTORY)
endif()

#Tests

#Create tests for parent project
cspec_configure("uva-networking" ${CMAKE_CURRENT_LIST_DIR} "uva-networking")