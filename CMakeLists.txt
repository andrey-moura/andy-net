#Require a minimum version
cmake_minimum_required(VERSION 3.10)

project(uva-networking)

add_library(uva-networking
	${CMAKE_CURRENT_LIST_DIR}/src/web_application.cpp
)

include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories("${CMAKE_CURRENT_LIST_DIR}/include/asio/asio/include")

set(NETWORKING_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})

include("${CMAKE_CURRENT_LIST_DIR}/networking/CMakeLists.txt")

if(WIN32 OR WIN64)
else()
	find_package(OpenSSL REQUIRED)
	include_directories(${OPENSSL_INCLUDE_DIR})
	target_link_libraries(uva-networking ${OPENSSL_LIBRARIES})
endif()

#Tests

#Create tests for parent project
cspec_configure("uva-networking" ${CMAKE_CURRENT_LIST_DIR} "uva-networking")