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

include("${CMAKE_CURRENT_LIST_DIR}/networking/CMakeLists.txt")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(uva-networking ${OPENSSL_LIBRARIES} uva-binary)

if(WIN32)
	get_filename_component(OPENSSL_ROOT ${OPENSSL_INCLUDE_DIR} DIRECTORY)
endif()

#Tests

#Create tests for parent project
cspec_configure("uva-networking" ${CMAKE_CURRENT_LIST_DIR} "uva-networking")