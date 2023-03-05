#Require a minimum version
cmake_minimum_required(VERSION 3.10)

project(basic-web-client)

add_executable(basic-web-client
	${CMAKE_CURRENT_LIST_DIR}/src/main.cpp
)

target_link_libraries(basic-web-client uva-networking uva-core uva-json uva-console)

if(OpenSSL)
	include_directories(${OPENSSL_INCLUDE_DIR})
	target_link_libraries(basic-web-client ${OPENSSL_LIBRARIES})
endif()

if(WIN32)
	if(OpenSSL)
		get_filename_component(OPENSSL_ROOT ${OPENSSL_INCLUDE_DIR} DIRECTORY)
	endif()
endif()