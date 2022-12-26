#Require a minimum version
cmake_minimum_required(VERSION 3.10)

project(uva-networking)

add_library(uva-networking
	${CMAKE_CURRENT_LIST_DIR}/src/networking.cpp
)

include_directories(${CMAKE_CURRENT_LIST_DIR})

#Tests

#Create tests for parent project
cspec_configure("uva-networking" ${CMAKE_CURRENT_LIST_DIR} "uva-networking")