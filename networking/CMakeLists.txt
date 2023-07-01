
#Require a minimum version
cmake_minimum_required(VERSION 3.10)

project(networking)

add_console_app(networking)

target_link_libraries(networking uva-networking uva-console uva-core uva-routing uva-file)

if(WIN32)
    set(BIN_FILE "networking.exe")
else()
    set(BIN_FILE "networking")
endif()

add_custom_command(TARGET networking 
                   POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:networking> ${CMAKE_SOURCE_DIR}/bin/${BIN_FILE})

