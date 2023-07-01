function(add_web_app name)

    message(STATUS "Add web app for folder ${CMAKE_CURRENT_LIST_DIR}")

    file(GLOB_RECURSE source_files CONFIGURE_DEPENDS 
        "${CMAKE_CURRENT_LIST_DIR}/include/controllers/*_controller.hpp"
        "${CMAKE_CURRENT_LIST_DIR}/src/controllers/*_controller.cpp"

        "${CMAKE_CURRENT_LIST_DIR}/include/helpers/*_helper.hpp"
        "${CMAKE_CURRENT_LIST_DIR}/src/helpers/*_helper.cpp"

        "${CMAKE_CURRENT_LIST_DIR}/src/migrations/*_migration.cpp"

        "${CMAKE_CURRENT_LIST_DIR}/include/models/*.hpp"
        "${CMAKE_CURRENT_LIST_DIR}/src/models/*.cpp"

        "${CMAKE_CURRENT_LIST_DIR}/include/jobs/*.hpp"
        "${CMAKE_CURRENT_LIST_DIR}/src/jobs/*.cpp"
    )

    SET(source_files
        ${source_files}
        "${CMAKE_CURRENT_LIST_DIR}/config/routes.cpp")

    include_directories("${CMAKE_CURRENT_LIST_DIR}/include/controllers")
    include_directories("${CMAKE_CURRENT_LIST_DIR}/include/helpers")
    include_directories("${CMAKE_CURRENT_LIST_DIR}/include/models")
    include_directories("${CMAKE_CURRENT_LIST_DIR}/include/jobs")
    
    if(NOT source_files)
        message(STATUS "The web app ${name} won't be add because there is no source files for the target.")
    else()
        add_executable(
            # The name of your game
            ${name}
            
            ${source_files}
        )
    endif()

    if (TARGET uva-job)
        file(GLOB_RECURSE jobs_files CONFIGURE_DEPENDS 
            "${CMAKE_CURRENT_LIST_DIR}/src/jobs/*.cpp"
        )

        foreach (job_file IN LISTS jobs_files)
            get_filename_component(job_name ${job_file} NAME_WLE)

            string(REPLACE "_" "-"   job_executable ${job_name})

            message(STATUS "Found job: ${job_name} (${job_executable})")

            add_executable(${job_executable} ${job_file})
            target_link_libraries(${job_executable} uva-job uva-console uva-json)
            target_compile_definitions(${job_executable} PUBLIC -D__UVA_JOB_COMPILATION__=1)

            add_dependencies(${name} ${job_executable})
        endforeach()

        target_link_libraries(${name} uva-job)
    else()
        message(STATUS "Job will be ignored because uva-job is not available")
    endif()

    if (TARGET uva-database)
        target_link_libraries(${name} uva-database)
    endif()
    
    target_compile_definitions(${name} PUBLIC -DAPP_ROOT="${CMAKE_CURRENT_LIST_DIR}")

    if(WIN32)
        target_link_options(${name} PUBLIC /SAFESEH:NO)
    endif()

    target_link_libraries(${name} uva-json uva-networking)
    
endfunction(add_web_app)