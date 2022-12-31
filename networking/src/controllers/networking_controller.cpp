#include <networking_controller.hpp>

#include <iostream>

#include <console.hpp>
#include <file.hpp>

void networking_controller::new_project()
{
    if(!params.size()) {
        log_error("error: missing argument 'project name'");
        return;
    } 

    var project_name = params[0];

    std::filesystem::create_directories(project_name.to_s());

    std::filesystem::path project_root = std::filesystem::absolute(project_name.to_s());
    std::filesystem::create_directories(project_root / "src/controllers");
    std::filesystem::create_directories(project_root / "include/controllers");
    std::filesystem::create_directories(project_root / "config");

    static std::string routes_template =
R"~~~(#include <iostream>
#include <web_application.hpp>

using namespace uva;
using namespace routing;
using namespace networking;

DECLARE_WEB_APPLICATION(
    //Declare your routes above. As good practice, keep then ordered by controler.
    //You can have C++ code here, perfect for init other libraries.
)
)~~~";

    uva::file::write_all_text(project_root / "config" / "routes.cpp", routes_template);

    static std::string cmake_template =
    std::format(
R"~~~(#Require a minimum version
cmake_minimum_required(VERSION 3.10)

project({})

include(${{NETWORKING_ROOT_DIR}}/networking.cmake)

add_web_app({})

target_link_libraries({} uva-networking uva-console uva-core uva-routing)

add_custom_command(TARGET {} 
                   POST_BUILD
                   COMMAND ${{CMAKE_COMMAND}} -E copy $<TARGET_FILE:{}> ${{CMAKE_SOURCE_DIR}}/bin/{})

)~~~", project_name.downcase(), project_name.downcase(), project_name.downcase(), project_name.downcase(), project_name.downcase(), project_name.downcase());

    uva::file::write_all_text(project_root / "CMakeLists.txt", cmake_template);

    if(params.key("--git") != null) {
        std::cout << "Initializing git repository..." << std::endl;
    }
}
