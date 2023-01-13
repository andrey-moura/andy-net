#pragma once

#include "networking.hpp"
#include <routing.hpp>
#include <json.hpp>

#define DECLARE_WEB_APPLICATION(...) \
int main(int argc, const char **argv)\
{\
    __VA_ARGS__\
    web_application::init(argc, argv);\
    return 0;\
}\

#define GET(path, action_handler) \
route("GET " path, &action_handler, #action_handler)\

#define POST(path, action_handler) \
route("POST " path, &action_handler, #action_handler)\

namespace uva
{
    namespace networking
    {
        http_message& operator<<(http_message& http_message, const uva::json& __body);
        http_message& operator<<(http_message& http_message, const status_code& __status);
        namespace web_application
        {
            extern http_message current_response;
            extern std::filesystem::path app_dir;
            void expose_function(std::string name, std::function<std::string(var)> function);
            void init(int argc, const char **argv);

            struct basic_html_template
            {
            public:
                basic_html_template(std::string &&__file_name, std::map<var,var> &&__locals, const std::string& __controller);
                std::string controller;
                std::string file_name;
                var locals;
            };
            struct basic_css_file
            {
                std::string name;
                basic_css_file(const std::string& __file_name)
                    : name(__file_name)
                {

                }
            };
        };  // namespace web_application
        http_message& operator<<(http_message& http_message, const web_application::basic_html_template& __template);
        http_message& operator<<(http_message& http_message, const web_application::basic_css_file& css);
    }; // namespace networking
    
}; // namespace uva

#define respond uva::networking::web_application::current_response << 
#define html_template(file_name, ...) basic_html_template(file_name, __VA_ARGS__, name)
#define css_file(file_name) basic_css_file(file_name)
#define with_status << 