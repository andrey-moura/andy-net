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
        namespace web_application
        {
            class basic_web_controller : public uva::routing::basic_controller, public std::enable_shared_from_this<basic_web_controller>
            {
            public:
                http_message request;
                var cookies;
            };
            extern http_message current_response;
            extern std::filesystem::path app_dir;
            void expose_function(std::string name, std::function<std::string(var)> function);
            void init(int argc, const char **argv);
            void add_route();
            struct basic_html_template
            {
            public:
                basic_html_template(std::string &&__file_name, std::map<var,var> &&__locals, const std::string& __controller);
                basic_html_template(std::string &&__file_name, std::shared_ptr<basic_web_controller> __controller);
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
            // class web_server_connection : public http_connection_participant
            // {
            
            // };
        };  // namespace web_application

        http_message& operator+=(http_message& http_message, std::map<var,var>&& __body);
        http_message& operator<<(http_message& http_message, const status_code& __status);
        http_message& operator<<(http_message& http_message, const web_application::basic_html_template& __template);
        http_message& operator<<(http_message& http_message, const web_application::basic_css_file& css);
        http_message& redirect_to(const std::string& url, const var& params = null);
    }; // namespace networking
    
}; // namespace uva

#define respond uva::networking::web_application::current_response
#define JSON +=
#define html_template(file_name) << basic_html_template(file_name, shared_from_this())
#define html_template_for_controller(controller_name, file_name, ...) << basic_html_template(file_name, __VA_ARGS__, controller_name)
#define css_file(file_name) << basic_css_file(file_name)
#define with_status ; uva::networking::web_application::current_response <<