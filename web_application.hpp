#pragma once

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

namespace uva
{
    namespace networking
    {
        namespace web_application
        {
            enum class status_code {
                ok = 200,
                no_content = 204,
                bad_request = 400,
                not_found = 404,

            };

            enum class content_type {
                application_json,
                text_html,
            };
            struct request
            {
                status_code status;
                content_type type;
                std::string body;
                var params;
                var headers;
            };
            struct response
            {
            public:
                status_code status;
                content_type type;
                std::string body;
            public:
                response& operator<<(const uva::json& __body);
                response& operator<<(const status_code& __status);
            };
            extern response current_response;
            void init(int argc, const char **argv);
        };  // namespace web_application
    }; // namespace networking
    
}; // namespace uva

#define respond uva::networking::web_application::current_response << 
#define with_status << 