#pragma once

#define DECLARE_WEB_APPLICATION(...) \
int main(int argc, const char **argv)\
{\
    __VA_ARGS__\
    web_application::init(argc, argv);\
    return 0;\
}\

namespace uva
{
    namespace networking
    {
        namespace web_application
        {
            void init(int argc, const char **argv);
        };  // namespace web_application
    }; // namespace networking
    
}; // namespace uva
