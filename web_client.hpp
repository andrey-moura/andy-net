#pragma once

#include <string>
#include <sstream>
#include <format.hpp>

#ifdef _WIN32
    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT 0x0A00
    #endif
#endif

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define ASIO_STANDALONE

#include <asio.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ssl.hpp>

#include <core.hpp>
#include <networking.hpp>

namespace uva
{
    namespace networking
    {
        class basic_web_client
        {
        public:
            basic_web_client(std::string __host);
            ~basic_web_client();
        protected:
            std::string m_host;
            std::string m_protocol;
            basic_socket m_socket;
        protected:
            void connect_if_is_not_open();
            void connect_if_is_not_open_async(std::function<void()> success, std::function<void(error_code&)> on_error = nullptr);
        public:
            void get (const std::string& route, std::map<var, var> params, std::map<var, var> headers, std::function<void(http_message)> on_success, std::function<void(error_code&)> on_error = nullptr);
            void post(const std::string& route, std::map<var, var> body,   std::map<var, var> headers, std::function<void(http_message)> on_success, std::function<void(error_code&)> on_error = nullptr);
        public:
            virtual void on_connection_error(const uva::networking::error_code& ec);
        }; // class basic_web_client
        
    }; // namespace networking
    
}; // namespace uva
