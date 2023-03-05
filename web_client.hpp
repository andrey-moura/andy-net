#pragma once

#include <string>
#include <sstream>
#include <format.hpp>
#include <deque>
#include <deque>

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

#ifdef __UVA_OPENSSL_FOUND__
    #include <asio/ssl.hpp>
#endif
#include <thread>

#include <core.hpp>
#include <networking.hpp>

namespace uva
{
    namespace networking
    {
        struct web_client_request
        {
            std::function<void(http_message m)> success;
            std::function<void(error_code m)> error;
            http_message request;
        };
        using web_client_request_pipeline = uva::networking::basic_thread_safe_pipeline_waiter<web_client_request>;
        class basic_web_client
        {
        public:
            basic_web_client(std::string __host);
            ~basic_web_client();
        protected:
            std::string m_host;
            std::string m_protocol;
            basic_socket m_socket;

            asio::streambuf m_buffer;
            
            std::mutex m_mutex;
            web_client_request_pipeline m_requests_pipeline;

            std::unique_ptr<std::thread> m_pipeline_executer;

            http_message m_response_buffer;
        protected:
            void connect_if_is_not_open();
            void connect_if_is_not_open_async(std::function<void()> success, std::function<void(error_code)> on_error = nullptr);
            void enqueue_request(http_message __request, std::function<void(http_message)> __success, std::function<void(error_code)> __error = nullptr);
        private:
            void write_front_request();
        public:
            void get (const std::string& route, std::map<var, var> params, std::map<var, var> headers, std::function<void(http_message)> on_success, std::function<void(error_code)> on_error = nullptr);
            void post(const std::string& route, std::map<var, var> body,   std::map<var, var> headers, std::function<void(http_message)> on_success, std::function<void(error_code)> on_error = nullptr);
            void post(const std::string& route, std::string body, content_type type, std::map<var, var> headers, std::function<void(http_message)> on_success, std::function<void(error_code)> on_error = nullptr);
        public:
            virtual void on_connection_error(const uva::networking::error_code& ec);
        }; // class basic_web_client
        
    }; // namespace networking
    
}; // namespace uva
