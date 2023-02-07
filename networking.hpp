#pragma once

#include <memory>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <core.hpp>

class web_connection;
namespace uva
{
    namespace networking
    {
        enum class status_code {
            /* updates here must reflect on s_status_codes */
            ok = 200,
            no_content = 204,
            bad_request = 400,
            unauthorized = 401,
            not_found = 404,
            payload_too_large = 413,
            unsupported_media_type = 415,
            internal_server_error = 500
        };
        enum class content_type {
            application_json,
            text_html,
            text_css
        };
        struct http_message
        {
            http_message() = default;
            http_message(http_message&& other) = default;
            status_code status;
            std::string status_msg;
            std::string version;
            content_type type;
            std::string method;
            std::string query_string;
            std::string url;
            std::string endpoint;
            std::string raw_body;
            var params;
            var headers;

            web_connection* connection;
        public:
            http_message& operator=(http_message&& message) = default;
        };
        enum class run_mode
        {
            async,
            sync
        };
        enum class protocol
        {
            http,
            https,
        };
        using error_code = asio::error_code;
        class basic_socket
        {
        public:
            basic_socket(asio::ip::tcp::socket&& __socket, const protocol& __protocol);
            basic_socket(basic_socket&& __socket);
            basic_socket() = default;
            ~basic_socket();
        protected:
            std::unique_ptr<asio::ssl::stream<asio::ip::tcp::socket>> m_ssl_socket = nullptr;
            std::unique_ptr<asio::ip::tcp::socket> m_socket = nullptr;
            protocol m_protocol;
        public:
            bool is_open() const;
            bool needs_handshake() const;
            size_t available() const;
            size_t available(error_code& ec) const;
            std::string remote_endpoint_string() const;

            error_code server_handshake();
            error_code client_handshake();
            void async_client_handshake(std::function<void(error_code)> completation);
            void async_server_handshake(std::function<void(error_code)> completation);

            error_code connect(const std::string& protocol, const std::string& host);
            void connect_async(const std::string& protocol, const std::string& host, std::function<void(error_code)> completation);

            void close();

            void read_until(std::string& buffer, std::string_view delimiter);
            void async_read_until(asio::streambuf& buffer, std::string_view delimiter, std::function<void(error_code, size_t)> completation);
            void write(std::string_view sv);
            void async_write(std::string_view sv, std::function<void(error_code&)> completation);

            void read_exactly(char* buffer, size_t to_read);
            void read_exactly(std::string& buffer, size_t to_read);
            void async_read_exactly(asio::mutable_buffer buffer, size_t to_read, std::function<void(error_code, size_t)> completation);

            uint8_t read_byte();
        };

        extern std::unique_ptr<asio::io_context> io_context;
        extern std::unique_ptr<asio::io_context::work> work;
        extern std::unique_ptr<asio::ssl::context> ssl_context;

        extern const std::string version;

        void init(const run_mode& mode);
        bool is_initialized();
        void cleanup();

        void async_read_http_request(basic_socket &socket, http_message& request, asio::streambuf& buffer, std::function<void()> completation);
        void async_write_http_response(basic_socket& socket, const std::string& body, const status_code& status, const content_type& content_type, std::function<void (uva::networking::error_code &)> completation);
        http_message read_http_response(basic_socket& socket, asio::streambuf& buffer);
        void write_http_request(basic_socket& socket, std::string host, const std::string &route, const std::map<var, var> &params, const std::map<var, var> &headers, const std::string& body, std::function<void()> on_success, std::function<void(error_code&)> on_error = nullptr);

        void decode_char_from_web(std::string_view& sv, std::string& buffer);
        std::map<var, var> query_to_params(std::string_view query);
    }; // namespace networking
    
}; // namespace uva
