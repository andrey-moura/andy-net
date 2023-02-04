#pragma once

#include <memory>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <core.hpp>

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
            status_code status;
            std::string status_msg;
            std::string version;
            content_type type;
            std::string method;
            std::string query_string;
            std::string url;
            std::string endpoint;
            var body;
            var params;
            var headers;
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
            basic_socket() = default;
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

            error_code connect(const std::string& protocol, const std::string& host);
            void connect_async(const std::string& protocol, const std::string& host, std::function<void(error_code)> completation);

            void close();

            void read_until(std::string& buffer, std::string_view delimiter);
            void read_until_async(std::string& buffer, std::string_view delimiter, std::function<void(error_code&)> completation);
            void write(std::string_view sv);
            void write_async(std::string_view sv, std::function<void(error_code&)> completation);

            void read_exactly(char* buffer, size_t to_read);
            void read_exactly(std::string& buffer, size_t to_read);

            uint8_t read_byte();
        };

        extern std::unique_ptr<asio::io_context> io_context;
        extern std::unique_ptr<asio::io_context::work> work;
        extern std::unique_ptr<asio::ssl::context> ssl_context;

        extern const std::string version;

        void init(const run_mode& mode);
        bool is_initialized();
        void cleanup();

        http_message read_http_request(basic_socket& socket);
        http_message read_http_response(basic_socket& socket);
        void write_http_response(basic_socket& socket, const std::string& body, const status_code& status, const content_type& content_type);
        void write_http_request(basic_socket& socket, std::string host, const std::string &route, const std::map<var, var> &params, const std::map<var, var> &headers, const std::string& body, std::function<void()> on_success, std::function<void(error_code&)> on_error = nullptr);

        void decode_char_from_web(std::string_view& sv, std::string& buffer);
        std::map<var, var> query_to_params(std::string_view query);
    }; // namespace networking
    
}; // namespace uva
