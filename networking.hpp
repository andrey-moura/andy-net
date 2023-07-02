#pragma once

#include <memory>
#include <deque>

#include <asio.hpp>

#ifdef __UVA_OPENSSL_FOUND__
    #include <asio/ssl.hpp>
#endif

#include <core.hpp>

#define BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_PROTOCOL(__protocol) throw std::runtime_error(std::format("undefined method '{}' for {}", UVA_FUNCTION_NAME, __protocol));
#define BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL() VAR_THROW_UNDEFINED_METHOD_FOR_TYPE(m_protocol)

class web_connection;
namespace uva
{
    namespace networking
    {
        enum class status_code {
            /* updates here must reflect on s_status_codes */
            ok = 200,
            no_content = 204,
            moved = 302,
            bad_request = 400,
            unauthorized = 401,
            not_found = 404,
            payload_too_large = 413,
            unsupported_media_type = 415,
            internal_server_error = 500
        };
        enum class content_type {
            /* updates here must reflect on s_content_types */
            application_json,
            application_javascript,
            image_png,
            image_jpeg,
            text_html,
            text_css,
            video_mp4,
            video_mpd,
            video_m4s,
        };
        const std::string& content_type_to_string(const content_type& status);
        content_type content_type_from_string(const std::string& status);
        struct http_message
        {
            http_message() = default;
            http_message(const http_message& other) = default;
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
            std::string host;
            var params;
            var headers;

            web_connection* connection;
        public:
            http_message& operator=(http_message&& message) = default;
        };
        template<typename T>
        class basic_thread_safe_pipeline_waiter
        {
        private:
            //thread safe
            std::mutex m_deque_mutex;
            //T pipeline
            std::deque<T> m_deque;
            //waiter
            std::condition_variable m_wait_variable;
            std::mutex m_wait_mutex;
        public:
        void push_back(T&& t)
        {
            std::scoped_lock locker(m_deque_mutex);

            m_deque.push_back(std::move(t));

            m_wait_variable.notify_one();
        }
        T pop_front()
        {
            std::scoped_lock locker(m_deque_mutex);

            T& t = m_deque.front();
            T __t = std::move(t);

            m_deque.pop_front();

            return __t;
        }
        T pop_back()
        {
            std::scoped_lock locker(m_deque_mutex);

            T& t = m_deque.back();
            T __t = std::move(t);

            m_deque.pop_back();

            return __t;
        }
        T& front()
        {
            std::scoped_lock locker(m_deque_mutex);

            return m_deque.front();
        }
        void consume_front()
        {
            std::scoped_lock locker(m_deque_mutex);
            m_deque.pop_front();
        }
        void clear()
        {
            std::scoped_lock lock(m_deque_mutex);
            m_deque.clear();
        }

        bool empty()
        {
            std::scoped_lock lock(m_deque_mutex);
            return m_deque.empty();
        }

        size_t size()
        {
            std::scoped_lock lock(m_deque_mutex);
            return m_deque.size();
        }

        void wait()
        {
            while (empty())
            {
                std::unique_lock<std::mutex> ul(m_wait_mutex);
                m_wait_variable.wait(ul);
            }
        }
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
            operator bool();
            basic_socket() = default;
            ~basic_socket();
        protected:
#if __UVA_OPENSSL_FOUND__
            std::unique_ptr<asio::ssl::stream<asio::ip::tcp::socket>> m_ssl_socket = nullptr;
#endif
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
#ifdef __UVA_OPENSSL_FOUND__
        extern std::unique_ptr<asio::ssl::context> ssl_context;
#endif
        extern const std::string version;

        void init(const run_mode& mode);
        bool is_initialized();
        void cleanup();

        void async_read_http_request(basic_socket &socket, http_message& request, asio::streambuf& buffer, std::function<void()> completation);
        void async_write_http_response(basic_socket& socket, const std::string& body, const status_code& status, const content_type& content_type, std::function<void (uva::networking::error_code &)> completation);

        /// @brief Asynchronous write an http request into the socket. 
        /// @param socket The socket to write to.
        /// @param request The request to be written into socket. The request should not be destroyed untill completation is called. The request should not be used after calling this function.
        /// @param on_success Is called on success
        /// @param on_error  Is called on error
        void async_write_http_request(basic_socket& socket, http_message& request, std::function<void()> on_success, std::function<void(error_code&)> on_error = nullptr);
        void async_read_http_response(basic_socket& socket, http_message& response, asio::streambuf& buffer, std::function<void()> completation);

        void decode_char_from_web(std::string_view& sv, std::string& buffer);
        std::map<var, var> query_to_params(std::string_view query);
    }; // namespace networking
    
}; // namespace uva

template <>
struct std::formatter<uva::networking::protocol> : std::formatter<std::string> {
    auto format(uva::networking::protocol protocol, format_context& ctx) {
        switch(protocol)
        {
            case uva::networking::protocol::http:
                return std::format_to(ctx.out(), "{}", "http");
            break;
            case uva::networking::protocol::https:
                return std::format_to(ctx.out(), "{}", "https");
            break;
            default:
                throw std::runtime_error(std::format("invalid value of uva::networking::protocol: {}", (int)protocol));
            break;
        }
    }
};