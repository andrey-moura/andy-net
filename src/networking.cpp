#include <networking.hpp>

#include <iostream>

#include <console.hpp>
#include <json.hpp>
#include <binary.hpp>

using namespace uva;
using namespace networking;
using namespace console;

//STATIC PUBLIC VARIABLES
std::unique_ptr<asio::io_context> uva::networking::io_context;
std::unique_ptr<asio::io_context::work> uva::networking::work;
#ifdef __UVA_OPENSSL_FOUND__
std::unique_ptr<asio::ssl::context> uva::networking::ssl_context;
#endif
const std::string uva::networking::version = "1.0.0";

//STATIC PRIVATE VARIABLES
std::unique_ptr<std::thread> work_thread;
std::unique_ptr<asio::ip::tcp::resolver> resolver;

void asio_thread_loop()
{
    std::cout << "Running ASIO..." << std::endl;
    try {
        io_context->run();
    } catch(std::exception& e)
    {
        log_error("Exception caught at ASIO thread: {}", e.what());
        asio_thread_loop();
    }
    catch(...)
    {
        log_error("Unknown exception caught at ASIO thread.");
        asio_thread_loop();
    }
    std::cout << "Exiting ASIO thread" << std::endl; 
}

void uva::networking::init(const run_mode &mode)
{
    io_context = std::make_unique<asio::io_context>();
    
    switch (mode)
    {
        case uva::networking::run_mode::async: {
            work = std::make_unique<asio::io_context::work>(*io_context);
            work_thread = std::make_unique<std::thread>(&asio_thread_loop);
        }
        break;
    
    default:
        throw std::runtime_error("undefined value for rum_mode in init");
        break;
    }

#ifdef __UVA_OPENSSL_FOUND__
    ssl_context = std::make_unique<asio::ssl::context>(asio::ssl::context::sslv23);

    ssl_context->set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 | asio::ssl::context::single_dh_use);

    ssl_context->set_password_callback([](size_t, asio::ssl::context::password_purpose){ return "teste"; });

    ssl_context->use_certificate_chain_file("server.crt");
    ssl_context->use_private_key_file("server.key", asio::ssl::context::pem);
    ssl_context->use_tmp_dh_file("dh2048.pem");
#endif

    resolver = std::make_unique<asio::ip::tcp::resolver>(*io_context);
}

bool uva::networking::is_initialized()
{
    return io_context ? true : false;
}

void uva::networking::cleanup()
{
    io_context->stop();

    if(work_thread && work_thread->joinable())
    {
        work_thread->join();
    }

    work.reset();
    io_context.reset();
#ifdef __UVA_OPENSSL_FOUND__
    ssl_context.reset();
#endif
    work_thread.reset();
}

static std::map<status_code, std::string> s_status_codes
{
    { status_code::ok, "OK" },
    { status_code::created, "Created" },
    { status_code::accepted, "Accepted" },
    { status_code::no_content, "No Content" },
    { status_code::moved_permanently, "Moved Permanently" },
    { status_code::found, "Found" },
    { status_code::see_other, "See Other" },
    { status_code::not_modified, "Not Modified" },
    { status_code::bad_request, "Bad Request" },
    { status_code::unauthorized, "Unauthorized" },
    { status_code::forbidden, "Forbidden" },
    { status_code::not_found, "Not Found" },
    { status_code::method_not_allowed, "Method Not Allowed" },
    { status_code::request_timeout, "Request Timeout" },
    { status_code::conflict, "Conflict" },
    { status_code::gone, "Gone" },
    { status_code::length_required, "Length Required" },
    { status_code::precondition_failed, "Precondition Failed" },
    { status_code::payload_too_large, "Payload Too Large" },
    { status_code::unsupported_media_type, "Unsupported Media Type" },
    { status_code::internal_server_error, "Internal Server Error" },
    { status_code::not_implemented, "Not Implemented" },
    { status_code::bad_gateway, "Bad Gateway" },
    { status_code::service_unavailable, "Service Unavailable" },
    { status_code::gateway_timeout, "Gateway Timeout" }
};

static std::map<content_type, std::string> s_content_types
{
    { content_type::text_html,              "text/html" },
    { content_type::image_jpeg,             "image/jpeg" },
    { content_type::image_png,              "image/png" },
    { content_type::text_css,               "text/css" },
    { content_type::application_json,       "application/json" },
    { content_type::application_javascript, "application/javascript" },
    { content_type::video_mp4,              "video/mp4" },
    { content_type::video_m4s,              "video/m4s" },
    { content_type::image_gif,              "image/gif" },
    { content_type::image_gif,              "image/gif" },
    { content_type::image_svg_xml,          "image/svg+xml" },
};

static std::string s_server_version = "0.0.1";

const std::string& status_code_to_string(const status_code& status) {
    auto it = s_status_codes.find(status);

    if (it == s_status_codes.end()) {
        throw std::runtime_error(std::format("error: {} is not a valid status_code code.", (size_t)status));
    }

    return it->second;
}

const std::string& uva::networking::content_type_to_string(const content_type& type) {
    auto it = s_content_types.find(type);

    if (it == s_content_types.end()) {
        throw std::runtime_error(std::format("error: {} is not a valid content_type code.", (size_t)type));
    }

    return it->second;
}

content_type uva::networking::content_type_from_string(const std::string &content_type)
{
    std::string actual_content_type;
    actual_content_type.reserve(actual_content_type.size());

    const char* str = content_type.c_str();
    while(*str) {
        if(*str == ';') {
            break;
        }

        actual_content_type.push_back(*str);
        ++str;
    }

    for(auto & content : s_content_types) {
        if(content.second == actual_content_type) {
            return content.first;
        }
    }

    throw std::runtime_error(std::format("error: {} is not a valid content_type.", actual_content_type));
}

const char* standard_time_format()
{
    return "%a, %d %b %Y %X GMT";
}

std::string time_to_string(const char* format, const time_t& time)
{
    std::tm* tm = std::gmtime(&time);

    char buffer[100];

    std::strftime(buffer, 100, standard_time_format(), tm);
    std::string now_str = buffer;

    return now_str;
}

std::string time_to_standard_string(const time_t& time)
{
    const char* format = standard_time_format();
    return time_to_string(format, time);
}

std::string time_now_to_string(const char* format)
{
    time_t now = time(nullptr);
    return time_to_string(format, now);
}

std::string time_now_to_standard_string()
{
    return time_now_to_string(standard_time_format());
}

std::map<var, var> parse_headers(std::istream &headers_stream)
{
    std::map<var, var> headers;
    std::string header;

    while (std::getline(headers_stream, header) && header != "\r")
    {
        if (!header.size()) continue;
        size_t separator = header.find(':');
        if (separator == std::string::npos) continue;
        std::string h = header.substr(0, separator);
        header.erase(0, h.size() + 1);
        while (header.size() && header.starts_with(' ') || header.starts_with('\t') || header.starts_with("'") || header.starts_with("\"")) {
            header.erase(0, 1);
        }
        while (header.size() && header.ends_with(' ') || header.ends_with('\t') || header.ends_with("'") || header.ends_with("\"") || header.ends_with("\r") || header.ends_with("\n")) {
            header.erase(header.size() - 1, 1);
        }

        headers[h] = header;
    }

    return headers;
}

// void chunked_loop(basic_socket &socket, asio::streambuf& buffer)
// {
//     size_t to_read;
//     std::string line;
//     //\r\n NUMBER \r\n
//     line.reserve(2 + 8 + 2);
//     socket.read_until(line, );

//     socket.async_read_until(buffer, "\r\n", [&buffer](uva::networking::error_code ec, size_t len){
//         if(!ec) {
//             buffer.
//         }
//     });
// }

// void chunked_loop(basic_socket &socket, asio::streambuf& buffer, std::istream& streambuf, std::string& body)
// {
//     std::string line;
//     std::getline(stream, line);

//     while(line.ends_with('\n') || line.ends_with('\r')) line.pop_back();

//     size_t chunk_size = std::stoi(line, nullptr, 16);

//     if(chunk_size) {
//         if(buffer.data().size() < chunk_size) {
//             size_t remaining = chunk_size - buffer.data().size();

//             socket.async_read_exactly(buffer, remaining, [&socket, &buffer, &body, &streambuf](error_code, size_t) {
//                 streambuf.read()
//             });
//         }
//         size_t old_size = body.size();
//         body.resize(old_size + chunk_size);

//         chunked_loop(basic_socket &socket, asio::streambuf& buffer, std::string& body);
//     } else {
//         std::getline(stream, line);
//         completation(error_code(), body.size());

//         break;
//     }
// }

void async_read_body(basic_socket &socket, asio::streambuf& buffer, size_t already_read, std::string& body, const var& headers, std::function<void(error_code, size_t)> completation)
{
    var transfer_encoding = headers.fetch("Transfer-Encoding");

    if (transfer_encoding != null) {
        if (transfer_encoding != "chunked") {
            throw std::runtime_error(std::format("Transfer-Encoding '{}' currently are not supported.", transfer_encoding));
        }

        socket.async_read_until(buffer, "\r\n", [&, completation](const error_code& ec, size_t bytes_transferred) {
            if (!ec) {
                std::istream response_stream(&buffer);
                std::string chunk_size_str;
                std::getline(response_stream, chunk_size_str, '\r');
                response_stream.get();  // Consume the '\n' after the chunk size.
                size_t chunk_size = std::stoul(chunk_size_str, nullptr, 16);

                if (chunk_size == 0) {
                    // Last chunk; body fully read.
                    completation(ec, already_read);
                } else {
                    // Read the chunk data.
                    socket.async_read_exactly(buffer, chunk_size + 2,  // Include '\r\n'.
                        [&, chunk_size, completation](const error_code& ec, size_t bytes_transferred) {
                            if (!ec) {
                                std::istream chunk_stream(&buffer);
                                std::string chunk_data(chunk_size, '\0');
                                chunk_stream.read(&chunk_data[0], chunk_size);
                                body += chunk_data;

                                // Discard '\r\n'.
                                char crlf[2];
                                chunk_stream.read(crlf, 2);

                                async_read_body(socket, buffer, already_read + chunk_size, body, headers, completation);
                            } else {
                                completation(ec, already_read);
                            }
                        });
                }
            } else {
                completation(ec, already_read);
            }
        });
    }
    else {
        var content_lenght = headers.fetch("Content-Length");

        if (content_lenght == null) {
            completation(error_code(), 0);
        } else {
            size_t body_size = content_lenght.to_i();
            body.resize(body_size);

            size_t available_size = buffer.data().size();
            size_t remaining_size = body_size - available_size;

            if(available_size) {
                std::istream stream(&buffer);
                stream.read(body.data(), available_size);
            }

            if(remaining_size) {
                socket.async_read_exactly(asio::buffer(body.data()+available_size, remaining_size), remaining_size, completation);
            } else {
                completation(error_code(), body_size);
            }
        }
    }
}

void uva::networking::async_read_http_request(basic_socket &socket, http_message& request, asio::streambuf& buffer, std::function<void()> completation)
{
    socket.async_read_until(buffer, "\r\n\r\n", [&socket, &buffer, &request, completation](uva::networking::error_code ec, size_t s){
        if (s) {
            std::istream request_stream(&buffer);
            std::string url;

            request_stream >> request.method;
            request_stream >> url;
            request_stream >> request.version;

            std::string_view url_view;
            url_view = url;

            request.url.reserve(url.size());
            
            while(url_view.size()) {
                char c = url_view.front();
                url_view.remove_prefix(1);
                if(c == '?') {
                    break;
                }
                else {
                    request.url.push_back(c);
                }
            }

            if(url_view.size()) {
                request.params = query_to_params(url_view);
            } else {
                request.params = empty_map;
            }

            std::string endpoint = socket.remote_endpoint_string();
            request.endpoint = endpoint;

            static std::string version_start = "HTTP/";

            if (!request.version.starts_with(version_start)) {
                throw std::runtime_error(std::format("Unrecognized HTTP version: {} ({} {})", request.version, request.method, request.url));
            }

            std::string empty_line;
            std::getline(request_stream, empty_line);
            request.headers = parse_headers(request_stream);

            async_read_body(socket, buffer, s, request.raw_body, request.headers, [&request, completation](error_code ec, size_t) {
                if(request.method == "POST") {

                    std::string content_type = request.headers["Content-Type"];
                    if(content_type.starts_with("application/json")) {
                        request.params = json::decode(request.raw_body);
                    } else if(content_type.starts_with("application/x-www-form-urlencoded")) {
                        request.params = query_to_params(request.raw_body);
                    }
                }

                completation();
            });
        }
    });
}

void uva::networking::async_write_http_request(basic_socket& socket, http_message& request, std::function<void()> on_success, std::function<void(error_code&)> on_error)
{
    std::string buffer;
    buffer.reserve(512+request.raw_body.size()+(50*request.params.size())+(50*request.headers.size()));

    buffer += request.method;
    buffer.push_back(' ');

    if(!request.url.starts_with('/')) {
        buffer += "/";
    }

    buffer += request.url;

    if (!request.params.is_null() && !request.params.empty()) {
        buffer.push_back('?');

#if __UVA_DEBUG_LEVEL__ > 0
        if(request.params.type != var::var_type::map)
        {
            throw std::runtime_error(std::format("error: request params invalid type '{}'", request.params.type));
        }
#endif
        for (const auto& param : request.params.as<var::map>())
        {
            param.first.append_to(buffer);
            buffer.push_back('=');
            param.second.append_to(buffer);
            buffer.push_back('&');
        }

        buffer.pop_back();
    }
    
    buffer += " HTTP/1.1\r\n";

    buffer += "Host: ";
    buffer += request.host;
    buffer += "\r\n";
    buffer += "User-Agent: uva::networking/";
    buffer += version;
    buffer += "\r\n";
    buffer += "Accept: */*\r\n";
    buffer += "Content-Type: ";
    buffer += content_type_to_string(request.type);
    buffer += "\r\n";
    buffer += "Connection: keep-alive\r\n";

    if(request.headers.is_a<var::map>()) {
        for(const auto& header : request.headers.as<var::map>())
        {
            header.first.append_to(buffer);
            buffer += ": ";
            header.second.append_to(buffer);
            buffer += "\r\n";
        }
    }

    if(request.raw_body.size()) {
        buffer += "Content-Length: ";
        buffer += std::to_string(request.raw_body.size());
        buffer += "\r\n\r\n";
    } else {
        buffer += "\r\n";
    }

#if __UVA_DEBUG_LEVEL__ >= 2
    log(buffer);
#endif

    socket.async_write(buffer, [on_success, on_error, &request, &socket](error_code& ec) {
        if(ec) {
            if(on_error) {
                on_error(ec);
            }
        } else {
            if(request.raw_body.size()) {
                socket.async_write(request.raw_body, [on_success, on_error](error_code& ec) {
                    if(ec) {
                        if(on_error) {
                            on_error(ec);
                        }
                    } else {
                        on_success();
                    };
                });
            }
            else {
                on_success();
            };
        }
    });
}

void uva::networking::async_read_http_response(basic_socket& socket, http_message& response, asio::streambuf& buffer, std::function<void()> completation)
{
    socket.async_read_until(buffer, "\r\n\r\n", [&buffer, &response, &socket, completation](uva::networking::error_code ec, size_t s) {
        if(!ec) {
            std::istream request_stream(&buffer);

            request_stream >> response.version;

            char version_start[] = "HTTP/";

            if(!response.version.starts_with(version_start)) {
                throw std::runtime_error("invalid response: invalid http response (1)");
            }

            response.version = response.version.substr(sizeof(version_start)-1);

            int status;

            request_stream >> status;
            std::getline(request_stream, response.status_msg);

            if(response.status_msg.ends_with('\r')) {
                response.status_msg.pop_back();
            }

            response.status = (status_code)status;
            response.headers = parse_headers(request_stream);
            response.params = var::map();

            response.type = content_type_from_string(response.headers.fetch("Content-Type"));

            async_read_body(socket, buffer, s, response.raw_body, response.headers, [&response, completation](uva::networking::error_code ec, size_t){
                var content_type = response.headers.fetch("Content-Type");

                if(content_type == "application/json") {
                    response.params = uva::json::decode(response.raw_body);
                }

                if(completation) {
                    completation();
                }
            });
        }
    });
}

void uva::networking::async_write_http_response(basic_socket &socket, http_message& response, std::function<void (uva::networking::error_code &)> completation)
{
    std::string status_code_string = std::to_string((size_t)response.status);
    std::string status_string = status_code_to_string(response.status);
    std::string date_string = time_now_to_standard_string();
    std::string content_type_string = content_type_to_string(response.type);
    std::string body_length_string = std::to_string(response.raw_body.size());

    std::string header = "HTTP/1.1 " + status_code_string + " " + status_string;
    header.reserve(1024);

    if(response.headers.is_null()) {
        response.headers = var::map();
    }

    auto& headers = response.headers.as<var::map>();

    headers["Server"] = "uva::net/" + s_server_version;
    headers["Date"] = date_string;
    headers["Content-Type"] = content_type_string;
    headers["Content-Length"] = body_length_string;

    for(auto& pair : headers)
    {
        header.append("\r\n");
        header.append(pair.first);
        header.push_back(':');
        header.push_back(' ');
        header.append(pair.second);
    }

    header.append("\r\n\r\n");

    size_t bytes_written = 0;

    socket.async_write(header, [&response, &socket, completation](uva::networking::error_code ec) {
        socket.async_write(response.raw_body, [completation](uva::networking::error_code ec) {
            completation(ec);
        });
    });
}

void uva::networking::decode_char_from_web(std::string_view& sv, std::string &buffer)
{
    if(sv.starts_with('%')) {
        sv.remove_prefix(1);

        if(sv.size() <= 1) {
            if(!uva::binary::is_hex_digit(sv.front())) {
                throw std::runtime_error("invalid character following hex scape sequence");
            }

            buffer.push_back(uva::binary::nibble_from_hex_string(sv.front()));
            sv.remove_prefix(1);
        } else if(sv.size() >= 2) {
            if(uva::binary::is_hex_digit(sv[0])) {
                if(uva::binary::is_hex_digit(sv[1])) {
                    buffer.push_back(uva::binary::byte_from_hex_string(sv.data()));
                    sv.remove_prefix(2);
                } else {
                    buffer.push_back(uva::binary::nibble_from_hex_string(sv.front()));
                    sv.remove_prefix(1);
                }
            } else
            {
                throw std::runtime_error("invalid character following hex scape sequence");
            }

        }
    } else {
        buffer.push_back(sv.front());
        sv.remove_prefix(1);
    }
}

std::map<var, var> uva::networking::query_to_params(std::string_view query, bool escape_plus)
{
    std::map<var, var> params;

    std::string current_param_key;
    std::string current_param_value;

    while(query.size()) {

        while(query.size())
        {
            if(query.starts_with('=')) {
                query.remove_prefix(1);
                break;
            } else if(escape_plus && query.starts_with('+')) {
                current_param_key.push_back(' ');
            } else {
                decode_char_from_web(query, current_param_key);
            }
        }

        while(query.size())
        {
            if(query.starts_with('&')) {
                query.remove_prefix(1);
                break;
            } else if(escape_plus && query.starts_with('+')) {
                current_param_value.push_back(' ');
            } else {
                decode_char_from_web(query, current_param_value);
            }
        }

        params.insert({std::move(current_param_key), std::move(current_param_value)});

        current_param_key.clear();
        current_param_key.reserve(20);

        current_param_value.clear();
        current_param_value.reserve(20);
    }

    return params;
}

uva::networking::basic_socket::basic_socket(asio::ip::tcp::socket &&__socket, const protocol &__protocol)
    : m_protocol(__protocol)
{
    switch(m_protocol)
    {
        case protocol::http:
            m_socket = std::make_unique<asio::ip::tcp::socket>(std::forward<asio::ip::tcp::socket&&>(__socket));
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            m_ssl_socket = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket>>(std::forward<asio::ip::tcp::socket&&>(__socket), *ssl_context);
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

uva::networking::basic_socket::basic_socket()
    : m_protocol((protocol)3)
{
}

uva::networking::basic_socket::basic_socket(basic_socket &&__socket)
    :
#ifdef __UVA_OPENSSL_FOUND__
    m_ssl_socket(std::move(__socket.m_ssl_socket)),
#endif
    m_socket(std::move(__socket.m_socket)), m_protocol(__socket.m_protocol)
{

}

uva::networking::basic_socket::operator bool()
{
    switch(m_protocol)
    {
        case protocol::http:
            return m_socket ? true : false;
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            return m_ssl_socket ? true : false;
        break;
#endif
        case (protocol)3:
            return false;
        break;
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

uva::networking::basic_socket::~basic_socket()
{
    switch(m_protocol)
    {
        case protocol::http:
            if(m_socket) {
                if(m_socket->is_open()) {
                    m_socket->close();
                }
            }
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            if(m_ssl_socket) {
                if(m_ssl_socket->lowest_layer().is_open()) {
                    m_ssl_socket->lowest_layer().close();
                }
            }
        break;
#endif
    }
}

bool uva::networking::basic_socket::is_open() const
{
    if(
#ifdef __UVA_OPENSSL_FOUND__
        !m_ssl_socket &&
#endif
        !m_socket
    ) return false;

    switch(m_protocol)
    {
        case protocol::http:
            return m_socket->is_open();
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            return m_ssl_socket->lowest_layer().is_open();
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

bool uva::networking::basic_socket::needs_handshake() const
{
    switch(m_protocol)
    {
        case protocol::http:
            return false;
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            return true;
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

size_t uva::networking::basic_socket::available() const
{
    switch(m_protocol)
    {
        case protocol::http:
            return m_socket->available();
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            return m_ssl_socket->lowest_layer().available();
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

size_t uva::networking::basic_socket::available(error_code& ec) const
{
    switch(m_protocol)
    {
        case protocol::http:
            return m_socket->available(ec);
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            return m_ssl_socket->lowest_layer().available(ec);
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

std::string uva::networking::basic_socket::remote_endpoint_string() const
{
    error_code ec;
    asio::ip::tcp::endpoint endpoint;

    switch(m_protocol)
    {
        case protocol::http:
            endpoint = m_socket->remote_endpoint(ec);
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            endpoint = m_ssl_socket->lowest_layer().remote_endpoint(ec);
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }

    if(ec) {
        return "[Invalid Address]";
    }

    return endpoint.address().to_string();
}

error_code uva::networking::basic_socket::connect(const std::string &protocol, const std::string &host)
{
    std::string __host = host;
    std::string port = protocol;
    size_t port_index = host.find(':');
    if(port_index != std::string::npos) {
        __host = host.substr(0, port_index);
        port = host.substr(port_index+1);
    }

    asio::error_code ec;

    m_protocol = protocol == "https" ? protocol::https : protocol::http;
    asio::ip::basic_resolver_results<asio::ip::tcp> results = resolver->resolve(asio::ip::tcp::resolver::query(__host, port), ec);

    if(ec) {
        return ec;
    }

    switch(m_protocol)
    {
        case protocol::http:
            m_socket = std::make_unique<asio::ip::tcp::socket>(*io_context);
            m_socket->connect(*results, ec);
#ifdef __UVA_OPENSSL_FOUND__
            m_ssl_socket.reset();
#endif
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            m_ssl_socket = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket>>(*io_context, *ssl_context);
            m_ssl_socket->lowest_layer().connect(*results, ec);

            m_socket.reset();
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }

    if(ec) {
        close();
    }

    return ec;
}

void uva::networking::basic_socket::connect_async(const std::string &protocol, const std::string &host, std::function<void(error_code)> completation)
{
    std::string __host = host;
    std::string port = protocol;
    size_t port_index = host.find(':');
    if(port_index != std::string::npos) {
        __host = host.substr(0, port_index);
        port = host.substr(port_index+1);
    }

    if(__host.ends_with('/')) {
        __host.pop_back();
    }

    asio::error_code ec;

    m_protocol = protocol == "https" ? protocol::https : protocol::http;
    resolver->async_resolve(asio::ip::tcp::resolver::query(__host, port), [completation, this](error_code ec, asio::ip::tcp::resolver::iterator iterator){

        if(ec) {
            completation(ec);
            return;
        }

        auto connect_completation = [completation, this](error_code ec) {
            if(ec) {
                close();
            }

            completation(ec);
        };

    switch(m_protocol)
    {
        case protocol::http:
#ifdef __UVA_OPENSSL_FOUND__
            m_ssl_socket.reset();
#endif
            m_socket = std::make_unique<asio::ip::tcp::socket>(*io_context);
            m_socket->async_connect(*iterator, connect_completation);
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            m_socket.reset();
            m_ssl_socket = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket>>(*io_context, *ssl_context);
            m_ssl_socket->lowest_layer().async_connect(*iterator, connect_completation);
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
    });
}

error_code uva::networking::basic_socket::server_handshake()
{
    error_code ec;


    switch(m_protocol)
    {
        case protocol::http:
            //throw excpetion
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            m_ssl_socket->handshake(asio::ssl::stream_base::server, ec);
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }

    return ec;
}

error_code uva::networking::basic_socket::client_handshake()
{
    error_code ec;

    switch(m_protocol)
    {
        case protocol::http:
            //throw excpetion
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            m_ssl_socket->handshake(asio::ssl::stream_base::client, ec);
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }

    return ec;
}

void uva::networking::basic_socket::async_client_handshake(std::function<void(error_code)> completation)
{
    switch(m_protocol)
    {
        case protocol::http:
            //throw excpetion
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            m_ssl_socket->async_handshake(asio::ssl::stream_base::client, completation);
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

void uva::networking::basic_socket::async_server_handshake(std::function<void(error_code)> completation)
{
    switch(m_protocol)
    {
        case protocol::http:
            //throw excpetion
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            m_ssl_socket->async_handshake(asio::ssl::stream_base::server, completation);
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

void uva::networking::basic_socket::close()
{
    switch(m_protocol)
    {
        case protocol::http:
            m_socket->close();
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            m_ssl_socket->lowest_layer().close();
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

void uva::networking::basic_socket::read_until(std::string &buffer, std::string_view delimiter)
{
}

void uva::networking::basic_socket::async_read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(error_code, size_t)> completation)
{
    switch(m_protocol)
    {
        case protocol::http:
            asio::async_read_until(*m_socket, buffer, delimiter, completation);
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            asio::async_read_until(*m_ssl_socket, buffer, delimiter, completation);
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

void uva::networking::basic_socket::write(std::string_view sv)
{   
    switch(m_protocol)
    {
        case protocol::http:
            asio::write(*m_socket, asio::buffer(sv, sv.size()));
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            asio::write(*m_ssl_socket, asio::buffer(sv, sv.size()));
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

void uva::networking::basic_socket::async_write(std::string_view sv, std::function<void(error_code &)> completation)
{
    switch(m_protocol)
    {
        case protocol::http:
            asio::async_write(*m_socket, asio::buffer(sv, sv.size()), [completation](error_code ec, size_t bytes_written) {
                completation(ec);
            });
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            asio::async_write(*m_ssl_socket, asio::buffer(sv, sv.size()), [completation](error_code ec, size_t bytes_written) {
                completation(ec);
            });
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

void uva::networking::basic_socket::read_exactly(char *buffer, size_t to_read)
{
    size_t read = 0;

    switch(m_protocol)
    {
        case protocol::http:
            read = asio::read(*m_socket, asio::buffer(buffer, to_read), asio::transfer_exactly(to_read));
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            read = asio::read(*m_ssl_socket, asio::buffer(buffer, to_read), asio::transfer_exactly(to_read));
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }

    if (read != to_read) {
        throw std::runtime_error("expecting to read exactly " + std::to_string(to_read) + " bytes but " + std::to_string(read) + " were read instead.");
    }
}

void uva::networking::basic_socket::read_exactly(std::string &buffer, size_t to_read)
{
    size_t read = 0;

    switch(m_protocol)
    {
        case protocol::http:
            read = asio::read(*m_socket, asio::buffer(buffer), asio::transfer_exactly(to_read));
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            read = asio::read(*m_ssl_socket, asio::buffer(buffer), asio::transfer_exactly(to_read));
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }

    if (read != to_read) {
        throw std::runtime_error("expecting to read exactly " + std::to_string(to_read) + " bytes but " + std::to_string(read) + " were read instead.");
    }
}

void uva::networking::basic_socket::async_read_exactly(asio::mutable_buffer buffer, size_t to_read, std::function<void(error_code, size_t)> completation)
{
    switch(m_protocol)
    {
        case protocol::http:
            asio::async_read(*m_socket, asio::buffer(buffer), asio::transfer_exactly(to_read), completation);
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            asio::async_read(*m_ssl_socket, asio::buffer(buffer), asio::transfer_exactly(to_read), completation);
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

void uva::networking::basic_socket::async_read_exactly(asio::streambuf& buffer, size_t to_read, std::function<void(error_code, size_t)> completation)
{
    switch(m_protocol)
    {
        case protocol::http:
            asio::async_read(*m_socket, buffer, asio::transfer_exactly(to_read), completation);
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            asio::async_read(*m_ssl_socket, buffer, asio::transfer_exactly(to_read), completation);
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }
}

uint8_t uva::networking::basic_socket::read_byte()
{
	uint8_t byte;
	const size_t to_read = sizeof(byte);

	auto buffer = asio::buffer(&byte, to_read);

    size_t read = 0;

    switch(m_protocol)
    {
        case protocol::http:
            read = asio::read(*m_socket, buffer, asio::transfer_exactly(to_read));
        break;
#ifdef __UVA_OPENSSL_FOUND__
        case protocol::https:
            read = asio::read(*m_ssl_socket, buffer, asio::transfer_exactly(to_read));
        break;
#endif
        default:
            BASIC_SOCKET_THROW_UNDEFINED_METHOD_FOR_THIS_PROTOCOL();
        break;
    }

    if (read != to_read) {
        throw std::runtime_error("expecting to read exactly " + std::to_string(to_read) + " bytes but " + std::to_string(read) + " were read instead.");
    }

    return byte;
}
