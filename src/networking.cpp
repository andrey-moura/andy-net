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
std::unique_ptr<asio::ssl::context> uva::networking::ssl_context;
const std::string uva::networking::version = "1.0.0";

//STATIC PRIVATE VARIABLES
std::unique_ptr<std::thread> work_thread;
std::unique_ptr<asio::ip::tcp::resolver> resolver;

void asio_thread_loop()
{
    std::cout << "Running ASIO..." << std::endl;
    try {
        io_context->run();
    } catch(std::exception e)
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

    ssl_context = std::make_unique<asio::ssl::context>(asio::ssl::context::sslv23);

    ssl_context->set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 | asio::ssl::context::single_dh_use);

    ssl_context->set_password_callback([](size_t, asio::ssl::context::password_purpose){ return "teste"; });

    ssl_context->use_certificate_chain_file("server.crt");
    ssl_context->use_private_key_file("server.key", asio::ssl::context::pem);
    ssl_context->use_tmp_dh_file("dh2048.pem");

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
    ssl_context.reset();
    work_thread.reset();
}

static std::map<status_code, std::string> s_status_codes
{
    { (status_code)200, "OK" },
    { (status_code)204, "No Content" },
    { (status_code)400, "Bad Request" },
    { (status_code)401, "Unauthorized" },
    { (status_code)404, "Not Found" },
    { (status_code)413, "Payload Too Large" },
    { (status_code)415, "Unsupported Media Type" },
    { (status_code)500, "Internal Server Error" },
};

static std::map<content_type, std::string> s_content_types
{
    { content_type::text_html, "text/html" },
    { content_type::text_css, "text/css" },
    { content_type::application_json, "application/json" },
};

static std::string s_server_version = "0.0.1";

const std::string& status_code_to_string(const status_code& status) {
    auto it = s_status_codes.find(status);

    if (it == s_status_codes.end()) {
        throw std::runtime_error(std::format("error: {} is not a valid http_message code.", (size_t)status));
    }

    return it->second;
}

const std::string& content_type_to_string(const content_type& type) {
    auto it = s_content_types.find(type);

    if (it == s_content_types.end()) {
        throw std::runtime_error(std::format("error: {} is not a valid http_message code.", (size_t)type));
    }

    return it->second;
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

void async_read_body(basic_socket &socket, asio::streambuf& buffer, size_t already_read, std::string& body, const var& headers, std::function<void(error_code, size_t)> completation)
{
    var transfer_encoding = headers.fetch("Transfer-Encoding");

    if (transfer_encoding != null) {
        //if (transfer_encoding != "chunked") {
            throw std::runtime_error("invalid http_message: transfer enconding currently aren't supported.");
        //}
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
        {
            std::istream request_stream(&buffer);

            request_stream >> request.method;
            request_stream >> request.url;
            request_stream >> request.version;

            std::string endpoint = socket.remote_endpoint_string();
            request.endpoint = endpoint;

            static std::string version_start = "HTTP/";

            if (!request.version.starts_with(version_start)) {
                throw std::runtime_error(std::format("Unrecognized HTTP version: {} ({} {})", request.version, request.method, request.url));
            }

            std::string empty_line;
            std::getline(request_stream, empty_line);
            request.headers = parse_headers(request_stream);
        }

        async_read_body(socket, buffer, s, request.raw_body, request.headers, [&request, completation](error_code ec, size_t) {
            if(request.method == "POST") {

                std::string content_type = request.headers["Content-Type"];
                if(content_type == "application/json") {
                    request.params = json::decode(request.raw_body);
                }
            } else {
                std::string query;

                size_t search_params_index = request.url.find('?');

                if(search_params_index != std::string::npos) {
                    query = request.url.substr(search_params_index+1);
                    request.url = request.url.substr(0, search_params_index);
                }

                request.params = std::move(query_to_params(query));
            }

            if(request.url.starts_with('/')) {
                request.url.erase(request.url.begin());
            }

            completation();
        });
        
    });
}

http_message uva::networking::read_http_response(basic_socket& socket, asio::streambuf& buffer)
{
    http_message response;
    // Read the response status line. The response streambuf will automatically
    // grow to accommodate the entire line. The growth may be limited by passing
    // a maximum size to the streambuf constructor.                
    std::string headers;
    headers.reserve(512);

    socket.read_until(headers, "\r\n\r\n");

    std::stringstream headers_stream(headers);

    std::string http_info;
    while((http_info.empty() || http_info == "\r") && std::getline(headers_stream, http_info))
    {

    }

    std::stringstream htpp_info_stream(http_info);

    std::string version;
    htpp_info_stream >> version;

    char version_start[] = "HTTP/";

    if(!version.starts_with(version_start)) {
        throw std::runtime_error("invalid response: invalid http response (1)");
    }

    response.version = version.substr(sizeof(version_start)-1);

    int status;

    htpp_info_stream >> status;
    htpp_info_stream >> response.status_msg;

    // response.status = (status_code)status;
    // response.headers = read_headers(headers_stream);
    // std::string body = read_body(socket, response.headers);

    // var content_type = response.headers.fetch("Content-type");

    // if(content_type == "application/json") {
    //     response.body = uva::json::decode(body);
    // } else {
    //     response.body = body;
    // }

    return response;
}

void uva::networking::async_write_http_response(basic_socket &socket, const std::string &body, const status_code &status, const content_type &content_type, std::function<void (uva::networking::error_code &)> completation)
{
    std::string status_code_string = std::to_string((size_t)status);
    std::string status_string = status_code_to_string(status);
    std::string date_string = time_now_to_standard_string();
    std::string content_type_string = content_type_to_string(content_type);
    std::string body_length_string = std::to_string(body.size());

    const char* const header_format =
"HTTP/1.1 {} {}\r\n"
"Server: uva::networking/{}\r\n"
"Date: {}\r\n"
"Content-Type: {}\r\n"
"Content-Length: {}\r\n"
"\r\n";

    std::string header = std::format(header_format, status_code_string, status_string, s_server_version, date_string, content_type_string, body_length_string);

    size_t bytes_written = 0;

    socket.async_write(header, [&body, &socket, completation](uva::networking::error_code ec) {
        socket.async_write(body, [completation](uva::networking::error_code ec) {
            completation(ec);
        });
    });
}

void uva::networking::write_http_request(basic_socket &socket, std::string host, const std::string &route, const std::map<var, var> &params, const std::map<var, var> &headers, const std::string &body, std::function<void()> on_success, std::function<void(error_code &)> on_error)
{
    std::string subject = route;

    if(subject.starts_with('/')) {
        subject.erase(0);
    }

    //OLD CODE
    if (!params.empty()) {
        subject += "?";
        for (const auto& param : params)
        {
            subject += param.first.to_s();
            subject += "=";
            subject += param.second.to_s();
            subject += '&';
        }
        subject.erase(subject.size() - 1, 1);
    }

    if (host.starts_with("https://")) {
        host.erase(0, 8);
    } else if(host.starts_with("http://")) {
        host.erase(0, 7);
    }

    std::string request;
    request.reserve(512+body.size());

    request += "GET /";
    request += subject;
    request += " HTTP/1.1\r\n";

    request += "Host: ";
    request += host;
    request += "\r\n";
    request += "User-Agent: uva::networking/";
    request += version;
    request += "\r\n";
    request += "Accept: */*\r\n";
    request += "Connection: keep-alive\r\n";

    for(const auto& header : headers)
    {
        request += std::format("{}: {}\r\n", header.first, header.second.to_s());
    }

    if(body.size()) {
        request += "Content-Length: ";
        request += std::to_string(body.size());
        request += "\r\n\r\n";

        request += body;
    } else {
        request += "\r\n";
    }

    socket.async_write(request, [on_success, on_error](error_code& ec) {
        if(ec) {
            on_error(ec);
        } else {
            on_success();
        }
    });
}

void uva::networking::decode_char_from_web(std::string_view& sv, std::string &buffer)
{
    if(sv.starts_with('%')) {
        sv.remove_prefix(1);

        if(sv.size() <= 1) {
            if(!isdigit(sv.front())) {
                throw std::runtime_error("invalid character following hex scape sequence");
            }

            buffer.push_back(uva::binary::nibble_from_hex_string(sv.front()));
            sv.remove_prefix(1);
        } else if(sv.size() >= 2) {
            if(isdigit(sv[0])) {
                if(isdigit(sv[1])) {
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

std::map<var, var> uva::networking::query_to_params(std::string_view query)
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
            }

            decode_char_from_web(query, current_param_key);
        }

        while(query.size())
        {
            if(query.starts_with('&')) {
                query.remove_prefix(1);
                break;
            }

            decode_char_from_web(query, current_param_value);
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
        case protocol::https:
            m_ssl_socket = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket>>(std::forward<asio::ip::tcp::socket&&>(__socket), *ssl_context);
        break;
    }
}

uva::networking::basic_socket::basic_socket(basic_socket &&__socket)
    : m_ssl_socket(std::move(__socket.m_ssl_socket)), m_socket(std::move(__socket.m_socket)), m_protocol(__socket.m_protocol)
{

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
        case protocol::https:
            if(m_ssl_socket) {
                if(m_ssl_socket->lowest_layer().is_open()) {
                    m_ssl_socket->lowest_layer().close();
                }
            }
        break;
    }
}

bool uva::networking::basic_socket::is_open() const
{
    if(!m_ssl_socket && !m_socket) return false;

    if(m_protocol == protocol::https) {
        return m_ssl_socket->lowest_layer().is_open();
    } else {
        return m_socket->is_open();
    }
}

bool uva::networking::basic_socket::needs_handshake() const
{
    if(!m_ssl_socket && !m_socket) {
        //throw error
    }

    return m_protocol == protocol::https;
}

size_t uva::networking::basic_socket::available() const
{
    if(m_protocol == protocol::https) {
        return m_ssl_socket->lowest_layer().available();
    } else {
        return m_socket->available();
    }
}

size_t uva::networking::basic_socket::available(error_code& ec) const
{
    if(m_protocol == protocol::https) {
        return m_ssl_socket->lowest_layer().available(ec);
    } else {
        return m_socket->available(ec);
    }
}

std::string uva::networking::basic_socket::remote_endpoint_string() const
{
    error_code ec;
    asio::ip::tcp::endpoint endpoint;

    if(m_protocol == protocol::https) {
        endpoint = m_ssl_socket->lowest_layer().remote_endpoint(ec);
    } else {
        endpoint = m_socket->remote_endpoint(ec);
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
    else if(m_protocol == protocol::https) {
        m_ssl_socket = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket>>(*io_context, *ssl_context);
        m_ssl_socket->lowest_layer().connect(*results, ec);

        m_socket.reset();
    } else {
        m_socket = std::make_unique<asio::ip::tcp::socket>(*io_context);
        m_socket->connect(*results, ec);

        m_ssl_socket.reset();
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

        if (m_protocol == protocol::https) {
            m_socket.reset();
            m_ssl_socket = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket>>(*io_context, *ssl_context);
            m_ssl_socket->lowest_layer().async_connect(*iterator, connect_completation);
        } else {
            m_ssl_socket.reset();
            m_socket = std::make_unique<asio::ip::tcp::socket>(*io_context);
            m_socket->async_connect(*iterator, connect_completation);
        }
    });
}

error_code uva::networking::basic_socket::server_handshake()
{
    error_code ec;

    if(m_protocol == protocol::https) {
        m_ssl_socket->handshake(asio::ssl::stream_base::server, ec);
    } else {
        //throw excpetion
    }

    return ec;
}

error_code uva::networking::basic_socket::client_handshake()
{
    error_code ec;

    if(m_protocol == protocol::https) {
        m_ssl_socket->handshake(asio::ssl::stream_base::client, ec);
    } else {
        //throw excpetion
    }

    return ec;
}

void uva::networking::basic_socket::async_client_handshake(std::function<void(error_code)> completation)
{
    if(m_protocol == protocol::https) {
        m_ssl_socket->async_handshake(asio::ssl::stream_base::client, completation);
    } else {
        //throw excpetion
    }
}

void uva::networking::basic_socket::async_server_handshake(std::function<void(error_code)> completation)
{
    if(m_protocol == protocol::https) {
        m_ssl_socket->async_handshake(asio::ssl::stream_base::server, completation);
    } else {
        //throw excpetion
    }
}

void uva::networking::basic_socket::close()
{
    if(!m_ssl_socket && !m_socket) {
        //throw error
        return;
    }

    if(m_protocol == protocol::https) {
        m_ssl_socket->lowest_layer().close();
    } else {
        m_socket->close();
    }  
}

void uva::networking::basic_socket::read_until(std::string &buffer, std::string_view delimiter)
{
}

void uva::networking::basic_socket::async_read_until(asio::streambuf &buffer, std::string_view delimiter, std::function<void(error_code, size_t)> completation)
{
    switch(m_protocol)
    {
        case protocol::https:
            asio::async_read_until(*m_ssl_socket, buffer, delimiter, completation);
        break;
            asio::async_read_until(*m_socket, buffer, delimiter, completation);
        break;
    }
}

void uva::networking::basic_socket::write(std::string_view sv)
{   
    if(m_protocol == protocol::https) {
        if(!m_ssl_socket) {
            throw std::runtime_error("error: attempt to write on a null socket");
        }
        asio::write(*m_ssl_socket, asio::buffer(sv, sv.size()));
    } else {
        asio::write(*m_socket, asio::buffer(sv, sv.size()));
    }  
}

void uva::networking::basic_socket::async_write(std::string_view sv, std::function<void(error_code &)> completation)
{
    if(m_protocol == protocol::https) {
        asio::async_write(*m_ssl_socket, asio::buffer(sv, sv.size()), [completation](error_code ec, size_t bytes_written) {
            completation(ec);
        });
    } else {
        asio::async_write(*m_ssl_socket, asio::buffer(sv, sv.size()), [completation](error_code ec, size_t bytes_written) {
            completation(ec);
        });
    }  
}

void uva::networking::basic_socket::read_exactly(char *buffer, size_t to_read)
{
    size_t read = 0;
    switch (m_protocol)
    {
    case protocol::http:
        read = asio::read(*m_socket, asio::buffer(buffer, to_read), asio::transfer_exactly(to_read));
        break;
    case protocol::https:
        read = asio::read(*m_ssl_socket, asio::buffer(buffer, to_read), asio::transfer_exactly(to_read));
        break;
    default:
        break;
    }

    if (read != to_read) {
        throw std::runtime_error("expecting to read exactly " + std::to_string(to_read) + " bytes but " + std::to_string(read) + " were read instead.");
    }
}

void uva::networking::basic_socket::read_exactly(std::string &buffer, size_t to_read)
{
    size_t read = 0;
    switch (m_protocol)
    {
    case protocol::http:
        read = asio::read(*m_socket, asio::buffer(buffer), asio::transfer_exactly(to_read));
        break;
    case protocol::https:
        read = asio::read(*m_ssl_socket, asio::buffer(buffer), asio::transfer_exactly(to_read));
        break;
    default:
        break;
    }

    if (read != to_read) {
        throw std::runtime_error("expecting to read exactly " + std::to_string(to_read) + " bytes but " + std::to_string(read) + " were read instead.");
    }
}

void uva::networking::basic_socket::async_read_exactly(asio::mutable_buffer buffer, size_t to_read, std::function<void(error_code, size_t)> completation)
{
    switch (m_protocol)
    {
    case protocol::http:
        asio::async_read(*m_socket, asio::buffer(buffer), asio::transfer_exactly(to_read), completation);
        break;
    case protocol::https:
        asio::async_read(*m_ssl_socket, asio::buffer(buffer), asio::transfer_exactly(to_read), completation);
        break;
    default:
        break;
    }
}

uint8_t uva::networking::basic_socket::read_byte()
{
	uint8_t byte;
	const size_t to_read = sizeof(byte);

	auto buffer = asio::buffer(&byte, to_read);

    size_t read = 0;
    switch (m_protocol)
    {
    case protocol::http:
        read = asio::read(*m_socket, buffer, asio::transfer_exactly(to_read));
        break;
    case protocol::https:
        read = asio::read(*m_ssl_socket, buffer, asio::transfer_exactly(to_read));
        break;
    default:
        break;
    }

    if (read != to_read) {
        throw std::runtime_error("expecting to read exactly " + std::to_string(to_read) + " bytes but " + std::to_string(read) + " were read instead.");
    }

    return byte;
}