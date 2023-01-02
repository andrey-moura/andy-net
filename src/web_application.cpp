#include <thread>
#include <map>
#include <iostream>
#include <filesystem>
#include <fstream>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <web_application.hpp>
#include <console.hpp>

using namespace uva;
using namespace console;
using namespace networking;
using namespace routing;
using namespace web_application;

response web_application::current_response;

class web_connection;

request proccess_request(std::shared_ptr<web_connection> connnection, bool new_connection = false);

asio::io_context m_asioContext;
asio::ssl::context* m_ssl_context;
asio::io_context::work work(m_asioContext);
std::thread m_threadContext([]() { m_asioContext.run(); });
// These things need an asio context
asio::ip::tcp::acceptor* m_asioAcceptor = nullptr;

class web_connection : public basic_connection
{
public:
    web_connection(asio::ssl::stream<asio::ip::tcp::socket>&& socket)
        : m_socket(std::forward<asio::ssl::stream<asio::ip::tcp::socket>&&>(socket))
    {
        asio::error_code ec;
        m_socket.handshake(asio::ssl::stream_base::server, ec);

        if (ec) {
            std::cout << "handshake failed " + ec.message() << std::endl;
        } else {
            std::cout << "handshake good" << std::endl;
        }
    }

    ~web_connection()
    {
        if(m_socket.lowest_layer().is_open()) {
            m_socket.lowest_layer().close();
        }
    }

    asio::ssl::stream<asio::ip::tcp::socket> m_socket;
};

std::vector<std::shared_ptr<web_connection>> m_connections;

//Reads byte-to-byte from socket storing into buffer while the bytes NOT ends with delimiter
void read_until(std::string& buffer, asio::ssl::stream<asio::ip::tcp::socket>& socket, const std::string& delimiter) {
	uint8_t byte;
	const size_t read_amount = sizeof(byte);

	auto response_buffer = asio::buffer(&byte, read_amount);

	while (!buffer.ends_with(delimiter)) {
        size_t read = 0;
        try {
             read = asio::read(socket, response_buffer, asio::transfer_exactly(1));
        }
        catch(asio::system_error e) {
            std::cerr << "[SERVER] Error: cannot read from socket." << std::endl;
            return;
        }

		if (read != 1) {
			throw std::runtime_error("expecting to read exactly " + std::to_string(read_amount) + " byte but " + std::to_string(read) + " were read instead.");
		}

		buffer.push_back(byte);
	}
}

static std::map<status_code, std::string> s_status_codes
{
    { (status_code)200, "OK" },
    { (status_code)204, "No Content" },
    { (status_code)400, "Bad Request" },
    { (status_code)404, "Not Found" },
};

static std::map<content_type, std::string> s_content_types
{
    { content_type::text_html, "text/html" },
    { content_type::application_json, "application/json" },
};

static std::string s_server_version = "0.0.1";

const std::string& status_code_to_string(const status_code& status) {
    auto it = s_status_codes.find(status);

    if (it == s_status_codes.end()) {
        throw std::runtime_error(std::format("error: {} is not a valid response code.", (size_t)status));
    }

    return it->second;
}

const std::string& content_type_to_string(const content_type& type) {
    auto it = s_content_types.find(type);

    if (it == s_content_types.end()) {
        throw std::runtime_error(std::format("error: {} is not a valid response code.", (size_t)type));
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

request http_headers_from_socket(asio::ssl::stream<asio::ip::tcp::socket>& socket)
{
    // Read the response status line. The response streambuf will automatically
    // grow to accommodate the entire line. The growth may be limited by passing
    // a maximum size to the streambuf constructor.                

    size_t available = socket.lowest_layer().available();

    std::string buffer;
    buffer.reserve(512);

    read_until(buffer, socket, "\r\n\r\n");

    std::stringstream headers_stream(buffer);

    std::string http_info;
    std::getline(headers_stream, http_info);

    std::stringstream htpp_info_stream(http_info);

    std::string request_type;
    htpp_info_stream >> request_type;

    std::string request_url;
    htpp_info_stream >> request_url;

    std::string http_version;
    htpp_info_stream >> http_version;

    char version_start[] = "HTTP/";

    if (!http_version.starts_with(version_start)) {
        throw std::runtime_error("invalid response: invalid http response (1)");
    }

    request request;
    request.headers = empty_map;
    request.params = empty_map;

    //std::string status_code;
    //std::string status_message;

    //htpp_info_stream >> status_code;
    //htpp_info_stream >> status_message;

    request.headers["request_type"] = request_type;
    request.headers["request_url"] = request_url;
    request.headers["http_version"] = http_version;

    //headers["http_version"] = version;
    //headers["status_code"] = status_code;
    //headers["status_message"] = status_message;

    std::string header;
    size_t content_lenght = 0;

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

        request.headers[h] = header;
    }

    var transfer_encoding = request.headers.fetch("Transfer-Encoding");

    if (transfer_encoding != null) {
        if (transfer_encoding != "chunked") {
            throw std::runtime_error("invalid response: only response body with chunked encoding are supported.");
        }

        size_t to_read = std::string::npos;

        do {
            std::string line;
            //\r\n NUMBER \r\n
            line.reserve(2 + 8 + 2);

            read_until(line, socket, "\r\n");

            //There is a separator between the response body and the lenght.
            //This line is consumed the first time when the header is read but
            //not after that.
            if (to_read != std::string::npos) {
                line.clear();
                read_until(line, socket, "\r\n");
            }

            to_read = std::stoi(line, nullptr, 16);

            size_t last_size = request.body.size();

            request.body.resize(last_size + to_read);

            size_t read = asio::read(socket, asio::buffer((char*)request.body.c_str() + last_size, to_read), asio::transfer_exactly(to_read));
            if (read != to_read) {
                throw std::runtime_error("expecting to read exactly " + std::to_string(to_read) + " bytes but " + std::to_string(read) + " were read instead.");
            }

        } while (to_read);
    }
    else {
        var content_lenght = request.headers.fetch("Content-Length");

        if (content_lenght != null) {
            size_t to_read = content_lenght.to_i();

            request.body.resize(to_read);
            size_t read = asio::read(socket, asio::buffer(request.body), asio::transfer_exactly(to_read));

            if (read != to_read) {
                throw std::runtime_error("expecting to read exactly " + std::to_string(to_read) + " bytes but " + std::to_string(read) + " were read instead.");
            }
        }
    }

    return request;
}

void write_response(asio::ssl::stream<asio::ip::tcp::socket>& socket, const std::string& body, const status_code& status, const content_type& content_type)
{
    std::string status_code_string = std::to_string((size_t)status);
    std::string status_string = status_code_to_string(status);
    std::string date_string = time_now_to_standard_string();
    std::string content_type_string = content_type_to_string(content_type);
    std::string body_length_string = std::to_string(body.size());

    std::string header_format =
"HTTP/1.1 {} {}\r\n"
"Server: cow/{}\r\n"
"Date: {}\r\n"
"Content-Type: {}\r\n"
"Content-Length: {}\r\n"
"\r\n";

    std::string header = std::format(header_format, status_code_string, status_string, s_server_version, date_string, content_type_string, body_length_string);

    size_t bytes_written = 0;
    
    try {
        asio::write(socket, asio::buffer(header, header.size()));
        asio::write(socket, asio::buffer(body, body.size()));
    } catch(asio::system_error e) {

    }


}

static std::string s_not_found_page =
R"~~~(
<html>
    <head><title>404 Not Found</title></head>
    <body bgcolor="white">
        <center><h1>404 Not Found</h1></center>
        <hr><center>uva-networking/)~~~" + s_server_version + R"~~~(</center>
    </body>
</html>
)~~~";

void write_404_response(asio::ssl::stream<asio::ip::tcp::socket>& socket)
{
    write_response(socket, s_not_found_page, status_code::not_found, content_type::text_html);
}

static std::string cow_read_file(const std::filesystem::path& path)
{
    std::ifstream cmake_file(path);
    if (!cmake_file.is_open()) {
        std::cout << "error: unable to create file " << path.string() << std::endl;
        return "";
    }
    std::string content;

    cmake_file.seekg(0, std::ios::end);
    size_t file_len = cmake_file.tellg();
    cmake_file.seekg(0, std::ios::beg);

    content.resize(file_len);

    cmake_file.read((char*)content.c_str(), content.size());
    cmake_file.close();
    return content;
}

std::string remote_endpoint(asio::ssl::stream<asio::ip::tcp::socket>& socket)
{
    asio::error_code ec;
    auto endpoint = socket.lowest_layer().remote_endpoint(ec);
    if(ec) {
        return "[Invalid Address]";
    }

    return endpoint.address().to_string();
}

request proccess_request(std::shared_ptr<web_connection> connnection, bool new_connection)
{
    request request;

    current_response.type = content_type::text_html;
    current_response.status = status_code::no_content;
    current_response.body = "";

    try {
        request = http_headers_from_socket(connnection->m_socket);
    }
    catch(std::runtime_error e) {
        std::cerr << "[SERVER] Read invalid http request from " << remote_endpoint(connnection->m_socket) << std::endl;
        connnection->m_socket.lowest_layer().close();
        return request;
    }

    if(new_connection) {

    }

    std::string action;
    std::string controller;

    std::string url = request.headers["request_url"];

    if(url.starts_with('/')) {
        url.erase(url.begin());
    }

    std::string route = request.headers["request_type"] + " " + url;

    if(request.headers["Connection"] != "keep-alive") {
        connnection->m_socket.lowest_layer().close();
    }

    dispatch(route, connnection, empty_map, request.headers, request.body);

    write_response(connnection->m_socket, current_response.body, current_response.status, current_response.type);

    if (0) {
        //todo: show detailed error message
        write_404_response(connnection->m_socket);
        return request;
    }

    return request;
}

void acceptor(asio::ip::tcp::acceptor& asioAcceptor) {
	asioAcceptor.async_accept([&asioAcceptor](std::error_code ec, asio::ip::tcp::socket socket)
	{
		// Triggered by incoming connection request
		if (!ec)
		{
	        std::cout << "[SERVER] New Connection: " << socket.remote_endpoint() << "\n";
            m_connections.push_back(std::make_shared<web_connection>(asio::ssl::stream<asio::ip::tcp::socket>(std::move(socket), *m_ssl_context)));


            proccess_request(m_connections.back(), true);
		}
		else
		{
			// Error has occurred during acceptance
			std::cout << "[SERVER] New Connection Error: " << ec.message() << "\n";
		}

		acceptor(asioAcceptor);
	});
}

void cleanup()
{
    m_asioContext.stop();

    if(m_threadContext.joinable())
    {
        m_threadContext.join();
    }
}

void web_application::init(int argc, const char **argv)
{
	size_t port = 3000;
    std::string address = "localhost";

    static std::string port_switch = "--port=";

    for(size_t i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if(arg.starts_with(port_switch)) {
            port = std::stoi(arg.substr(port_switch.size()));
        }
    }

    m_ssl_context = new asio::ssl::context(asio::ssl::context::sslv23);
    m_ssl_context->set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
                                asio::ssl::context::single_dh_use);

    m_ssl_context->set_password_callback([](size_t, asio::ssl::context::password_purpose){return "teste";});

    m_ssl_context->use_certificate_chain_file("server.crt");
    m_ssl_context->use_private_key_file("server.key", asio::ssl::context::pem);
    m_ssl_context->use_tmp_dh_file("dh2048.pem");
    
	asio::error_code ec;

	asio::ip::tcp::resolver resolver(m_asioContext);
	asio::ip::basic_resolver_results res = resolver.resolve({ address, std::to_string(port).data() }, ec);
    asio::ip::tcp::endpoint endpoint = asio::ip::tcp::endpoint(*res.begin());

    try {
        m_asioAcceptor = new asio::ip::tcp::acceptor(m_asioContext, endpoint, port); // Handles new incoming connection attempts...
    } catch(asio::system_error e)
    {
        ec = e.code();
    }

	if (ec || res.empty()) {
        log_error("Failed to resolve endpoint for {} on port {}: {}", address, port, ec.message());
        cleanup();
		return;
	}

	acceptor(*m_asioAcceptor);

    log_success("Started listening in {} on port {}", address, port);

	while (1) {
		std::this_thread::sleep_for(std::chrono::milliseconds(16));\

        std::vector<std::shared_ptr<web_connection>> seek_connections;

        for(auto& connection : m_connections)
        {
            asio::error_code ec;
            bool is_seek = false;

            if(connection->m_socket.lowest_layer().is_open())
            {
                size_t available = connection->m_socket.lowest_layer().available(ec);
                if(!ec)
                {
                    if(available)
                    {
                        proccess_request(connection);
                        //connection->read_request();
                    }
                }
            }

            seek_connections.push_back(connection);
        }

        std::remove_if(m_connections.begin(), m_connections.end(), [&seek_connections](std::shared_ptr<web_connection>& connection){
            auto it = std::find(seek_connections.begin(), seek_connections.end(), connection);

            if(it != seek_connections.end()) {
                seek_connections.erase(it);
                return true;
            }

            return false;
        });
	}
}

response &uva::networking::web_application::response::operator<<(const uva::json &__body)
{
    status = status_code::ok;
    body = __body.enconde();
    type = content_type::application_json;

    return *this;
}

response &uva::networking::web_application::response::operator<<(const status_code &__status)
{
    status = __status;
    return *this;
}

// #include <asio.hpp>
// #include <asio/ssl.hpp>
// #include <iostream>

// using asio::ip::tcp;
// using asio::error_code;
// using ssl_socket = asio::ssl::stream<tcp::socket>;
// using namespace std::chrono_literals;

// class session {
//   public:
//     session(asio::io_service& io_service, asio::ssl::context& context)
//         : socket_(io_service, context) {}

//     ssl_socket::lowest_layer_type& socket() {
//         return socket_.lowest_layer();
//     }

//     void start() {
//         socket_.async_handshake( //
//             ssl_socket::server,
//             std::bind(&session::handle_handshake, this,
//                         std::placeholders::_1));
//     }

//     void handle_handshake(error_code error) {
//         if (!error) {
//             std::cout << "handshake good" << std::endl;

//             asio::async_read_until(
//                 socket_, asio::dynamic_buffer(data_), "\r\n\r\n",
//                 std::bind(&session::handle_read, this,
//                             std::placeholders::_1,
//                             std::placeholders::_2));

//         } else {
//             std::cout << "handshake failed " + error.message() << std::endl;
//             delete this;
//         }
//     }

//     void handle_read(error_code error, size_t bytes_transferred) {
//         if (!error) {
//             std::string header =
// "HTTP/1.1 200 OK\r\n"
// "Server: cow/1.1\r\n"
// "Content-Type: text/html\r\n"
// "Content-Length: 0\r\n";

//             asio::write(socket_, asio::buffer(header, header.size()));
//         } else {
//             delete this;
//         }
//     }

//     void handle_write(error_code error) {
//         if (!error) {
//             socket_.async_read_some( //
//                 asio::buffer(data_),
//                 std::bind(&session::handle_read, this,
//                             std::placeholders::_1,
//                             std::placeholders::_2));
//         } else {
//             delete this;
//         }
//     }

//   private:
//     ssl_socket                        socket_;
//     std::string                       data_;
// };

// class server {
//   public:
//     using Ctx = asio::ssl::context;
//     server(asio::io_service& io_service, uint16_t port)
//         : io_service_(io_service)
//         , acceptor_(io_service, {tcp::v4(), port})
//         , context_(Ctx::sslv23) //
//     {
//         acceptor_.set_option(tcp::acceptor::reuse_address(true));
//         context_.set_options(Ctx::default_workarounds | Ctx::no_sslv2 |
//                              Ctx::single_dh_use);

//         context_.set_password_callback(&server::get_password);

//         context_.use_certificate_chain_file("server.crt");
//         context_.use_private_key_file("server.key", Ctx::pem);
//         context_.use_tmp_dh_file("dh2048.pem");

//         start_accept();
//     }

//   private:
//     static std::string get_password(size_t, Ctx::password_purpose) {
//         return "test";
//     }

//     void start_accept() {
//         session* new_session = new session(io_service_, context_);
//         acceptor_.async_accept(new_session->socket(),
//                                std::bind(&server::handle_accept, this,
//                                            new_session,
//                                            std::placeholders::_1));
//     }

//     void handle_accept(session* new_session, error_code error) {
//         if (!error) {
//             std::cout << "accept good" << std::endl;
//             new_session->start();
//         } else {
//             delete new_session;
//         }

//         start_accept();
//     }

//   private:
//     asio::io_service& io_service_;
//     tcp::acceptor     acceptor_;
//     asio::ssl::context      context_;
// };

// int main() {
//     asio::io_service ioc;
//     server s(ioc, 8989);

//     ioc.run_for(30s);
// }