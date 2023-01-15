#include <thread>
#include <map>
#include <iostream>
#include <filesystem>
#include <fstream>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <networking.hpp>
#include <web_application.hpp>
#include <file.hpp>
#include <console.hpp>

using namespace uva;
using namespace console;
using namespace networking;
using namespace routing;
using namespace web_application;

http_message web_application::current_response;

std::string name = "web_application";

class web_connection;

http_message proccess_request(std::shared_ptr<web_connection> connnection, bool new_connection = false);
asio::ip::tcp::acceptor* m_asioAcceptor = nullptr;

std::map<std::string, std::function<std::string(var)>> exposed_functions;

class web_connection : public basic_connection
{
public:
    web_connection(basic_socket&& socket)
        : m_socket(std::forward<basic_socket&&>(socket))
    {
        asio::error_code ec;
        if(m_socket.needs_handshake()) {
            ec = m_socket.server_handshake();
        }

        if (ec) {
            std::cout << "handshake failed " + ec.message() << std::endl;
        } else {
            std::cout << "handshake good" << std::endl;
        }
    }

    ~web_connection()
    {
        if(m_socket.is_open()) {
            m_socket.close();
        }
    }

    basic_socket m_socket;
};

std::vector<std::shared_ptr<web_connection>> m_connections;

static std::string s_not_found_page =
R"~~~(
<html>
    <head><title>404 Not Found</title></head>
    <body bgcolor="white">
        <center><h1>404 Not Found</h1></center>
        <hr><center>uva-networking/)~~~" + networking::version + R"~~~(</center>
    </body>
</html>
)~~~";

void write_404_http_message(basic_socket& socket)
{
    write_http_response(socket, s_not_found_page, status_code::not_found, content_type::text_html);
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

http_message proccess_request(std::shared_ptr<web_connection> connnection, bool new_connection)
{
    http_message request;

    current_response.type = content_type::text_html;
    current_response.status = status_code::no_content;
    current_response.body = "";

    try {
        request = read_http_request(connnection->m_socket);
    }
    catch(std::runtime_error e) {
        std::cerr << "[SERVER] Read invalid http request from " << connnection->m_socket.remote_endpoint_string() << std::endl;
        connnection->m_socket.close();
        return request;
    }

    if(new_connection) {

    }

    std::string action;
    std::string controller;

    std::string url = request.url;
    std::string query;

    std::cout << request.headers.to_s() << "\n\n\n";

    size_t search_params_index = url.find('?');

    if(search_params_index != std::string::npos) {
        query = url.substr(search_params_index+1);
        url = url.substr(0, search_params_index);
    }

    var params = std::move(query_to_params(query));

    if(url.starts_with('/')) {
        url.erase(url.begin());
    }

    //asking asset
    if(url.ends_with(".css")) {
        respond css_file(url);

        write_http_response(connnection->m_socket, current_response.body, current_response.status, current_response.type);
    } else {
        std::string route = request.method + " " + url;

        try {
            if(!dispatch(route, connnection, params, request.headers, request.body)) {
                respond html_template("error", {
                    { "error_type", "Routing Error" },
                    { "error_title", "Route Not Found" },
                    { "error_description", std::format("No Route Matches {}", route) },
                });
            }

            write_http_response(connnection->m_socket, current_response.body, current_response.status, current_response.type);
        } catch(std::exception e)
        {
            //write 500 response
            log_error("Exception during dispatch: {}", e.what());
            write_404_http_message(connnection->m_socket);
        }
    }


    if(request.headers["Connection"] != "keep-alive") {
        connnection->m_socket.close();
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
            m_connections.push_back(std::make_shared<web_connection>(basic_socket(std::move(socket), protocol::https)));


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

std::string find_html_file(const std::string& controller, const std::string& name)
{
    std::string folder;

    static std::vector<std::string> extensions = { "cpp.html", "html" };

    std::filesystem::path possibility = app_dir / "app" / "views" / controller / name;

    for(const std::string& extension : extensions) {
        possibility = possibility.replace_extension(extension);
        if(std::filesystem::exists(possibility)) {
            return possibility.string();
        }
    }

    return "";
}

std::string format_html_file(const std::string& path, const var& locals)
{
    static std::string var_tag = "<var>";
    static std::string close_var_tag = "</var>";

    std::string formated_content;
    std::string content = uva::file::read_all_text<char>(path);

    if(!path.ends_with(".cpp.html")) {
        return content;
    }

    formated_content.reserve(content.size());

    size_t index = 0;

    std::string current_var_name;

    while(index < content.size())
    {
        if(formated_content.ends_with(var_tag))
        {
            current_var_name.push_back(content[index]);

            if(current_var_name.ends_with(close_var_tag))
            {
                current_var_name.erase(current_var_name.end()-close_var_tag.size(), current_var_name.end());

                size_t parentheses_index = current_var_name.find('(');

                if(parentheses_index == std::string::npos) {
                    var value = locals.fetch(current_var_name);

                    current_var_name.clear();
                    formated_content.erase(formated_content.end()-var_tag.size(), formated_content.end());

                    if(value)
                    {
                        formated_content += value.to_s();
                    }
                } else {
                    std::string params = current_var_name.substr(parentheses_index);
                    current_var_name = current_var_name.substr(0, parentheses_index);

                    while(isspace(params.back())) {
                        params.pop_back();
                    }

                    if(!params.ends_with(')')) {
                        throw std::runtime_error("failed to parse HTML template: missing ')' at end of function call.");
                    }

                    params.erase(0, 1);
                    params.pop_back();

                    auto arguments = parse_argument_list(params);

                    auto it = exposed_functions.find(current_var_name);

                    if(it == exposed_functions.end()) {
                        throw std::runtime_error(std::format("error: function '{}' not found", current_var_name));
                    }

                    current_var_name.clear();
                    formated_content.erase(formated_content.end()-var_tag.size(), formated_content.end());

                    formated_content += it->second(arguments);
                }

            }
        } else {
            formated_content.push_back(content[index]);
        }

        index++;
    }

    return formated_content;
}

http_message& uva::networking::operator<<(http_message& http_message, const uva::json& __body)
{
    http_message.status = status_code::ok;
    http_message.body = __body.enconde();
    http_message.type = content_type::application_json;

    return http_message;
}

http_message &uva::networking::operator<<(http_message& http_message, const status_code &__status)
{
    http_message.status = __status;
    return http_message;
}

http_message &uva::networking::operator<<(http_message &http_message, const web_application::basic_html_template &__template)
{
    http_message.status = status_code::ok;
    http_message.type = content_type::text_html;

    std::string path = find_html_file(__template.controller, __template.file_name);

    if(path.empty()) {
        //throw error
    }

    http_message.body = format_html_file(path, __template.locals); 

    return http_message;
}

http_message &uva::networking::operator<<(http_message &http_message, const web_application::basic_css_file &css)
{
    http_message.status = status_code::ok;
    http_message.type = content_type::text_css;

    std::filesystem::path path = app_dir / "app" / css.name;

    if(!std::filesystem::exists(path)) {
        //throw error
    }

    http_message.body = uva::file::read_all_text<char>(path);

    return http_message;
}

uva::networking::web_application::basic_html_template::basic_html_template(std::string &&__file_name, std::map<var,var> &&__locals, const std::string& __controller)
    : file_name(std::forward<std::string&&>(__file_name)), locals(std::forward<std::map<var,var>&&>(__locals)), controller(__controller)
{

}

void uva::networking::web_application::expose_function(std::string name, std::function<std::string(var)> function)
{
    exposed_functions.insert({name, function});
}

std::string stylesheet_path(var params)
{
    if(params.size() != 1)
    {
        throw std::runtime_error("missing argument 1");
    }

    if(params[0].type != var::var_type::string) {
        throw std::runtime_error("argument 1 must by of type string");
    }

    std::string path = params[0];
    std::filesystem::path new_path;

    if(path.starts_with("styles")) {
        new_path = app_dir / "app" / path;
    }

    if(!std::filesystem::exists(new_path)) {
        throw std::runtime_error(std::format("error: cannot find css file '{}'", new_path.string()));
    }

    return std::format("<link rel='stylesheet' href='{}'/>", path);
}

void web_application::init(int argc, const char **argv)
{
    if(!networking::is_initialized()) {
        networking::init(run_mode::async);
    }

    expose_function("stylesheet_path", stylesheet_path);

	size_t port = 3000;
    std::string address = "localhost";

    static std::string port_switch = "--port=";
    static std::string address_switch = "--address=";

    for(size_t i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if(arg.starts_with(port_switch)) {
            port = std::stoi(arg.substr(port_switch.size()));
        } else if(arg.starts_with(address_switch)) {
            address_switch = arg.substr(address_switch.size());
        }
    }
    
	asio::error_code ec;

	asio::ip::tcp::resolver resolver(*io_context);
	asio::ip::basic_resolver_results res = resolver.resolve({ address, std::to_string(port).data() }, ec);
    asio::ip::tcp::endpoint endpoint = asio::ip::tcp::endpoint(*res.begin());

    try {
        m_asioAcceptor = new asio::ip::tcp::acceptor(*io_context, endpoint, port); // Handles new incoming connection attempts...
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
		std::this_thread::sleep_for(std::chrono::milliseconds(16));

        std::vector<std::shared_ptr<web_connection>> seek_connections;

        for(auto& connection : m_connections)
        {
            asio::error_code ec;
            bool is_seek = false;

            if(connection->m_socket.is_open())
            {
                size_t available = connection->m_socket.available(ec);

                if(!ec)
                {
                    if(available)
                    {
                        std::cout << available << " bytes are available to read" << std::endl;
                        proccess_request(connection);
                    }
                    
                    continue;
                }
            }

            seek_connections.push_back(connection);
            log_error("Connection {} was marked as seek.", connection->m_socket.remote_endpoint_string());
        }

        m_connections.erase(std::remove_if(m_connections.begin(), m_connections.end(), [&seek_connections](std::shared_ptr<web_connection>& connection){
            auto it = std::find(seek_connections.begin(), seek_connections.end(), connection);

            if(it != seek_connections.end()) {
                seek_connections.erase(it);
                return true;
            }

            return false;
        }), m_connections.end());
	}
}