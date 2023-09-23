#include <thread>
#include <map>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <atomic>
#include <deque>

#include <asio.hpp>

#ifdef __UVA_OPENSSL_FOUND__
    #include <asio/ssl.hpp>
#endif

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

void proccess_request(std::shared_ptr<web_connection> connection, bool new_connection = false);
asio::ip::tcp::acceptor* m_asioAcceptor = nullptr;

std::map<std::string, std::function<std::string(var)>> exposed_functions;

using http_message_pipeline = uva::networking::basic_thread_safe_pipeline_waiter<http_message>;
http_message_pipeline m_deque;

class web_connection : public basic_connection, public std::enable_shared_from_this<web_connection>
{
private:
    http_message m_request;
    std::deque<http_message> m_response_deque;

    asio::streambuf m_buffer;
    basic_socket m_socket;
    bool m_seek = false;
    std::mutex m_mutex;
public:
    web_connection(basic_socket&& socket);
public:
    bool is_seek();
    void read_request();
    void write_response(http_message&& message);
    void close();

    std::shared_ptr<web_connection> get_shared_pointer();
private:
    void write_front_response();
public:
};

web_connection::web_connection(basic_socket&& socket)
    : m_socket(std::forward<basic_socket&&>(socket))
{
    if(m_socket.needs_handshake()) {
        m_socket.async_server_handshake([this](uva::networking::error_code ec){
            if (ec) {
                m_seek = true;
            } else {
                read_request();
                m_seek = false;
            }
        });
    } else {
        read_request();
        m_seek = false;
    }
}

bool web_connection::is_seek()
{
    //Called from another thread
    std::scoped_lock lock(m_mutex);
    return m_seek;
}

void web_connection::read_request()
{
    networking::async_read_http_request(m_socket, m_request, m_buffer, [this]() {
        std::scoped_lock lock(m_mutex);

        m_request.connection = this;
        m_deque.push_back(std::move(m_request));

        //Haven't we came here before?
        read_request();
    });
} 

void web_connection::close()
{
    std::scoped_lock lock(m_mutex);
    m_socket.close();
}

std::shared_ptr<web_connection> web_connection::get_shared_pointer()
{
    std::scoped_lock lock(m_mutex);
    return shared_from_this();
}

void web_connection::write_response(http_message&& message)
{
    std::scoped_lock lock(m_mutex);
    m_response_deque.push_back(std::move(message));

    if(m_response_deque.size() == 1) {
        write_front_response();
    }
}

void web_connection::write_front_response()
{
    /* The scope is already locked by write_response */
    const http_message& response = m_response_deque.front();

    async_write_http_response(m_socket, response.raw_body, response.status, response.type, [this](uva::networking::error_code ec) {
        m_response_deque.pop_front();

        if(m_response_deque.size()) {
            write_front_response();
        }
    });
}

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

void write_404_http_message(std::shared_ptr<web_connection> connection)
{
    http_message message;
    message.raw_body = s_not_found_page;
    message.status = status_code::not_found;
    message.type = content_type::text_html;
    connection->write_response(std::move(message));
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

std::string parse_string_from_web(std::string_view sv)
{
    std::string str;
    str.reserve(sv.size());

    while(sv.size()) {
        decode_char_from_web(sv, str);
    }

    return str;
}

void proccess_request(http_message request)
{
    uva::networking::content_type initialized_type = (uva::networking::content_type)-1;
    current_response.type = initialized_type;
    current_response.status = status_code::no_content;
    current_response.raw_body = "";

    format_on_cout("\n\nStarted {} {} for {} with params:\n{}\nand headers: {}", request.method, request.url, request.endpoint, request.params.to_s(), request.headers.to_s());

    /*An HTTP/1.1 server MAY assume that a HTTP/1.1 client intends to
    maintain a persistent connection unless a Connection header including
    the connection-token "close" was sent in the request.*/

    bool should_close = false;
    if(request.headers["Connection"] == "close") {
        should_close = true;
    }

    //asking asset
    if(request.url.ends_with(".css")) {
        respond css_file(request.url);

        request.connection->write_response(std::move(current_response));
    } else {
        //Todo: documentation and refatoration for files
        std::string relative = parse_string_from_web(request.url);

        if(relative.starts_with('/') || relative.starts_with('\\')) {
            relative.erase(0, 1);
        }

        std::filesystem::path path = (app_dir / "app" / relative).make_preferred();

        if(request.url.find('.') != std::string::npos && std::filesystem::exists(path)) {
            //generated using OpenAI
            //Gere um std::map onde as keys são extensão de arquivos e o valor são MIME Type. Faça isso para os valores mais comuns para o MIME type
            std::map<std::string, std::string> mime_types {
                {".css",  "text/css"},
                {".js",   "application/javascript"},
                {".json", "application/json"},
                {".pdf",  "application/pdf"},
                {".jpg",  "image/jpeg"},
                {".jpeg", "image/jpeg"},
                {".png",  "image/png"},
                {".gif",  "image/gif"},
                {".svg",  "image/svg+xml"},
                {".mp4",  "video/mp4"},
                {".webm", "video/webm"},
                {".mpd",  "video/mp4"},
                {".m4s",  "video/m4s"},
                {".ogg",  "audio/ogg"},
                {".mp3",  "audio/mpeg"},
                {".wav",  "audio/wav"},
                {".txt",  "text/plain"}
            };

            std::string ext = path.extension().string();
            auto it = mime_types.find(uva::string::tolower(ext));
            
            if(it == mime_types.end()) {
                respond html_template_for_controller("web_application_controller", "error", {
                    { "error_type", "Filesystem Error" },
                    { "error_title", "File Not Found" },
                    { "error_description", std::format("The file {} has invalid extension.", ext) },
                }) with_status status_code::not_found;
            } else {
                current_response.headers = var::map();
                current_response.headers["Content-type"] = it->second;
                current_response.status = status_code::ok;
                current_response.type = content_type_from_string(it->second);
                current_response.raw_body = uva::file::read_all_text<char>(path);
            }

            request.connection->write_response(std::move(current_response));
        } else {

            std::string route = request.url;

            if(route.size() > 1 && route.front() == '/')  {
                route = route.substr(1);
            }

            route = request.method + " " + route;

            try {
                basic_action_target target = find_dispatch_target(route, request.connection->get_shared_pointer());
                if(target.controller) {
                    std::string action = target.action;
                    {
                        std::shared_ptr<basic_web_controller> web_controller = std::dynamic_pointer_cast<web_application::basic_web_controller>(target.controller);
                        if(web_controller) {
                            //Following lines are generating exceptions
                            var params = request.params;
                            for(auto pair : target.controller->params.as<var::var_type::map>()) {
                                params[pair.first] = pair.second;
                            }
                            target.controller->params = std::move(params);
                            web_controller->request = std::move(request);

                            //Clear locals just in case
                            web_controller->locals.clear();

                            dispatch(target, request.connection->get_shared_pointer());

                            //no render called
                            if(current_response.type == initialized_type) {

                                auto locals = web_controller->locals.as<var::var_type::map>();

                                respond html_template_for_controller(web_controller->name, std::move(action), std::move(locals) )
                                        with_status status_code::ok;
                            }

                            //Clear locals
                            web_controller->locals.clear();
                        } else {
                            respond html_template_for_controller("web_application_controller", "error", {
                                { "error_type", "Implementation Error" },
                                { "error_title", "Cannot Cast To <i>uva::networking::web_application::basic_web_controller</i>" },
                                { "error_description", std::format("Class <i>{}<i/> cannot be casted to <i>basic_web_controller</i>. "
                                                                        "Maybe have you forgotten to derive from <i>basic_web_controller<i> in your controller "
                                                                        "definition or declared it as a private base class?", target.controller->name) },
                            }) with_status status_code::internal_server_error;
                        }
                    }
                } else {
                    respond html_template_for_controller("web_application_controller", "error", {
                        { "error_type", "Routing Error" },
                        { "error_title", "Route Not Found" },
                        { "error_description", std::format("No Route Matches {}", route) },
                    }) with_status status_code::not_found;
                }

                request.connection->write_response(std::move(current_response));
            } catch(std::exception e)
            {
                //write 500 response
                log_error("Exception during dispatch: {}", e.what());

                respond html_template_for_controller("web_application_controller", "error", {
                    { "error_type", "Unhandled Exception" },
                    { "error_title", "Unhandled Exception" },
                    { "error_description", std::format("An unhandled exception has been caught: {}", e.what()) },
                }) with_status status_code::internal_server_error;

                request.connection->write_response(std::move(current_response));
            }
        }
    }

    if(should_close) {
        request.connection->close();
    }

    return;
}

void acceptor(asio::ip::tcp::acceptor& asioAcceptor, protocol __protocol) {
	asioAcceptor.async_accept([&asioAcceptor, __protocol](std::error_code ec, asio::ip::tcp::socket socket)
	{
		// Triggered by incoming connection request
		if (!ec)
		{
	        std::cout << "New Connection: " << socket.remote_endpoint() << std::endl;
            m_connections.push_back(std::make_shared<web_connection>(std::move(basic_socket(std::move(socket), __protocol))));

            //log("Connection accepted with {} bytes available to read.", m_connections.back()->m_socket.available());
            //proccess_request(m_connections.back(), true);
		}
		else
		{
			// Error has occurred during acceptance
			std::cout << "[SERVER] New Connection Error: " << ec.message() << std::endl;
		}

		acceptor(asioAcceptor, __protocol);
	});
}

static std::vector<std::string> html_template_extensions = { "cpp.html", "html" };

std::filesystem::path folder_for_controller_templates(const std::string& __controller)
{
    std::string controller;

    std::string sufix = "_controller";

    if(__controller.ends_with(sufix)) {
        controller = __controller.substr(0, __controller.size()-sufix.size());
    } else {
        controller = __controller;
    }

    return app_dir / "app" / "views" / controller;
}

std::string find_html_file(const std::string& __controller, const std::string& name)
{
    std::filesystem::path folder = folder_for_controller_templates(__controller);
    std::filesystem::path file   = folder / name;

    for(const std::string& extension : html_template_extensions) {
        std::filesystem::path possibility = file;
        possibility.replace_extension(extension);

        if(std::filesystem::exists(possibility)) {
            return possibility.string();
        }
    }

    return "";
}

std::string render_html_template(const std::string& html)
{
    std::string application_html_file_path = find_html_file("application", "application");

    if(application_html_file_path.empty()) {
        return html;
    }

    std::string content = uva::file::read_all_text<char>(application_html_file_path);

    static std::string render_tag = "<render>";
    static std::string close_render_tag = "</render>";

    std::string_view content_view = content;
    std::string formated_content;
    formated_content.reserve(content.size()+html.size()+1024);

    while(content_view.size())
    {
        char c = content_view.front();

        if(c == '<') {
            if(content_view.starts_with(render_tag))
            {
                formated_content += html;
                content_view.remove_prefix(render_tag.size());
                continue;
            } else if(content_view.starts_with(close_render_tag)) {
                content_view.remove_prefix(close_render_tag.size());
                continue;
            }
        }

        formated_content.push_back(content_view.front());
        content_view.remove_prefix(1);
    }

    return formated_content;
}

std::string format_html_file(const std::string& path, const var& locals)
{
    std::string buffer;
    buffer.reserve(256);

    static std::string var_tag = "<var>";
    static std::string close_var_tag = "</var>";

    //<if current_user_is_master>
    static std::string if_tag = "<if ";
    static std::string close_if_tag = "</if>";

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

                    if(value != null)
                    {
                        if(value.type == var::var_type::string) {
                            formated_content += value.as<var::var_type::string>();
                        }
                        else {
                            formated_content += value.to_typed_s('[', ']');
                        }
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
        } else if(formated_content.ends_with(if_tag))
        {
            buffer.clear();

            formated_content.resize(formated_content.size()-if_tag.size());

            while(isspace(content[index])) {
                ++index;
            }

            while(!isspace(content[index]) && content[index] != '>') {
                buffer.push_back(content[index]);
                ++index;
            }

            while(isspace(content[index])) {
                ++index;
            }

            if(content[index] != '>') {
                throw std::runtime_error(std::format("error: unexpected sequence after if condition"));
            }

            ++index;

            var value = locals.fetch(buffer);

            bool has_met_condition = (bool)value;

            std::string_view content_view(content.c_str() + index, content.size()-index);

            while(!content_view.starts_with(close_if_tag)) {
                if(has_met_condition) {
                    formated_content.push_back(content[index]);
                }
                content_view.remove_prefix(1);
                ++index;
            }

            index += close_var_tag.size();
        }
        else {
            formated_content.push_back(content[index]);
        }

        index++;
    }

    return render_html_template(formated_content);
}

http_message& uva::networking::operator+=(http_message& http_message, std::map<var,var>&& __body)
{
    http_message.status = status_code::ok;
    http_message.raw_body = uva::json::enconde(var(std::move(__body)));
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
        // respond html_template("error", {
        //     { "error_type", "Implementation Error" },
        //     { "error_title", "Cannot find template for action <i>{}</i> in <i>{}</i>" },
        //     { "error_description", std::format("A template with name <i>{}</i> was expected to exists in <i>{}</i>.<br/>"
        //                                             "Tried the following extensions: [<i>{}</i>] <br/>"
        //                                             "Maybe have you forgotten to create the template file?", __template.file_name, __template.controller,
        //                                                                                                      __template.file_name, folder_for_controller_templates(__template.controller),
        //                                                                                                      uva::string::join(uva::string::map(html_template_extensions, [](const std::string& ext){ return "\"" + ext + "\"" }), ", ")) },
        // }) with_status status_code::internal_server_error;

        respond html_template_for_controller("web_application_controller", "error", {
            { "error_type", "Implementation Error" },
            { "error_title", std::format("Cannot find template for action <i>{}</i> in <i>{}</i>", __template.file_name, __template.controller) },
            { "error_description", std::format("A template with name <i>{}</i> was expected to exists in <i>{}</i>.<br/>"
                                               "Tried the following extensions: [<i>{}</i>] <br/>", __template.file_name,
                                                                                                    folder_for_controller_templates(__template.controller).string(),
                                                                                                    uva::string::join(
                                                                                                        uva::string::map(html_template_extensions,
                                                                                                                            [](const std::string& ext){
                                                                                                                                return "\"" + ext + "\"";
                                                                                                                            }),
                                                                                                                    ", ")
                                                                                                    )}
        }) with_status status_code::internal_server_error;
    } else {
        http_message.raw_body = format_html_file(path, __template.locals); 
    }

    return http_message;
}

http_message &uva::networking::operator<<(http_message &http_message, const web_application::basic_css_file &css)
{
    http_message.status = status_code::ok;
    http_message.type = content_type::text_css;

    std::string test = app_dir.string();

    if(css.name.starts_with('/') || css.name.starts_with('\\')) {
        const_cast<web_application::basic_css_file&>(css).name.erase(0, 1);
    }

    std::filesystem::path path = app_dir / "app" / css.name;

    if(!std::filesystem::exists(path)) {
        
    }

    http_message.raw_body = uva::file::read_all_text<char>(path);

    return http_message;
}

http_message &uva::networking::redirect_to(const std::string &url, const var &params)
{
    current_response.status = status_code::moved;
    current_response.type   = content_type::text_html;
    current_response.headers = var::map({ { "Location", url } });
    return current_response;
}

uva::networking::web_application::basic_html_template::basic_html_template(std::string &&__file_name, std::map<var,var> &&__locals, const std::string& __controller)
    : file_name(std::forward<std::string&&>(__file_name)), locals(std::forward<std::map<var,var>&&>(__locals)), controller(__controller)
{

}

uva::networking::web_application::basic_html_template::basic_html_template(std::string &&__file_name, std::shared_ptr<basic_web_controller> __controller)
    : file_name(std::forward<std::string&&>(__file_name)), locals(__controller->locals), controller(__controller->name)
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

	std::string port = "3000";
    std::string address = "localhost";

    static std::string port_switch = "--port=";
    static std::string address_switch = "--address=";

    for(size_t i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if(arg.starts_with(port_switch)) {
            port = arg.substr(port_switch.size());
        }
        else if(arg.starts_with(address_switch)) {
            address = arg.substr(address_switch.size());
        }
    }

    try {
        if(address.size()) {
            asio::error_code ec;

            asio::ip::tcp::resolver resolver(*io_context);
            asio::ip::basic_resolver_results res = resolver.resolve({ address, port.data() }, ec);
            asio::ip::tcp::endpoint endpoint = asio::ip::tcp::endpoint(*res.begin());

            m_asioAcceptor = new asio::ip::tcp::acceptor(*io_context, endpoint);
        } else {
            m_asioAcceptor = new asio::ip::tcp::acceptor(*io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), std::stoi(port)));
        }
    } catch(std::exception& e)
    {
        log_error("Failed to start listening: {}", e.what());
        return;
    }
    
    if(port == "443"  || port == "https") {
	    acceptor(*m_asioAcceptor, protocol::https);
    } else {
        acceptor(*m_asioAcceptor, protocol::http);
    }

    log_success("Started listening in {} ({})", address, m_asioAcceptor->local_endpoint().address().to_string());

	while (1) {
        m_deque.wait();

        while(m_deque.size()) {
            //The message is first pop'ed_back, so in any error, the following request will be processed.
            //The pop_back is protected with a mutex, so no write while we read.

            http_message message(m_deque.pop_back());
            proccess_request(std::move(message));
        }
	}
}