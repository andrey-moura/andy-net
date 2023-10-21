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
#include <time.hpp>

using namespace uva;
using namespace console;
using namespace networking;
using namespace routing;
using namespace web_application;

http_message web_application::current_response;

std::string name = "web_application";

class web_connection;

bool next_non_white_space1(std::string_view& sv) {
    while(sv.size() && isspace(sv[0])) {
        sv.remove_prefix(1);
    }

    return sv.size();
}

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
    http_message& response = m_response_deque.front();

    async_write_http_response(m_socket, response, [this](uva::networking::error_code ec) {
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

    format_on_cout("\n\nStarted {} {} for {} at {}\nparams:\n{}\nheaders: {}", request.method, request.url, request.endpoint, time::iso_now(), request.params.to_s(), request.headers.to_s());

    /*An HTTP/1.1 server MAY assume that a HTTP/1.1 client intends to
    maintain a persistent connection unless a Connection header including
    the connection-token "close" was sent in the request.*/

    bool should_close = false;
    if(request.headers["Connection"] == "close") {
        should_close = true;
    }

    //Todo: documentation and refactoration for files
    std::string relative = parse_string_from_web(request.url);

    if(relative.starts_with('/') || relative.starts_with('\\')) {
        relative.erase(0, 1);
    }

    if(relative.starts_with("public/")) {
        std::filesystem::path path = (app_dir / "app" / relative).make_preferred();

        if(std::filesystem::exists(path)) {
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
            respond html_template_for_controller("web_application_controller", "error", {
                { "error_type", "Filesystem Error" },
                { "error_title", "File Not Found" },
                { "error_description", std::format("The requested file '{}' can not be found.", request.url) },
            }) with_status status_code::not_found;

            request.connection->write_response(std::move(current_response));
        }
    } else
    {
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
                        for(auto pair : target.controller->params.as<var::map>()) {
                            params[pair.first] = pair.second;
                        }

                        var::map_type cookies;

                        if(request.headers && request.headers.is_a<var::map>()) {
                            auto& headers_map = request.headers.as<var::map>();

                            auto it = headers_map.find("Cookie");

                            if(it != headers_map.end()) {
                                var cookie_var_str = std::move(it->second);
                                headers_map.erase(it);

                                if(cookie_var_str.is_a<var::string>()) {
                                    std::string cookie_str = std::move(cookie_var_str.as<var::string>());

                                    std::string_view cookie_str_view = cookie_str;

                                    std::string key;
                                    std::string value;

                                    while(cookie_str_view.size()) {
                                        key.clear();
                                        value.clear();

                                        next_non_white_space1(cookie_str_view);

                                        while(cookie_str_view.size() && cookie_str_view[0] != '=') {
                                            key.push_back(cookie_str_view.front());
                                            cookie_str_view.remove_prefix(1);
                                        }

                                        if(!key.size()) {
                                            break;
                                        }

                                        if(cookie_str_view.size()) {
                                            cookie_str_view.remove_prefix(1);
                                        }

                                        next_non_white_space1(cookie_str_view);

                                        while(cookie_str_view.size() && cookie_str_view[0] != ';') {
                                            value.push_back(cookie_str_view.front());
                                            cookie_str_view.remove_prefix(1);
                                        }

                                        if(cookie_str_view.size()) {
                                            cookie_str_view.remove_prefix(1);
                                        }

                                        next_non_white_space1(cookie_str_view);

                                        cookies[key] = value;
                                    }
                                }
                            }
                        }

                        target.controller->params = std::move(params);
                        web_controller->request = std::move(request);
                        web_controller->cookies = std::move(cookies);

                        //Clear locals just in case
                        web_controller->locals.clear();

                        dispatch(target, request.connection->get_shared_pointer());

                        //no render called
                        if(current_response.type == initialized_type) {

                            auto locals = web_controller->locals.as<var::map>();

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
        } catch(std::exception& e)
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

std::string format_html_file(const std::string& path, var& locals);

std::string render_html_template(const std::string& path, var& locals)
{
    std::string formatted_html = format_html_file(path, locals);

    std::string application_html_file_path = find_html_file("application", "application");

    if(application_html_file_path.empty()) {
        return formatted_html;
    }

    std::string content = format_html_file(application_html_file_path, locals);

    static std::string render_tag = "<render>";
    static std::string close_render_tag = "</render>";

    std::string_view content_view = content;
    std::string formated_content;
    formated_content.reserve(content.size()+formatted_html.size()+1024);

    while(content_view.size())
    {
        char c = content_view.front();

        if(c == '<') {
            if(content_view.starts_with(render_tag))
            {
                formated_content += formatted_html;
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

std::string format_html_content(std::string_view content, var& locals);

void locals_render(std::string_view keyword_open, std::string_view keyword_attributes, std::string_view keyword_content, std::string& output_html, var& locals)
{
    var value;
    std::string path;

    while(keyword_content.size())
    {
        path.push_back(keyword_content.front());

        if(path.ends_with('.')) {
            path.pop_back();

            if(value.is_null()) {
                value = locals.fetch(path);
            } else {
                value = value.fetch(path);
            }

            path.clear();
        }

        keyword_content.remove_prefix(1);
    }

    if(value.is_null()) {
        value = locals.fetch(path);
    } else {
        value = value.fetch(path);
    }

    if(value != null)
    {
        if(value.is_a<var::string>()) {
            output_html += value.as<var::string>();
        }
        else {
            output_html += value.to_typed_s('[', ']');
        }
    }
}

std::string_view extract_word(std::string_view& sv)
{
    size_t word_size = 0;

    while(word_size < sv.size()) {
        if(isspace(sv[word_size])) {
            break;
        }

        ++word_size;
    }
   
    std::string_view word = sv.substr(0, word_size);
    sv = sv.substr(word_size);

    return word;
}

void foreach_render(std::string_view keyword_open, std::string_view keyword_attributes, std::string_view keyword_content, std::string& output_html, var& locals)
{
    //<foreach product : products >
    
    if(!next_non_white_space1(keyword_attributes)) {
        //exception
        return;
    }

    std::string_view iterator_name = extract_word(keyword_attributes);

    if(!next_non_white_space1(keyword_attributes)) {
        //exception
        return;
    }

    std::string_view in = extract_word(keyword_attributes);

    if(in.empty() || in != "in") {
        //exception
        return;
    }

    if(!next_non_white_space1(keyword_attributes)) {
        //exception
        return;
    }

    std::string_view variable_name = extract_word(keyword_attributes);

    var variable = locals.fetch(std::string(variable_name));

    struct foreach_render_data {
        std::string& __output_html;
        std::string_view& __keyword_content;
        std::string __iterator_name;
        var& __locals;
    };

    foreach_render_data data = {
        output_html,
        keyword_content,
        std::string(iterator_name),
        locals
    };

    variable.for_each<var>([](var& value, void* void_data) {
       foreach_render_data* pData = (foreach_render_data*)void_data;

       pData->__locals[pData->__iterator_name] = value;

       std::string formatted_keyword_content = format_html_content(pData->__keyword_content, pData->__locals);
        pData->__output_html += formatted_keyword_content;
    }, (void*)&data);
}

void component_render(std::string_view keyword_open, std::string_view keyword_attributes, std::string_view keyword_content, std::string& output_html, var& locals)
{
    std::string_view component_name = keyword_open;

    while(component_name.size() && !component_name.ends_with('-')) {
        component_name.remove_suffix(1);
    }

    if(!component_name.ends_with('-')) {
        //exception
        return;
    }

    component_name.remove_suffix(1);

    auto component_path = app_dir / "app" / "views" / "components" / component_name;
    component_path.replace_extension(".cpp.html");

    std::string component_path_string = component_path;

    if(std::filesystem::exists(component_path_string)) {
        std::string component = format_html_file(component_path, locals);
        output_html.append(component);
    } else {
        //exception
        return;
    }
}

typedef void(*reserved_keyword_render)(std::string_view keyword_open, std::string_view keyword_attributes, std::string_view keyword_content, std::string& output_html, var& locals);

struct reserved_keywords
{
    reserved_keywords(std::string __tag, reserved_keyword_render __render, bool __is_suffix = false)
        :
        tag(__tag),
        render(__render),
        is_suffix(__is_suffix)
    {

    }

    std::string tag;
    bool is_suffix = false;

    reserved_keyword_render render;
};

std::string format_html_content(std::string_view content_view, var& locals)
{
    std::string formated_content;
    formated_content.reserve(content_view.size());

    std::string tag_name;
    tag_name.reserve(128);

    std::vector<reserved_keywords> keywords = {
        { "locals",     locals_render          },
        { "foreach",    foreach_render         },
        { "-component", component_render, true },
    };

    size_t last_open_tag = std::string::npos;

    while(content_view.size())
    {
        while(content_view.size() && content_view[0] != '<') {
            //if(content_view[0] == '<') {
                //last_open_tag = content_view.data() - content.data();
            //}

            formated_content.push_back(content_view[0]);
            content_view.remove_prefix(1);
        }

        //prevent waste of time when the next character is '/' ( </ )
        if(content_view.size() > 1 && content_view[1] != '/') {
            std::string_view possible_keyword_view = content_view;
            possible_keyword_view.remove_prefix(1);

            size_t tag_name_size = 0;
            while(possible_keyword_view.size() && (isalpha(possible_keyword_view[tag_name_size]) || possible_keyword_view[tag_name_size] == '-' )) {
                tag_name_size++;
            }

            possible_keyword_view = possible_keyword_view.substr(0, tag_name_size);

            for(size_t keyword_index = 0; keyword_index < keywords.size(); ++keyword_index) {
                if((keywords[keyword_index].is_suffix && possible_keyword_view.ends_with(keywords[keyword_index].tag)) || possible_keyword_view.starts_with(keywords[keyword_index].tag)) {
                    std::string_view keyword_content_view = content_view;
                    keyword_content_view.remove_prefix(tag_name_size + 1); // + '<'

                    std::string_view keyword_attributes_view = keyword_content_view;

                    while(keyword_content_view.size()) {

                        if(keyword_content_view.starts_with('>')) {
                            keyword_content_view.remove_prefix(1);
                            break;
                        }

                        keyword_content_view.remove_prefix(1);
                    }

                    keyword_attributes_view = std::string_view(keyword_attributes_view.data(), keyword_content_view.data() - keyword_attributes_view.data());
                    keyword_attributes_view.remove_suffix(1); // remove the > left above

                    std::string keyword_close = "</";
                    keyword_close.append(std::string(possible_keyword_view));

                    std::string_view possible_keyword_close = keyword_content_view;

                    while(possible_keyword_close.size()) {
                        if(possible_keyword_close.size() > 1 && possible_keyword_close[0] == '<' && possible_keyword_close[1] == '/') {
                            if(possible_keyword_close.starts_with(keyword_close)) {
                                break;
                            }
                        }

                        possible_keyword_close.remove_prefix(1);
                    }

                    keyword_content_view = std::string_view(keyword_content_view.data(), possible_keyword_close.data() - keyword_content_view.data());

                    content_view = possible_keyword_close;

                    content_view.remove_prefix(2 + tag_name_size); //</ + tag_name

                    while(content_view.size() && content_view[0] != '>') {
                        if(!isspace(content_view[0])) {
                            //exception
                        }

                        content_view.remove_prefix(1);
                    }

                    if(content_view.size()) {
                        content_view.remove_prefix(1); //remove >
                    }

                    reserved_keyword_render render = keywords[keyword_index].render;
                    render(possible_keyword_view, keyword_attributes_view, keyword_content_view, formated_content, locals);
                }
            }
        }

        if(content_view.size()) {
            formated_content.push_back(content_view[0]);
            content_view.remove_prefix(1);
        }
    }

    return formated_content;
}

std::string format_html_file(const std::string& path, var& locals)
{
    std::string content = uva::file::read_all_text<char>(path);

    const std::string template_extension = ".cpp.html";

    if(!path.ends_with(template_extension)) {
        return content;
    }

    content = format_html_content(content, locals);
    return content;
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
        http_message.raw_body = render_html_template(path, const_cast<var&>(__template.locals)); 
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
    current_response.status = status_code::found;
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

    if(!params[0].is_a<var::string>()) {
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