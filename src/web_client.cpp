#include <web_client.hpp>

#include <networking.hpp>
#include <json.hpp>

using namespace uva;
using namespace networking;

uva::networking::basic_web_client::basic_web_client(std::string __host)
{
    if(!uva::networking::is_initialized()) {
        uva::networking::init(run_mode::async);
    }

    bool https = false;

    if(__host.starts_with("http://"))
    {
        m_protocol = "http";
    } else if(__host.starts_with("https://"))
    {
        m_protocol = "https";
    } else {
        throw std::runtime_error(std::format("invalid protocol for '{}'", __host));
    }

    if(__host.ends_with('/')) {
        __host.pop_back();
    }

    m_host = __host.substr(m_protocol.size()+3); //+ "://"

    // m_pipeline_executer = std::make_unique<std::thread>([this](){
    //     while (1) {
    //         m_requests_pipeline.wait();

    //         while(m_requests_pipeline.size()) {
    //             //The message is first pop'ed_back, so in any error, the following request will be processed.
    //             //The pop_back is protected with a mutex, so no write while we read.

    //             web_client_request re(m_requests_pipeline.pop_back());
    //             forward_response(std::move(message));
    //         }
    //     }
    // });
}

uva::networking::basic_web_client::~basic_web_client()
{
    if(m_socket.is_open()) {
        m_socket.close();
    }
}

void uva::networking::basic_web_client::connect_if_is_not_open()
{
    if(!m_socket.is_open())
    {
        error_code ec = m_socket.connect(m_protocol, m_host);

        if(!ec) {
            if(m_socket.needs_handshake()) {
                ec = m_socket.client_handshake();
            }
        }

        if(ec)
        {
            on_connection_error(ec);
        }
    }
}

void uva::networking::basic_web_client::connect_if_is_not_open_async(std::function<void()> success, std::function<void(error_code)> on_error)
{
    if(!m_socket || !m_socket.is_open())
    {
        m_socket.connect_async(m_protocol, m_host, [this,success,on_error](error_code ec){

            if(ec)
            {
                if(on_error) {
                    on_error(ec);
                }
                on_connection_error(ec);
                return;
            }

            if(m_socket.needs_handshake()) {
                m_socket.async_client_handshake([this,success,on_error](error_code ec){
                    if(ec)
                    {
                        if(on_error) {
                            on_error(ec);
                        }
                        on_connection_error(ec);
                        return;
                    }

                    success();    
                });
            } else {
                success();
            }
        });
    } else {
        success();
    }
}

void uva::networking::basic_web_client::enqueue_request(http_message __request, std::function<void(http_message)> __success, std::function<void(error_code)> __error)
{
    web_client_request request;
    request.request = std::move(__request);
    request.error   = __error;
    request.success = __success;

    m_requests_pipeline.push_back(std::move(request));

    if(m_requests_pipeline.size() == 1) {
        write_front_request();
    }
}

void uva::networking::basic_web_client::write_front_request()
{
    connect_if_is_not_open_async([this]() {
        uva::networking::async_write_http_request(m_socket, m_requests_pipeline.front().request, [this]() {

            //TODO:
            //Continue writing the requests, so while the server is working on first request, we're sending others.

            uva::networking::async_read_http_response(m_socket, m_response_buffer, m_buffer, [this](){
                try {
                    m_requests_pipeline.front().success(std::move(m_response_buffer));
                    m_requests_pipeline.consume_front();
                } catch(std::exception e)
                {
                    m_requests_pipeline.consume_front();
                }

                if(m_requests_pipeline.size()) {
                    write_front_request();
                }
            });

        },  m_requests_pipeline.front().error);
    });
}

void uva::networking::basic_web_client::get(const std::string& route, std::map<var, var> params, std::map<var, var> headers, std::function<void(http_message)> on_success, std::function<void(error_code)> on_error)
{
    http_message request;
    request.method = "GET";
    request.url = route;
    request.params = std::move(params);
    request.headers = std::move(headers);
    request.type = content_type::text_html;
    request.host = m_host;

    enqueue_request(std::move(request), on_success, on_error);
}

void uva::networking::basic_web_client::post(const std::string &route, std::map<var, var> body, std::map<var, var> headers, std::function<void(http_message)> on_success, std::function<void(error_code)> on_error)
{
    std::string content = json::enconde(std::move(body));

    http_message request;
    request.method = "POST";
    request.url = route;
    request.raw_body = content;
    request.type = content_type::application_json;
    request.params = std::map<var, var>();
    request.headers = std::move(headers);
    request.host = m_host;

    enqueue_request(std::move(request), on_success, on_error);
}

void uva::networking::basic_web_client::post(const std::string &route, std::string body, content_type type, std::map<var, var> headers, std::function<void(http_message)> on_success, std::function<void(error_code)> on_error)
{
    http_message request;
    request.method = "POST";
    request.url = route;
    request.raw_body = std::move(body);
    request.type = type;
    request.params = std::map<var, var>();
    request.headers = std::move(headers);
    request.host = m_host;

    enqueue_request(std::move(request), on_success, on_error);
}

void uva::networking::basic_web_client::on_connection_error(const uva::networking::error_code &ec)
{
    throw std::runtime_error(std::format("An error occurred while trying to establish a connection: {}", ec.message()));
}
