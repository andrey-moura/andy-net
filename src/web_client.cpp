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


    m_host = __host.substr(m_protocol.size()+3); //+ "://"
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

void uva::networking::basic_web_client::connect_if_is_not_open_async(std::function<void()> success, std::function<void(error_code&)> on_error)
{
    if(!m_socket.is_open())
    {
        m_socket.connect_async(m_protocol, m_host, [this,success,on_error](error_code ec){

            if(ec)
            {
                on_error(ec);
                on_connection_error(ec);
                return;
            }

            if(m_socket.needs_handshake()) {
                m_socket.async_client_handshake([this,success,on_error](error_code ec){
                    if(ec)
                    {
                        on_error(ec);
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

void uva::networking::basic_web_client::get(const std::string& route, std::map<var, var> params, std::map<var, var> headers, std::function<void(http_message)> on_success, std::function<void(error_code&)> on_error)
{
    connect_if_is_not_open_async([&,this]() {
        if(m_socket.is_open()) {
            write_http_request(m_socket, m_host, route, params, headers, "", [on_success,this]() {
                //on_success(read_http_response(m_socket));
            }, on_error);
        }
    });
}

void uva::networking::basic_web_client::post(const std::string &route, std::map<var, var> body, std::map<var, var> headers, std::function<void(http_message)> on_success, std::function<void(error_code &)> on_error)
{
    connect_if_is_not_open_async([&,this]() {
        if(m_socket.is_open()) {
            std::string content = json::enconde(std::move(body));
            write_http_request(m_socket, m_host, route, {}, headers, "", [on_success,this]() {
                //on_success(read_http_response(m_socket));
            }, on_error);
        }
    });
}

void uva::networking::basic_web_client::on_connection_error(const uva::networking::error_code &ec)
{
    throw std::runtime_error(std::format("An error occurred while trying to establish a connection: {}", ec.message()));
}
