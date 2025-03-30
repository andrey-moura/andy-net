#include <iostream>

#include <andy/net/http.hpp>

#define ASIO_STANDALONE
#include <asio.hpp>

namespace andy
{
    namespace net
    {
        namespace http
        {
            response get(std::string_view url)
            {
                std::string_view port;
                std::string_view host;
                std::string_view path;
                size_t host_size = 0;
                if(url.starts_with("http://"))
                {
                    port = "80";
                    url.remove_prefix(7);
                } else if(url.starts_with("https://"))
                {
                    port = "443";
                    url.remove_prefix(8);
                }
                while(host_size < url.size() && url[host_size] != '/')
                {
                    host_size++;
                }
                host = url.substr(0, host_size);
                path = url.substr(host_size);
                // std::cout << "host: " << host << std::endl;
                // std::cout << "path: " << path << std::endl;
                // std::cout << "port: " << port << std::endl;
                response res;
                asio::io_context io_context;
                asio::ip::tcp::resolver resolver(io_context);
                asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(host, "http");
                asio::ip::tcp::socket socket(io_context);
                asio::connect(socket, endpoints);
                std::string request;
                request.reserve(url.size() + 60);
                request.append("GET ");
                request.append(path);
                request.append(" HTTP/1.1\r\nHost: ");
                request.append(host);
                request.append("\r\nConnection: close\r\n\r\n");
                //std::cout << request << std::endl;
                asio::write(socket, asio::buffer(request));
                asio::streambuf streambuf;
                asio::read_until(socket, streambuf, "\r\n");
                std::string_view response_line(asio::buffer_cast<const char*>(streambuf.data()), streambuf.size());
                //std::cout << response_line << std::endl;
                if (response_line.substr(0, 9) == "HTTP/1.1 ")
                {
                    res.status_code = std::stoi(std::string(response_line.substr(9, 3)));
                }
                //std::string content;
                //asio::read(socket, streambuf, asio::transfer_all());
                //std::cout << asio::buffer_cast<const char*>(streambuf.data()) << std::endl;
                return res;
            }
        };
    };
};