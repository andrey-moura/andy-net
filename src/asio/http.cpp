#include <iostream>

#include <andy/net/http.hpp>

#define ASIO_STANDALONE
#ifdef _WIN32
#   ifndef _WIN32_WINNT
#      define _WIN32_WINNT 0x0601  // Minimum Windows version is Windows 7
#   endif
#endif

#include <asio.hpp>

namespace andy
{
    namespace net
    {
        namespace http
        {
            static void read_until(asio::ip::tcp::socket& socket, char delimiter, std::string& out)
            {
                asio::error_code ec;
                uint8_t byte_read;
                while(asio::read(socket, asio::buffer(&byte_read, 1), ec))
                {
                    if(ec) {
                        throw asio::system_error(ec);
                    }

                    if(byte_read == delimiter)
                    {
                        break;
                    }

                    out.push_back(byte_read);
                }
            }

            static std::string read_word(asio::ip::tcp::socket& socket)
            {
                asio::error_code ec;

                std::string word;
                word.reserve(8);

                read_until(socket, ' ', word);

                return word;
            }

            static std::string read_line(asio::ip::tcp::socket& socket)
            {
                asio::error_code ec;

                std::string line;
                line.reserve(32);

                read_until(socket, '\n', line);

                line.pop_back(); // Remove the \r

                return line;
            }

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
                asio::write(socket, asio::buffer(request));

                char response_first_5_bytes[5];
                asio::error_code ec;
                if(asio::read(socket, asio::buffer(response_first_5_bytes), asio::transfer_exactly(5), ec) != 5)
                {
                    throw std::runtime_error("Failed to read first 5 bytes of HTTP response: " + ec.message());
                }

                if(std::strncmp(response_first_5_bytes, "HTTP/", 5) != 0)
                {
                    throw std::runtime_error("Invalid HTTP response not starting with 'HTTP/'. Starting with: " + std::string(response_first_5_bytes, 5));
                }

                std::string http_version = read_word(socket);

                if(http_version != "1.1" && http_version != "1.0")
                {
                    throw std::runtime_error("Unsupported HTTP version: " + http_version);
                }

                std::string status_code_str = read_word(socket);

                if(status_code_str.size() != 3)
                {
                    throw std::runtime_error("Invalid HTTP status code: " + status_code_str);
                }

                size_t index;
                res.status_code = std::stoi(status_code_str, &index);

                if (index != status_code_str.size())
                {
                    throw std::runtime_error("Invalid HTTP status code: " + status_code_str);
                }

                res.status_text = read_line(socket);
                std::string header_line = read_line(socket);
                do
                {
                    res.header_lines.push_back(header_line);

                    size_t key_end = header_line.find(":");
                    if (key_end != header_line.npos)
                    {
                        std::string_view key(res.header_lines.back().data(), key_end);
                        std::string_view value(res.header_lines.back().data() + key_end + 2, res.header_lines.back().data() + res.header_lines.back().size());
                        res.headers[key] = value;
                    }
                    // Next header line
                    header_line = read_line(socket);
                } while(header_line.size());

                std::string_view content_length_header = res.headers["Content-Length"];

                if (content_length_header.size()) {
                    size_t index;
                    size_t content_length = std::stoul(std::string(content_length_header), &index);

                    if (index != content_length_header.size()) {
                        throw std::runtime_error("Invalid Content-Length header: " + std::string(content_length_header));
                    }

                    res.raw_body.resize(content_length);

                    asio::error_code ec;
                    asio::read(socket, asio::buffer(res.raw_body), asio::transfer_exactly(content_length), ec);

                    if (ec) {
                        throw std::runtime_error("Failed to read HTTP response body: " + ec.message());
                    }
                }

                return res;
            }
        };
    };
};