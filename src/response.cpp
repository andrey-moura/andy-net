#include "andy/net/http/response.hpp"

#include <stdexcept>

namespace andy
{
    namespace net
    {
        namespace http
        {
            response::response(response&& other)
            {
                status_code = other.status_code;
                status_text = std::move(other.status_text);
                header_lines = std::move(other.header_lines);
                headers = std::move(other.headers);
                raw_body = std::move(other.raw_body);
            }

            std::string_view response::text()
            {
                std::string_view content_type = headers["Content-Type"];

                if(!content_type.starts_with("text/plain") && !content_type.starts_with("text/html"))
                {
                    throw std::runtime_error("Trying to access response body as text, but Content-Type is not text/plain or text/html");
                }

                if(!raw_body.size()) {
                    return "";
                }

                return std::string_view(reinterpret_cast<const char*>(raw_body.data()), raw_body.size());
            }

            bool response::is_text() const
            {
                std::string_view content_type = headers.at("Content-Type");
                return content_type.starts_with("text/plain") || content_type.starts_with("text/html");
            }
        };
    };
};