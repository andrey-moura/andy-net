#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <functional>
#include <cstdint>

namespace andy
{
    namespace net
    {
        namespace http
        {
            struct response
            {
public:
                response() = default;
                response(response&& other);
                ~response() = default;
public:
                int status_code;
                std::string status_text;
                std::vector<std::string> header_lines;
                std::map<std::string_view, std::string_view> headers;
                std::vector<uint8_t> raw_body;

                std::string_view text();

                bool is_text() const;
            };
        };
    };
};