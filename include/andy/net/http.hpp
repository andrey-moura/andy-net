#pragma once

#include <string_view>

#include <andy/net/http/response.hpp>

namespace lavi
{
    namespace net
    {
        namespace http
        {
            response get(std::string_view url);
        };
    };
};