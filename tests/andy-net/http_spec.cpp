#include <andy/net/http.hpp>

#include <andy/tests.hpp>

describe of("lavi::net::http", [](){
    describe(static_function, "get", [](){
        auto status_tester = [](int status_code){
            describe("/status/" + std::to_string(status_code), [=](){
                std::string url = "http://httpbin.org/status/" + std::to_string(status_code);
                it("should return status code " + std::to_string(status_code), [=](){
                    lavi::net::http::response res = lavi::net::http::get(url);
                    expect(res.status_code).to<eq>(status_code);
                });
            });
        };
        status_tester(200);
        status_tester(404);
        status_tester(500);
    });
});