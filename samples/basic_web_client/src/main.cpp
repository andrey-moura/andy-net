#include <networking.hpp>
#include <web_client.hpp>
#include <mutex>

using namespace uva;
using namespace networking;

void print_help()
{
    std::cout << "This is a simple client to demonstrate the capabilities of client. You can use something like https://httpbin.org/ to test." << std::endl;
    std::cout << "Type the HTTP method followed by the url." << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
}

int main(int argc, const char **argv)
{
    if(argc < 2) {
        print_help();
        std::cout << "Error: missing host";
        return 0;
    }

    basic_web_client client(argv[1]);

    print_help();

    std::mutex mutex;
    std::condition_variable variable;

    std::string url;
    std::string cmd;

    while(1) {
        std::cin >> cmd;
        std::cin >> url;

        if(cmd == "GET" || cmd == "get") {

            try {
                client.get(url, {}, {}, [&variable](http_message m) {
                    std::cout << "Status: "       << (int)m.status << " (" << m.status_msg << " )" << std::endl;
                    std::cout << "Content-Type: " << uva::networking::content_type_to_string(m.type) << std::endl;
                    std::cout << "Body:" << std::endl;
                    std::cout << m.raw_body << std::endl;

                    variable.notify_one();
                });
            } catch(std::exception e) {
                variable.notify_one();
            }
        }

        std::unique_lock<std::mutex> ul(mutex);
        variable.wait(ul);
    }
}