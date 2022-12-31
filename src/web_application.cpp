#include <web_application.hpp>

using namespace uva;
using namespace networking;

asio::io_context m_asioContext;
asio::io_context::work work(m_asioContext);
std::thread m_threadContext([]() { m_asioContext.run(); });
// These things need an asio context
asio::ip::tcp::acceptor* m_asioAcceptor = nullptr;

void web_application::init(int argc, const char **argv)
{

}