
#include <iostream>
#include <application.hpp>

#include <networking_controller.hpp>

using namespace uva;
using namespace routing;
using namespace console;

DECLARE_CONSOLE_APPLICATION(
    //Declare your routes above. As good practice, keep then ordered by controler.
    //You can have C++ code here, perfect for init other libraries.

    ROUTE("new-project", networking_controller::new_project);
    ROUTE("new-controller", networking_controller::new_controller);
)
