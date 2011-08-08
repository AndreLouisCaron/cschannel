// Copyright(c) Andre Caron, 2009-2011
//
// This document is covered by the an Open Source Initiative approved software
// license.  A copy of the license should have been provided alongside
// this software package (see "license.txt").  If not, the license is available
// online at "http://www.opensource.org/licenses/mit-license".

#include "Client.hpp"
#include "Server.hpp"

#include <iostream>

namespace {

}

int main ( int, char ** )
{
    demo::Client client;
    demo::Server server;
    
      // negotiation.
    client >> server, server >> client;
    client >> server, server >> client;
    std::cout << "-----" << std::endl;
    
      // exchange.
#if 0
    client << "Hello, server!";
    client >> server;
    { std::string message;
        server >> message;
        std::cout << "Server: data='" << message << "'." << std::endl;
    }
    std::cout << "-----" << std::endl;
#endif
    
      // re-negotiation.
#if 0
    client.renegotiate();
    client >> server, server >> client;
    client >> server, server >> client;
    client >> server, server >> client;
    std::cout << "-----" << std::endl;
      // exchange.
    server << "Hello, client!";
    server >> client;
    { std::string message;
        client >> message;
        std::cout << "Client: data='" << message << "'." << std::endl;
    }
    std::cout << "-----" << std::endl;
#endif
    
      // re-negotiation.
    server.renegotiate();
    server >> client;
    client >> server, server >> client;
    client >> server, server >> client;
    std::cout << "-----" << std::endl;
    
      // exchange.
    server << "Hello, client!";
    server >> client;
    { std::string message;
        client >> message;
        std::cout << "Client: data='" << message << "'." << std::endl;
    }
    std::cout << "-----" << std::endl;
    
      // exchange.
#if 0
    client << "Hello, server!";
    client >> server;
    { std::string message;
        server >> message;
        std::cout << "Server: data='" << message << "'." << std::endl;
    }
    std::cout << "-----" << std::endl;
#endif
    
      // shutdown.
    server.shutdown();
    server >> client;
}

#pragma comment ( lib, "Crypt32.lib" )
#pragma comment ( lib, "Secur32.lib" )
