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
      // negotiation.
    std::cout
        << "(1): negotiate" << std::endl
        << "--------------" << std::endl;
    demo::Client client;
    demo::Server server;
    do {
        client >> server, server >> client;
    }
    while ( client.negotiating() || server.negotiating() );
    std::cout << std::endl << std::endl << std::endl;
    
      // exchange.
    std::cout
        << "(2) client -> server" << std::endl
        << "--------------------" << std::endl;
    client << "Hello, server!";
    client >> server;
    { std::string message;
        server >> message;
        std::cout << "Server: data='" << message << "'." << std::endl;
    }
    std::cout << std::endl << std::endl << std::endl;
    
      // exchange.
    std::cout
        << "(3) client <- server" << std::endl
        << "--------------------" << std::endl;
    server << "Hello, client!";
    server >> client;
    { std::string message;
        client >> message;
        std::cout << "Client: data='" << message << "'." << std::endl;
    }
    std::cout << std::endl << std::endl << std::endl;
    
      // re-negotiation.
    std::cout
        << "(4) client re-negotiation" << std::endl
        << "-------------------------" << std::endl;
    client.renegotiate();
    server << "Hello, client!"; // simulate pending message.
    server >> client;
    { std::string message;
        client >> message;
        std::cout << "Client: data='" << message << "'." << std::endl;
    }
    do {
        client >> server, server >> client;
    }
    while ( client.negotiating() || server.negotiating() );
    std::cout << std::endl << std::endl << std::endl;
    
      // exchange.
    std::cout
        << "(5) client <- server, double" << std::endl
        << "----------------------------" << std::endl;
    server << "Hello, client!";
    server << "Hello, client!";
    server >> client;
    { std::string message;
        client >> message;
        std::cout << "Client: data='" << message << "'." << std::endl;
    }
    std::cout << std::endl << std::endl << std::endl;
    
    // re-negotiation.
    std::cout
        << "(6) server re-negotiation" << std::endl
        << "-------------------------" << std::endl;
    server.renegotiate();
    client << "Hello, server!"; // simulate pending message.
    client >> server;
    { std::string message;
        server >> message;
        std::cout << "Server: data='" << message << "'." << std::endl;
    }
    do {
        client >> server, server >> client;
    }
    while ( client.negotiating() || server.negotiating() );
    std::cout << std::endl << std::endl << std::endl;
    
      // exchange.
    std::cout
        << "(7) client <- server" << std::endl
        << "--------------------" << std::endl;
    server << "Hello, client!";
    server >> client;
    { std::string message;
        client >> message;
        std::cout << "Client: data='" << message << "'." << std::endl;
    }
    std::cout << std::endl << std::endl << std::endl;
    
      // shutdown.
    std::cout
        << "(8) shutdown" << std::endl
        << "------------" << std::endl;
    server.shutdown();
    server >> client;
    server >> client;
}

#pragma comment ( lib, "Crypt32.lib" )
#pragma comment ( lib, "Secur32.lib" )
