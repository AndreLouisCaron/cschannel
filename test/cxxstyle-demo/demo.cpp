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
    demo::Client client_;
    demo::Server server_;
    
      // negotiation.
    client_ >> server_, server_ >> client_;
    client_ >> server_, server_ >> client_;
    std::cout << "-----" << std::endl;
    
      // exchange.
#if 0
    client_ << "Hello, server!";
    client_ >> server_;
    { std::string message;
        server_ >> message;
        std::cout << "Server: data='" << message << "'." << std::endl;
    }
    std::cout << "-----" << std::endl;
#endif
    
      // re-negotiation.
#if 0
    client_.renegotiate();
    client_ >> server_, server_ >> client_;
    client_ >> server_, server_ >> client_;
    client_ >> server_, server_ >> client_;
    std::cout << "-----" << std::endl;
      // exchange.
    server_ << "Hello, client!";
    server_ >> client_;
    { std::string message;
        client_ >> message;
        std::cout << "Client: data='" << message << "'." << std::endl;
    }
    std::cout << "-----" << std::endl;
#endif
    
      // re-negotiation.
    server_.renegotiate();
    server_ >> client_;
    client_ >> server_, server_ >> client_;
    client_ >> server_, server_ >> client_;
    std::cout << "-----" << std::endl;
    
      // exchange.
    server_ << "Hello, client!";
    server_ >> client_;
    { std::string message;
        client_ >> message;
        std::cout << "Client: data='" << message << "'." << std::endl;
    }
    std::cout << "-----" << std::endl;
    
      // exchange.
#if 0
    client_ << "Hello, server!";
    client_ >> server_;
    { std::string message;
        server_ >> message;
        std::cout << "Server: data='" << message << "'." << std::endl;
    }
    std::cout << "-----" << std::endl;
#endif
    
      // shutdown.
    server_.shutdown();
    server_ >> client_;
}

#pragma comment ( lib, "Crypt32.lib" )
#pragma comment ( lib, "Secur32.lib" )
