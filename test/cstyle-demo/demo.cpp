// Copyright(c) Andre Caron, 2009-2011
//
// This document is covered by the an Open Source Initiative approved software
// license.  A copy of the license should have been provided alongside
// this software package (see "license.txt").  If not, the license is available
// online at "http://www.opensource.org/licenses/mit-license".

#include "cschannel.h"
#include "certificate.hpp"

#include <iostream>
#include <iomanip>

#define NOBODY 0
#define CLIENT 1
#define SERVER 2

#define RENEGOTIATE NOBODY
#define SHUTDOWN    NOBODY

namespace {

    char clientdata[16*1024]; size_t clientsize = 0;
    char serverdata[16*1024]; size_t serversize = 0;

    void client_consumed ( size_t size )
    {
        std::memcpy(clientdata, clientdata+size, clientsize-size);
        clientsize -= size;
    }

    void client_overflow
        ( secure_channel * channel, const void * data, size_t size )
    {
        std::memcpy(clientdata+clientsize, data, size);
        clientsize += size;
    }

    void client_decrypted
        ( secure_channel * channel, const void * data, size_t size )
    {
        std::cout << "Client: data='";
        std::cout.write((const char*)data, size);
        std::cout << "'." << std::endl;
    }

    void client_encrypted
        ( secure_channel * channel, const void * data, size_t size )
    {
        std::memcpy(serverdata+serversize, data, size);
        serversize += size;
        std::cout
            << "Client: push(" << size << ")" << std::endl;
    }

    void server_consumed ( size_t size )
    {
        std::memcpy(serverdata, serverdata+size, serversize-size);
        serversize -= size;
    }

    void server_overflow
        ( secure_channel * channel, const void * data, size_t size )
    {
        std::memcpy(serverdata+serversize, data, size);
        serversize += size;
    }

    void server_decrypted
        ( secure_channel * channel, const void * data, size_t size )
    {
        std::cout << "Server: data='";
        std::cout.write((const char*)data, size);
        std::cout << "'." << std::endl;
    }

    void server_encrypted
        ( secure_channel * channel, const void * data, size_t size )
    {
        std::memcpy(clientdata+clientsize, data, size); clientsize += size;
        std::cout
            << "Server: push(" << size << ")" << std::endl;
    }

}

int main ( int, char ** )
{
      // basic initialization.
    ::security_package package;
    ::security_package_setup(&package);
      // server-side channel.
    ::secure_channel server;
    ::secure_channel_clear(&server);
    server.allow_reconnect = 0;
    server.accept_overflow = &::server_overflow;
    server.accept_decrypted = &::server_decrypted;
    server.accept_encrypted = &::server_encrypted;
    server.certificate.handle = w32::cr::acquire();
      // client-side channel.
    ::secure_channel client;
    ::secure_channel_clear(&client);
    server.allow_reconnect = 0;
    client.accept_overflow = &::client_overflow;
    client.accept_decrypted = &::client_decrypted;
    client.accept_encrypted = &::client_encrypted;
    
    
      // negotiate!
    ::secure_channel_setup(&package, &server, ::secure_channel_server);
    ::secure_channel_setup(&package, &client, ::secure_channel_client);
    while ( serversize > 0 || clientsize > 0 )
    {
        server_consumed(::secure_channel_push(&server, serverdata, serversize));
        client_consumed(::secure_channel_push(&client, clientdata, clientsize));
    }
    std::cout << "-----" << std::endl;
    
    
      // session secured, exchange stuff.
    std::memcpy(clientdata, "Hello, server!", clientsize=14);
    while ( serversize > 0 || clientsize > 0 )
    {
          // encrypt message.
        client_consumed(::secure_channel_push(&client, clientdata, clientsize));
        ::secure_channel_flush(&client);
          // decrypt message.
        server_consumed(::secure_channel_pull(&server, serverdata, serversize));
    }
    std::cout << "-----" << std::endl;
    
    
      // much stuff exchanged, renegotiat for extra safety.
#if (RENEGOTIATE == CLIENT)
    ::secure_channel_renegotiate(&client);
    server_consumed(::secure_channel_pull(&server, serverdata, serversize));
#endif
#if (RENEGOTIATE == SERVER)
    ::secure_channel_renegotiate(&server);
    client_consumed(::secure_channel_pull(&client, clientdata, clientsize));
#endif
#if (RENEGOTIATE != NOBODY)
    while ( serversize > 0 || clientsize > 0 )
    {
        server_consumed(::secure_channel_push(&server, serverdata, serversize));
        client_consumed(::secure_channel_push(&client, clientdata, clientsize));
    }
    std::cout << "-----" << std::endl;
#endif
    
    
      // session secured, exchange stuff.
    std::memcpy(serverdata, "Hello, client!", serversize=14);
    while ( serversize > 0 || clientsize > 0 )
    {
          // encrypt message.
        server_consumed(::secure_channel_push(&server, serverdata, serversize));
        ::secure_channel_flush(&server);
          // decrypt message.
        client_consumed(::secure_channel_pull(&client, clientdata, clientsize));
    }
    std::cout << "-----" << std::endl;
    
    
      // shutdown channel.
#if (SHUTDOWN == CLIENT)
    ::secure_channel_close(&client);
    server_consumed(::secure_channel_pull(&server, serverdata, serversize));
#endif
#if (SHUTDOWN == SERVER)
    ::secure_channel_close(&server);
    client_consumed(::secure_channel_pull(&client, clientdata, clientsize));
#endif
#if (SHUTDOWN != NOBODY)
    if ( client.state != secure_channel_expire ) {
        std::cerr << "Client: not expired!" << std::endl;
    }
    if ( server.state != secure_channel_expire ) {
        std::cerr << "Server: not expired!" << std::endl;
    }
#endif
    
      // cleanup.
    w32::cr::release(server.certificate.handle);
}

#pragma comment ( lib, "Crypt32.lib" )
#pragma comment ( lib, "Secur32.lib" )
