#ifndef _Peer_hpp__
#define _Peer_hpp__

// Copyright(c) Andre Caron, 2009-2011
//
// This document is covered by the an Open Source Initiative approved software
// license.  A copy of the license should have been provided alongside
// this software package (see "license.txt").  If not, the license is available
// online at "http://www.opensource.org/licenses/mit-license".

#include "Buffer.hpp"
#include "cschannel.h"
#include "certificate.hpp"

#include <iostream>
#include <string>

namespace demo {

    class Peer
    {
        /* data. */
    private:
        Buffer myEBuffer; // to encrypt.
        Buffer myPBuffer; // to send.
        Buffer myGBuffer; // received.
        Buffer myDBuffer; // decrypted.
    protected:
        ::security_package myPackage;
        ::secure_channel   myChannel;

        /* construction. */
    public:
        Peer ()
            : myEBuffer(16*1024), myPBuffer(16*1024),
              myGBuffer(16*1024), myDBuffer(16*1024)
        {
              // Pre-initialize.
            ::security_pacakge_setup(&myPackage);
            ::secure_channel_clear(&myChannel);
              // Settings.
            myChannel.allow_reconnect    = 0;
              // Initialize.
            myChannel.accept_overflow    = &Peer::overflow;
            myChannel.accept_decrypted   = &Peer::decrypted;
            myChannel.accept_encrypted   = &Peer::encrypted;
              // ...
            myChannel.object = this;
        }

        /* methods. */
    public:
        bool negotiating () const
        {
            return (((myChannel.state == ::secure_channel_virgin) ||
                     (myChannel.state == ::secure_channel_unsafe))
                    && (myChannel.error == ::secure_channel_good));
        }

        void process ()
        {
            myEBuffer.take(::secure_channel_push(
                &myChannel, myEBuffer.data(), myEBuffer.size()));
            myGBuffer.take(::secure_channel_pull(
                &myChannel, myGBuffer.data(), myGBuffer.size()));
        }

        void renegotiate ()
        {
            ::secure_channel_renegotiate(&myChannel);
        }

        void shutdown ()
        {
            ::secure_channel_close(&myChannel);
        }

        /* operators. */
    public:
        Peer& operator<< ( const std::string& message )
        {
            ::secure_channel_push(&myChannel, message.data(), message.size());
            ::secure_channel_flush(&myChannel);
            return (*this);
        }

        Peer& operator>> ( std::string& message )
        {
            message.append(myDBuffer.begin(), myDBuffer.end());
            myDBuffer.take(myDBuffer.end());
            return (*this);
        }

        friend Peer& operator<< ( Peer& lhs, Peer& rhs )
        {
            std::cout << "<< " << rhs.myPBuffer.size() << std::endl;
            rhs.myPBuffer.take(
                lhs.myGBuffer.push(rhs.myPBuffer.begin(), rhs.myPBuffer.end()));
            lhs.process();
            return (lhs);
        }

        friend Peer& operator>> ( Peer& lhs, Peer& rhs )
        {
            std::cout << ">> " << lhs.myPBuffer.size() << std::endl;
            lhs.myPBuffer.take(
                rhs.myGBuffer.push(lhs.myPBuffer.begin(), lhs.myPBuffer.end()));
            rhs.process();
            return (lhs);
        }

        /* class methods. */
    private:
        static void overflow
            ( secure_channel * channel, const void * data, size_t size )
        {
            static_cast<Peer*>(channel->object)
                -> myGBuffer.push(data, size);
        }

        static void decrypted
            ( secure_channel * channel, const void * data, size_t size )
        {
            static_cast<Peer*>(channel->object)
                -> myDBuffer.push(data, size);
        }

        static void encrypted
            ( secure_channel * channel, const void * data, size_t size )
        {
            static_cast<Peer*>(channel->object)
                -> myPBuffer.push(data, size);
        }
    };

}

#endif /* _Peer_hpp__ */
