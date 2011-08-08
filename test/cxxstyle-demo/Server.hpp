#ifndef _demo_Server_hpp__
#define _demo_Server_hpp__

// Copyright(c) Andre Caron, 2009-2011
//
// This document is covered by the an Open Source Initiative approved software
// license.  A copy of the license should have been provided alongside
// this software package (see "license.txt").  If not, the license is available
// online at "http://www.opensource.org/licenses/mit-license".

#include "Peer.hpp"

namespace demo {

    class Server :
        public Peer
    {
    public:
        Server ()
        {
            myChannel.certificate.handle = w32::cr::acquire();
            ::secure_channel_setup(
                &myPackage, &myChannel, ::secure_channel_server);
        }

        ~Server ()
        {
            w32::cr::release(myChannel.certificate.handle);
        }
    };

}

#endif /* _demo_Server_hpp__ */
