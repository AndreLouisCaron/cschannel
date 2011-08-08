#ifndef _demo_Client_hpp__
#define _demo_Client_hpp__

// Copyright(c) Andre Caron, 2009-2011
//
// This document is covered by the an Open Source Initiative approved software
// license.  A copy of the license should have been provided alongside
// this software package (see "license.txt").  If not, the license is available
// online at "http://www.opensource.org/licenses/mit-license".

#include "Peer.hpp"

namespace demo {

    class Client :
        public Peer
    {
    public:
        Client ()
        {
            myChannel.allow_renegotiation = 0;
            ::secure_channel_setup(
                &myPackage, &myChannel, ::secure_channel_client);
        }
    };

}

#endif /* _demo_Client_hpp__ */
