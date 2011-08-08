#ifndef _Buffer_hpp__
#define _Buffer_hpp__

// Copyright(c) Andre Caron, 2009-2011
//
// This document is covered by the an Open Source Initiative approved software
// license.  A copy of the license should have been provided alongside
// this software package (see "license.txt").  If not, the license is available
// online at "http://www.opensource.org/licenses/mit-license".

#include <algorithm>
#include <cstddef>
#include <iomanip>
#include <vector>

#ifdef _MSC_VER
#   pragma push_macro("min")
#   undef min
#endif

namespace demo {

    class Buffer
    {
        std::vector<char> myData;
    public:
        typedef std::vector<char>::const_iterator iterator;

        iterator begin () const
        {
            return (myData.begin());
        }

        iterator end () const
        {
            return (myData.end());
        }

        Buffer ( std::size_t size )
        {
            myData.reserve(size);
        }

        std::size_t size () const
        {
            return (myData.size());
        }

        const char * data () const
        {
            if ( myData.empty() ) {
                return (0);
            }
            return (&myData[0]);
        }

        void dump ( std::ostream& stream ) const
        {
            stream << std::hex << "0x";
            for ( size_t i = 0; (i < myData.size()); ++i )
            {
                stream
                    << std::setfill('0') << std::setw(2)
                    << static_cast<int>(myData[i]);
            }
            stream << std::dec << std::endl;
        }

        void push ( const char * data, std::size_t size )
        {
            size = std::min(myData.capacity()-myData.size(), size);
            std::copy(data, data+size, std::back_inserter(myData));
        }

        void push ( const void * data, std::size_t size )
        {
            push(static_cast<const char*>(data), size);
        }

        std::size_t free () const
        {
            return (myData.capacity() - myData.size());
        }

        template<typename Iterator>
        Iterator push ( Iterator begin, Iterator end )
        {
            for ( ; ((begin != end) && (free() > 0)); ++begin ) {
                myData.push_back(*begin);
            }
            return (begin);
        }

        void take ( std::size_t size )
        {
            size = std::min(myData.size(), size);
            myData.erase(myData.begin(), myData.begin()+size);
        }

        void take ( iterator until )
        {
            myData.erase(myData.begin(), until);
        }
    };

}

#ifdef _MSC_VER
#   pragma pop_macro("min")
#endif

#endif /* _Buffer_hpp__ */
