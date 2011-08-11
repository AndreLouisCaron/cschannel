#ifndef _cschannel_h__
#define _cschannel_h__

/* Copyright(c) Andre Caron, 2009-2011
**
** This document is covered by the an Open Source Initiative approved software
** license.  A copy of the license should have been provided alongside
** this software package (see "license.txt").  If not, the license is available
** online at "http://www.opensource.org/licenses/mit-license". */

/*!
 * @mainpage Streaming secure channel in C.
 *
 * This project wraps the horrible Microsoft Security Support Provider Interface
 * (SSPI) API for use with the Microsoft Secure Channel, a TLS/SSL
 * implementation.  The API is somewhat difficult to use correctly and requires
 * much experimentation and testing.
 *
 * The project aims at providing a TLS/SSL implementation which is:
 *
 * @li @b convenient: integration in existing applications requires a minimal
 *  amount of code
 * @li @b reliable: the implementation is already debugged and supports a wide
 *  variety of situations, including corner cases
 * @li @b compatible: the implementation does not impose a network model and is
 *  compatible with any communucation transport providing reliable, ordered
 *  delivery of a stream of bytes.
 *
 * <b>Table of contents:</b>
 *
 * @li @ref license
 * @li @ref motivation
 * @li @ref design
 *
 * @section license Software license
 *
 * The software is released under an Open Source Initiative (OSI) approved
 * licence (MIT) with maximal compatibility with your business model, be it open
 * or closed source.
 *
 * The software is Copyright(c) Andre Caron, 2009-2011:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @section motivation Motivation
 *
 * Microsoft's TLS/SSL implementation, Secure Channel (SChannel) is exposed
 * through the Microsoft Security Support Provider Interface (SSPI) API.  This
 * API is designed to be very generic and is therefore very complicated to use;
 * applications look like they're using a generic encryption mechanism, rather
 * than a TLS/SSL implementation.
 *
 * All in all, the API is difficult to use, and documentation is not very
 * helpful as far as corner cases are concerned.  Examples in the Platform SDK
 * only demonstrate simple cases and leave difficult corner cases as "an
 * exercise for the reader".
 *
 * This project provides a simple facade for this Secure Channel beast as a
 * standalone library with no other dependencies.  It is suitable for use in a
 * wide range of use cases and should be easily pluggable into any application.
 *
 * @section design Design
 *
 * The implementation is based on a finite state machine, which is interruptible
 * at (almost) any moment.  It does no I/O on its own and thus does not block on
 * networking operations, making it suitable for use in high-performance
 * networking applications based on asynchronous I/O (using I/O completion
 * ports, for example).
 */

/* standard library. */
#include <stddef.h>

/* microsoft secure channel api. */
#ifndef SECURITY_WIN32
#   define SECURITY_WIN32
#endif
#include <WinSock2.h>
#include <WinCrypt.h>
#include <SChnlSp.h>
#include <Security.h>

/* don't mangle names. */
#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @brief Enumeration of secure channel error states.
 */
enum secure_channel_error
{
    secure_channel_good,
    secure_channel_fail,
};

/*!
 * @brief Enumeration of secure channel states.
 */
enum secure_channel_state
{
    secure_channel_failed=-1,
    secure_channel_virgin,
    secure_channel_unsafe,
    secure_channel_secure,
    secure_channel_expire,
};

/*!
 * @brief Enumeration of secure channel roles.
 */
enum secure_channel_role
{
    secure_channel_client,
    secure_channel_server,
};

/*!
 * @brief Information about the host's identity (local, self).
 */
struct security_certificate
{
    /*!
     * @brief Handle to opaque certificate state.
     */
    PCCERT_CONTEXT handle;
};

/*!
 * @brief Information about the host's identity (local, self).
 */
struct security_credentials
{
    /*!
     * @brief Description of the identity exposed by the channel.
     */
    SCHANNEL_CRED identity;

    /*!
     * @brief Handle to opaque credentials state.
     */
    CredHandle handle;
};

/*!
 * @brief Information about the security service provider.
 */
struct security_package
{
    /*!
     * @brief Maximum size of a negotiation token, in bytes.
     */
    DWORD token_size;
};

/*!
 * @brief Enumeration of possible errors codes when using TLS 1.
 */
enum tls1_alert
{
    tls1_alert_certificate_invalid   = TLS1_ALERT_BAD_CERTIFICATE,
    tls1_alert_certificate_support   = TLS1_ALERT_UNSUPPORTED_CERT,
    tls1_alert_certificate_revoked   = TLS1_ALERT_CERTIFICATE_REVOKED,
    tls1_alert_certificate_expired   = TLS1_ALERT_CERTIFICATE_EXPIRED,
    tls1_alert_certificate_unkonwn   = TLS1_ALERT_CERTIFICATE_UNKNOWN,
    tls1_alert_unknown_authority     = TLS1_ALERT_UNKNOWN_CA,
    tls1_alert_access_denied         = TLS1_ALERT_ACCESS_DENIED,
    tls1_alert_insufficient_security = TLS1_ALERT_INSUFFIENT_SECURITY,
    tls1_alert_user_cancelled        = TLS1_ALERT_USER_CANCELED,
    tls1_alert_no_renegotiation      = TLS1_ALERT_NO_RENEGOTIATION,
};

/*!
 * @brief High-level wrapper for the security channel interface.
 */
struct secure_channel
{
    /*!
     * @brief Current channel state.
     */
    enum secure_channel_state state;

    /*!
     * @brief Current channel error state.
     */
    enum secure_channel_error error;

    /*!
     * @brief Channel role.
     */
    enum secure_channel_role role;

    /*!
     * @brief Host certificate (local peer, self).
     */
    struct security_certificate certificate;

    /*!
     * @brief Host credentials (local peer, self).
     */
    struct security_credentials credentials;

    /*!
     * @brief Set to 1 to request client certificate, 0 by default.
     *
     * @ingroup server
     */
    int mutual_authentication;

    /*!
     * @brief Set to 0 to disable quick reconnect.
     */
    int allow_reconnect;

    /*!
     * @brief Set to 0 to deny renegotiation requests.
     */
    int allow_renegotiation;

    /*!
     * @private
     * @brief Set to 1 when renegotiation is requested.
     */
    int requested_renegotiation;

    /*!
     * @private
     * @brief Handle to opaque secure channel state.
     */
    CtxtHandle handle;

    /*!
     * @private
     * @brief Maximum token size, in bytes.
     */
    DWORD token_size;

    /*!
     * @private
     * @brief Maximum message header size, in bytes.
     */
    DWORD header_size;

    /*!
     * @private
     * @brief Maximum message stream size, in bytes.
     */
    DWORD stream_size;

    /*!
     * @private
     * @brief Maximum message footer size, in bytes.
     */
    DWORD footer_size;

    /*!
     * @addtogroup buffers
     */
    /// @{

    /*!
     * @private
     * @brief Buffer for in-bound negotiation token data.
     */
    void * itoken;

    /*!
     * @private
     * @brief Buffer for out-bound negotiation token data.
     */
    void * otoken;

    /*!
     * @private
     * @brief Buffer for out-bound message header.
     * @invariant Points to 0 or an array of @c header_size bytes.
     */
    void * emheader;

    /*!
     * @private
     * @brief Buffer for out-bound message stream.
     * @invariant Points to 0 or an array of @c stream_size bytes.
     */
    void * emstream;

    /*!
     * @private
     * @brief Buffer for out-bound message footer.
     * @invariant Points to 0 or an array of @c footer_size bytes.
     */
    void * emfooter;

    /*!
     * @private
     * @brief Buffer for in-bound message stream.
     * @invariant Points to 0 or an array of @c stream_size bytes.
     */
    void * dmstream;

    /*!
     * @private
     * @brief Buffers passed to security package.
     */
    SecBuffer buffers[12];

    /*!
     * @private
     * @brief Buffer for in-bound token data (received from peer).
     * @invariant References entries in @c buffers.
     */
    SecBufferDesc itbuffer;

    /*!
     * @private
     * @brief Buffer for out-bound token data (to be sent to peer).
     * @invariant References entries in @c buffers.
     */
    SecBufferDesc otbuffer;

    /*!
     * @private
     * @brief Buffer for encrypting messages, passed to security package.
     * @invariant References entries in @c buffers.
     */
    SecBufferDesc embuffer;

    /*!
     * @private
     * @brief Buffer for decrypting messages, passed to security package.
     * @invariant References entries in @c buffers.
     */
    SecBufferDesc dmbuffer;

    /// @}

    /*!
     * @public
     * @brief Set to 1 when the stream expects a @c secure_channel_pull() call.
     */
    int need_pull;

    /*!
     * @public
     * @brief Set to 1 when the stream expects a @c secure_channel_push() call.
     */
    int need_push;

    /*!
     * @addtogroup memory
     */
    /// @{

    /*!
     * @public
     * @brief Custom memory allocator's allocation function.
     *
     * If not specified, the secure channel will use @c malloc().
     *
     * @see release_buffer
     * @warning It is highly likely that setting only one of @c acquire_buffer
     *  or @c release_buffer is a logic error.  Always set both.
     */
    void*(*acquire_buffer)(struct secure_channel*, size_t);

    /*!
     * @public
     * @brief Custom memory allocator's cleanup function.
     *
     * If not specified, the secure channel will use @c free().
     *
     * @see acquire_buffer
     * @warning It is highly likely that setting only one of @c acquire_buffer
     *  or @c release_buffer is a logic error.  Always set both.
     */
    void (*release_buffer)(struct secure_channel*, void *);

    /// @}

    /*!
     * @public
     * @brief Callback invoked to notify of unused data in decryption.
     * @ingroup callback
     */
    void(*accept_overflow)(struct secure_channel*, const void*, size_t);

    /*!
     * @public
     * @brief Callback invoked to notify of availabile encrypted data.
     * @ingroup callback
     */
    void(*accept_encrypted)(struct secure_channel*, const void*, size_t);

    /*!
     * @public
     * @brief Callback invoked to notify of availabile decrypted data.
     * @ingroup callback
     */
    void(*accept_decrypted)(struct secure_channel*, const void*, size_t);

    /*!
     * @public
     * @brief Extra context, used by application-layer code (in callbacks).
     */
    void * object;
};

/*!
 * @brief Obtain information about the security package.
 * @param package Security package description to fill in.
 *
 * @ingroup export
 *
 * This function is mainly used to request the maximum token size, in bytes.
 * The specified limit is used to allocate token buffers on each side of the
 * connection.
 *
 * @note Call once and re-use for all channels.
 */
void security_package_setup ( struct security_package * package );

/*!
 * @brief Clear channel state and set default settings.
 * @param channel Secure channel instance to clear.
 *
 * @ingroup export
 *
 * All modifications to default settings should be made after a call to this
 * function is made.
 *
 * @see secure_channel_clear()
 *
 * @warning Calls to this function after a call to @c secure_channel_setup() has
 *  been made results in undefined behavior.  Common effects include memory
 *  leaks or large stream and token buffers.
 */
void secure_channel_clear ( struct secure_channel * channel );

/*!
 * @brief Finish initialization and start negotiation.
 * @param package Security package description.
 * @param channel Security channel instance for which to start initialization.
 * @param role Indicates whether the local host should initate negotiation or if
 *  the remote peer is expected to.
 *
 * @ingroup export
 *
 * For clients, this function produces the initial negotation token, which must
 * be sent to the server for negotiation to continue.  All modifications to
 * default settings should be made before this call is invoked.
 *
 * @see secure_channel_clear()
 */
void secure_channel_setup ( const struct security_package * package,
    struct secure_channel * channel, enum secure_channel_role role );

/*!
 * @brief Buffer message data for encryption (at a later time).
 * @param channel Security channel used for encryption.
 * @param data Pointer to first byte of data to encrypt.
 * @param size Number of bytes, starting at @a data, to encrypt.
 * @return Number of bytes consumed by the channel, in [0, @a size].
 *
 * @ingroup export
 *
 * Function used to process data before it is sent to the peer.  All data to
 * exchange over the secured connection must be passed to this filter.
 *
 * This function does not encrypt data.  The application should invoke the
 * @c secure_channel_flush method when a complete "message" is ready to be
 * encrypted.  Whenever data is encrypted, the resulting message data is passed
 * back to the application using the secure_channel::accept_encrypted callback.
 *
 * @see secure_channel_flush()
 */
size_t secure_channel_push
    ( struct secure_channel * channel, const char * data, size_t size );

/*!
 * @brief Attempt to message decryption.
 * @param channel Security channel used for encryption.
 * @param data Pointer to first byte of data to decrypt.
 * @param size Number of bytes, starting at @a data, to decrypt.
 * @return Number of bytes consumed by the channel, in [0, @a size].
 *
 * @ingroup export
 *
 * Function used to process data received from the peer, before it is used by
 * the application.  All data to exchange over the secured connection must be
 * passed to this filter.
 *
 * This function @e attempts to decrypt received data.  Because the secure
 * channel is @e message-based and the transport mechanism is @e stream-based,
 * it is possible to receive data in chunks smaller than the entire message.  In
 * such a case, data is buffered and kept until further data is provided and the
 * message is completely received.  Whenever data is decrypted, the resulting
 * message data is passed back to the application using the
 * secure_channel::accept_decrypted callback.
 */
size_t secure_channel_pull
    ( struct secure_channel * channel, const char * data, size_t size );

/*!
 * @brief Force any buffered data to be output.
 * @param channel Secure channel instance for which to encrypt buffered data.
 *
 * The secure channel allows the application to provide message parts in
 * multiple calls to the secure_channel_pull() function.  Because of this, the
 * secure channel requires a call to this function to actually encrypt data.
 *
 * @note Depending on the security package limits (maximum message size) and
 *  channel configuration, it is possible that a message be encrypted without
 *  a call to this function.  However, to ensure that data has been encrypted,
 *  this function a call!
 *
 * @ingroup export
 */
void secure_channel_flush ( struct secure_channel * channel );

/*!
 * @brief Notify peer of intent to re-negotiate.
 * @param channel Secure channel instance for which to request re-negotiation
 *
 * @ingroup export
 *
 * Re-negotiating the encryption keys is recommended after 1 Gigabyte or data
 * has been exchanged, or 1 hour has elapsed since the last negotiation,
 * whichever occurs first.  However, re-negotiation is optional, and the request
 * may be denied by the peer.  Thus, the secure channel does not attempt to
 * re-negotiate automatically and it is up to the application to request it if
 * desired.
 *
 * @note Re-negotiation of the connection is always optional.  The peer may
 *  decide not to acknowledge the request.  Also, the peer may continue to
 *  encrypt data until it ptocesses the renegotiation request.  Because of these
 *  two limitations, the secure channel cannot determine if the peer ever
 *  processes the renegotiation request.
 */
void secure_channel_renegotiate ( struct secure_channel * channel );

/*!
 * @brief Initiate shutdown.
 * @param channel Secure channel instance to close.
 *
 * A call to this function produces a token that notifies the peer of the intent
 * to shutdown the connection.
 *
 * @todo Figure out if the local channel can still decrypt data.
 *
 * @note Unlike network sockets, the secure channel does not support unilateral
 *  shutdown.  Moreover, the channel might need to re-negotiate at the peer's
 *  request, even if the application is only receiving data.  Therefore,
 *  applications should be careful not to request a shutdown until all data is
 *  exchanged, and to keep the socket open even if a one-way socket shutdown is
 *  possible.
 *
 * @ingroup export
 */
void secure_channel_close ( struct secure_channel * channel );

/* don't mangle names. */
#ifdef __cplusplus
}
#endif

#endif /* _cschannel_h__ */
