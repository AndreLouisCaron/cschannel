#ifndef _cschannel_h__
#define _cschannel_h__

/* Copyright(c) Andre Caron, 2009-2011
**
** This document is covered by the an Open Source Initiative approved software
** license.  A copy of the license should have been provided alongside
** this software package (see "license.txt").  If not, the license is available
** online at "http://www.opensource.org/licenses/mit-license". */

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
     * @brief Buffer for in-bound negotiation token.
     */
    void * gtokens;

    /*!
     * @private
     * @brief Buffer for out-bound negotiation token.
     */
    void * ptokens;

    /*!
     * @private
     * @brief Buffer for out-bound message header.
     * @invariant Points to 0 or an array of @c header_size bytes.
     */
    void * pheader;

    /*!
     * @private
     * @brief Buffer for out-bound message stream.
     * @invariant Points to 0 or an array of @c stream_size bytes.
     */
    void * pstream;

    /*!
     * @private
     * @brief Buffer for out-bound message footer.
     * @invariant Points to 0 or an array of @c footer_size bytes.
     */
    void * pfooter;

    /*!
     * @private
     * @brief Buffer for in-bound message stream.
     * @invariant Points to 0 or an array of @c stream_size bytes.
     */
    void * gstream;

    /*!
     * @private
     * @brief Buffers passed to security package.
     */
    SecBuffer buffers[8];

    /*!
     * @private
     * @brief Buffer for in-bound data, passed to security package.
     * @invariant References entries in @c buffers.
     */
    SecBufferDesc gbuffer;

    /*!
     * @private
     * @brief Buffer for out-bound data, passed to security package.
     * @invariant References entries in @c buffers.
     */
    SecBufferDesc pbuffer;

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
 *
 * @ingroup export
 *
 * This function is mainly used to request the maximum token size, in bytes.
 * The specified limit is used to allocate token buffers on each side of the
 * connection.
 *
 * @note Call once and re-use for all channels.
 */
void security_pacakge_setup ( struct security_package * package );

/*!
 * @brief Clear channel state and set default settings.
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
 *
 * @ingroup export
 *
 * For clients, this function produces the initial negotation token, which must
 * be sent to the server for negotiation to continue.  All modifications to
 * default settings should be made before this call is invoked.
 *
 * @see secure_channel_clear()
 */
void secure_channel_setup
    ( const struct security_package * pacakge, struct secure_channel * channel, enum secure_channel_role );

/*!
 * @brief Buffer message data for encryption (at a later time).
 *
 * @ingroup export
 *
 * @see secure_channel_flush()
 */
size_t secure_channel_push
    ( struct secure_channel * channel, const char * data, size_t size );

/*!
 * @brief Attempt to message decryption.
 *
 * @ingroup export
 */
size_t secure_channel_pull
    ( struct secure_channel * channel, const char * data, size_t size );

/*!
 * @brief Force any buffered data to be output.
 *
 * @ingroup export
 */
void secure_channel_flush ( struct secure_channel * channel );

/*!
 * @brief Notify peer of intent to re-negotiate.
 *
 * @ingroup export
 */
void secure_channel_renegotiate ( struct secure_channel * channel );

/*!
 * @brief Initiate shutdown.
 *
 * @ingroup export
 */
void secure_channel_close ( struct secure_channel * channel );

/* don't mangle names. */
#ifdef __cplusplus
}
#endif

#endif /* _cschannel_h__ */
