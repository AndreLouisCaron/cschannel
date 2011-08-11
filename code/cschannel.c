/* Copyright(c) Andre Caron, 2009-2011
**
** This document is covered by the an Open Source Initiative approved software
** license.  A copy of the license should have been provided alongside
** this software package (see "license.txt").  If not, the license is available
** online at "http://www.opensource.org/licenses/mit-license". */

#include "cschannel.h"
#include <stdio.h>

/*!
 * @defgroup export Exported symbols (public interface).
 *
 * All symbols in this group are of public visibility and are intended for use
 * by client code.  All functions marked as such as considered stable and will
 * not likely change in future versions of the library.
 */

/*!
 * @defgroup internal Internal symbols (helpers).
 *
 * All symbols in this group are private to the library.  They are
 * implementation artefacts and have internal linkage.  There should be no
 * attempt to access these symbols from client code.
 */

/*!
 * @defgroup client Client-side behavior.
 * @ingroup internal
 *
 * All symbols in this group are used only by secure channels created with the
 * @c secure_channel_client role.
 */

/*!
 * @defgroup server Server-side behavior.
 * @ingroup internal
 *
 * All symbols in this group are used only by secure channels created with the
 * @c secure_channel_server role.
 */

/*!
 * @defgroup memory Memory management.
 * @ingroup internal
 */

/*!
 * @defgroup buffers Security buffer management.
 * @ingroup internal
 */

/*!
 * @defgroup initialize Initialization functions.
 *
 * All symbols in this group are invoked during secure channel setup.  Once data
 * has been exchanged, it is a logic error to invoke any of them.
 */

/*!
 * @defgroup negotiate Negotiation functions.
 *
 * All symbols in this group are invoked during negotiation only.  Their purpose
 * is to secure the channel for exchange of sensitive information.  No
 * application-level data is exchanged between peers as a result of invoking any
 * of these functions.
 */

/*!
 * @defgroup exchange Application-layer data exchange.
 *
 * All symbols in this group are invoked after negotation, and only once the
 * channel is considered secure.  Their purpose is to exchange sensitive
*  application-level data.
 */

/*!
 * @defgroup control Secure channel state control.
 *
 * All symbols in this group are invoked after negotation, and only once the
 * channel is considered secure.  Their purpose is to communicate meta
 * information to the peer: anything about the connection itself.
 */

/*!
 * @defgroup callback Communication with client code.
 * @ingroup internal
 *
 * Functions in this group are used to wrap invocation of client code via
 * registred callbacks.  These functions are mainly used to notify application
 * code of interesting events and to submit data for transfer or processing.
 */

/*
** PROTOTYPES.
*/

static void secure_channel_decrypt
    ( struct secure_channel * channel, PSecBufferDesc buffer );
static void prepare_dmbuffer ( struct secure_channel * channel );
static void prepare_embuffer ( struct secure_channel * channel );
static void reset_itoken_buffers ( struct secure_channel * channel );
static void reset_otoken_buffers ( struct secure_channel * channel );

/*!
 * @brief Security package name.
 *
 * @ingroup internal
 */
static SEC_WCHAR PACKAGE_NAME[] = SCHANNEL_NAME_W;

/*!
 * @brief Choose minimum of two buffer sizes.
 *
 * @ingroup internal
 */
static size_t channel_min ( size_t lhs, size_t rhs )
{
    return (lhs < rhs)? lhs : rhs;
}

static void * poffset1 ( void * data, size_t size )
{
    return (((char*)data)+size);
}

static const void * poffset2 ( const void * data, size_t size )
{
    return (((const char*)data)+size);
}

#if 0
static size_t channel_copy ( void * ldata, size_t loff, size_t lsize,
                             const void * rdata, size_t rsize )
{
    const size_t size = channel_min(lsize-loff, rsize-roff);
    memcpy(poffset1(ldata,loff), poffset2(rdata,roff), size); 
    return (size);
}
#endif

/*!
 * @brief Copy data into security buffer.
 *
 * @ingroup internal
 */
static size_t channel_copy ( PSecBuffer buffer, size_t full,
                               const void * data, size_t size )
{
      /* fill to capacity. */
    const size_t used = channel_min(size, full-(buffer->cbBuffer));
    memcpy(((char*)buffer->pvBuffer)+(buffer->cbBuffer), data, used);
      /* update cursors. */
    buffer->cbBuffer += used;
    return (used);
}

#if 0
static size_t channel_splice ( PSecBuffer lhs, PSecBuffer rhs, size_t max_size )
{
      /* fill to capacity. */
    const size_t used = channel_copy(
        lhs->pvBuffer, lhs->cbBuffer, rhs->pvBuffer, rhs->cbBuffer, max_size);
    lhs->cbBuffer += used;
    rhs->cbBuffer -= used;
    return (used);
}
#endif

/*!
 * @brief String representation of @c secure_channel_role, for display.
 *
 * @ingroup internal
 */
static const char * channel_role
    ( const struct secure_channel * channel )
{
    const char * role = "?";
    if ( channel->role == secure_channel_client ) {
        role = "Client";
    }
    if ( channel->role == secure_channel_server ) {
        role = "Server";
    }
    return (role);
}

/*!
 * @brief Acquire memory used for buffering data.
 * @param channel Secure channel instance for which to acquire memory.
 * @param size Number of bytes of memory to acquire.
 *
 * @ingroup memory
 *
 * Memory allocation is performed using the custom memory allocation procedure,
 * if one is set.  If not, then the security channel uses @c malloc().
 *
 * @see secure_channel::acquire_buffer
 */
static void * channel_acquire ( struct secure_channel * channel, size_t size )
{
    return ((channel->acquire_buffer != 0)?
        channel->acquire_buffer(channel, size) : malloc(size));
}

/*!
 * @brief Release memory used for buffering data.
 * @param channel Secure channel instance for which to release memory.
 * @param data Pointer returned by @c channel_acquire()
 *
 * @ingroup memory
 *
 * Memory allocation is performed using the custom memory allocation procedure,
 * if one is set.  If not, then the security channel uses @c malloc().
 *
 * @see secure_channel::release_buffer
 */
static void channel_release ( struct secure_channel * channel, void * data )
{
    if ( channel->release_buffer == 0 ) {
        free(data);
    }
    else {
        channel->release_buffer(channel, data);
    }
}

/*!
 * @brief Acquire memory used for buffering security tokens.
 * @param channel Secure channel instance for which to acquire memory.
 *
 * @ingroup memory
 *
 * @note Buffer size is determined by the security package settings.
 *
 * @see channel_acquire()
 */
static void acquire_token_buffers ( struct secure_channel * channel )
{
    channel->itoken = channel_acquire(channel, channel->token_size);
    channel->otoken = channel_acquire(channel, channel->token_size);
}

/*!
 * @brief Release memory used for buffering security tokens.
 * @param channel Secure channel instance for which to release memory.
 *
 * @ingroup memory
 *
 * @see channel_release()
 */
static void release_token_buffers ( struct secure_channel * channel )
{
    channel_release(channel, channel->itoken), channel->otoken=0;
    channel_release(channel, channel->otoken), channel->otoken=0;
    memset(channel->buffers+0, 0, 4*sizeof(SecBuffer));
}

/*!
 * @brief Acquire memory used for buffering messages.
 * @param channel Secure channel instance for which to acquire memory.
 *
 * @ingroup memory
 *
 * @note Buffer size is determined by the security package settings.
 *
 * @see channel_acquire()
 */
static void acquire_stream_buffers ( struct secure_channel * channel )
{
    channel->emheader = channel_acquire(channel, channel->header_size);
    channel->emstream = channel_acquire(channel, channel->stream_size);
    channel->emfooter = channel_acquire(channel, channel->footer_size);
    channel->dmstream = channel_acquire(channel, channel->stream_size);
    prepare_embuffer(channel);
    prepare_dmbuffer(channel);
}

/*!
 * @brief Release memory used for buffering messages.
 * @param channel Secure channel instance for which to release memory.
 *
 * @ingroup memory
 *
 * @see channel_release()
 */
static void release_stream_buffers ( struct secure_channel * channel )
{
    channel_release(channel, channel->emheader); channel->emheader=0;
    channel_release(channel, channel->emstream); channel->emstream=0;
    channel_release(channel, channel->emfooter); channel->emfooter=0;
    channel_release(channel, channel->dmstream); channel->dmstream=0;
    memset(channel->buffers+4, 0, 8*sizeof(SecBuffer));
}

/*!
 * @brief Prepare get buffer for reception of negotiation token.
 * @param channel Secure channel instance for which to prepare token buffers.
 *
 * @ingroup buffers
 *
 * During negotiation, tokens produced locally are stored into the get buffer.
 * This function sets the @c pvBuffer and @c cbBuffer members to tell the
 * negotiation function where to write the token.  After the produced token is
 * sent, this function should be called to clear the token buffer and discard
 * invalidated data.
 *
 * @note This function does @e not allocate allocated memory.
 */
static void prepare_itbuffer ( struct secure_channel * channel )
{
    // 1st buffer contains in-bound token data.
    // 2nd buffer contains ?
    channel->itbuffer.ulVersion = SECBUFFER_VERSION;
    channel->itbuffer.pBuffers = channel->buffers+0;
    channel->itbuffer.cBuffers = 2;
    channel->itbuffer.pBuffers[0].BufferType = SECBUFFER_TOKEN;
    channel->itbuffer.pBuffers[0].cbBuffer   = 0;
    channel->itbuffer.pBuffers[0].pvBuffer   = channel->itoken;
    channel->itbuffer.pBuffers[1].BufferType = SECBUFFER_EMPTY;
    channel->itbuffer.pBuffers[1].cbBuffer   = 0;
    channel->itbuffer.pBuffers[1].pvBuffer   = 0;
}

/*!
 * @brief Prepare put buffer for reception of negotiation token.
 * @param channel Secure channel instance for which to prepare token buffers.
 *
 * @ingroup buffers
 *
 * During negotiation, tokens sent by the peer are stored into the put buffer.
 * This function sets the @c cbBuffer member to 0.  As data is received, token
 * content is copied into the buffer pointed to by @c pvBuffer and @c cbBuffer
 * is incremented to keep track of the amount of valid data.  Once tokens are
 * completely received, the negotiation function uses the data to compute a
 * token to send to the peer in order to complete negoitation.  After the token
 * is computed, this function should be called to clear the token buffer and
 * discard invalidated data.
 *
 * @note This function does @e not allocate allocated memory.
 */
static void prepare_otbuffer ( struct secure_channel * channel )
{
    // 1st buffer contains out-bound token data.
    // 2nd buffer contains in-bound unused data (start of 1st message).
    channel->otbuffer.ulVersion = SECBUFFER_VERSION;
    channel->otbuffer.pBuffers = channel->buffers+2;
    channel->otbuffer.cBuffers = 2;
    channel->otbuffer.pBuffers[0].BufferType = SECBUFFER_TOKEN;
    channel->otbuffer.pBuffers[0].cbBuffer   = channel->token_size;
    channel->otbuffer.pBuffers[0].pvBuffer   = channel->otoken;
    channel->otbuffer.pBuffers[1].BufferType = SECBUFFER_EMPTY;
    channel->otbuffer.pBuffers[1].cbBuffer   = 0;
    channel->otbuffer.pBuffers[1].pvBuffer   = 0;
}

/*!
 * @brief Prepare buffers for production of control token.
 *
 * @ingroup buffers
 */
static void prepare_ctbuffers ( struct secure_channel * channel )
{
    // if used, must be empty.
    channel->itbuffer.ulVersion = SECBUFFER_VERSION;
    channel->itbuffer.pBuffers = channel->buffers+0;
    channel->itbuffer.cBuffers = 1;
    channel->itbuffer.pBuffers[0].BufferType = SECBUFFER_EMPTY;
    channel->itbuffer.pBuffers[0].cbBuffer   = 0;
    channel->itbuffer.pBuffers[0].pvBuffer   = 0;
    // single buffer set to alert token.
    channel->otbuffer.ulVersion = SECBUFFER_VERSION;
    channel->otbuffer.pBuffers = channel->buffers+2;
    channel->otbuffer.cBuffers = 1;
    channel->otbuffer.pBuffers[0].BufferType = SECBUFFER_TOKEN;
    channel->otbuffer.pBuffers[0].cbBuffer   = channel->token_size;
    channel->otbuffer.pBuffers[0].pvBuffer   = channel->otoken;
}

static void prepare_dmbuffer ( struct secure_channel * channel )
{
    channel->dmbuffer.ulVersion = SECBUFFER_VERSION;
    channel->dmbuffer.pBuffers = channel->buffers+4;
    channel->dmbuffer.cBuffers = 4;
    channel->dmbuffer.pBuffers[0].BufferType = SECBUFFER_DATA;
    channel->dmbuffer.pBuffers[0].cbBuffer   = 0;
    channel->dmbuffer.pBuffers[0].pvBuffer   = channel->dmstream;
    channel->dmbuffer.pBuffers[1].BufferType = SECBUFFER_EMPTY;
    channel->dmbuffer.pBuffers[1].cbBuffer   = 0;
    channel->dmbuffer.pBuffers[1].pvBuffer   = 0;
    channel->dmbuffer.pBuffers[2].BufferType = SECBUFFER_EMPTY;
    channel->dmbuffer.pBuffers[2].cbBuffer   = 0;
    channel->dmbuffer.pBuffers[2].pvBuffer   = 0;
    channel->dmbuffer.pBuffers[3].BufferType = SECBUFFER_EMPTY;
    channel->dmbuffer.pBuffers[3].cbBuffer   = 0;
    channel->dmbuffer.pBuffers[3].pvBuffer   = 0;
}

static void prepare_embuffer ( struct secure_channel * channel )
{
    channel->embuffer.ulVersion = SECBUFFER_VERSION;
    channel->embuffer.pBuffers = channel->buffers+8;
    channel->embuffer.cBuffers = 4;
    channel->embuffer.pBuffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    channel->embuffer.pBuffers[0].cbBuffer   = channel->header_size;
    channel->embuffer.pBuffers[0].pvBuffer   = channel->emheader;
    channel->embuffer.pBuffers[1].BufferType = SECBUFFER_DATA;
    channel->embuffer.pBuffers[1].cbBuffer   = 0;
    channel->embuffer.pBuffers[1].pvBuffer   = channel->emstream;
    channel->embuffer.pBuffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    channel->embuffer.pBuffers[2].cbBuffer   = channel->footer_size;
    channel->embuffer.pBuffers[2].pvBuffer   = channel->emfooter;
    channel->embuffer.pBuffers[3].BufferType = SECBUFFER_EMPTY;
    channel->embuffer.pBuffers[3].cbBuffer   = 0;
    channel->embuffer.pBuffers[3].pvBuffer   = 0;
}

/*!
 * @brief Forward locally produced token using registered callbacks.
 *
 * @ingroup callback
 */
static void accept_token ( struct secure_channel * channel )
{
    ULONG i;
    for ( i = 0; (i < channel->otbuffer.cBuffers); ++i )
    {
        PSecBuffer buffer = &channel->otbuffer.pBuffers[i];
        if ( buffer->BufferType == SECBUFFER_TOKEN )
        {
              /* forward data. */
            channel->accept_encrypted(channel,
                buffer->pvBuffer, buffer->cbBuffer);
              /* expire token. */
            buffer->cbBuffer = 0;
        }
        if ( buffer->BufferType == SECBUFFER_EXTRA )
        {
              /* forward data. */
            channel->accept_overflow(channel,
                buffer->pvBuffer, buffer->cbBuffer);
              /* expire token. */
            buffer->cbBuffer = 0;
        }
    }
}

/*!
 * @brief Forward leftover message parts using registered callbacks.
 * @param channel Secure channel with unused data to return to the application.
 *
 * @ingroup callback
 *
 * When the amount of buffered data spans across token/message boundaries, not
 * all data is consumed by the negotiation/exhcange functions.  In that case,
 * the negotiation/exchange function marks unused data as "extra" and this
 * function is invoked to tell client code what data should be re-submitted for
 * negotiation/exchange.
 */
static void accept_overflow ( struct secure_channel * channel )
{
    ULONG i;
    for ( i = 0; (i < channel->dmbuffer.cBuffers); ++i )
    {
        PSecBuffer buffer = &channel->dmbuffer.pBuffers[i];
        if ( buffer->BufferType == SECBUFFER_EXTRA )
        {
              /* forward data. */
            channel->accept_overflow(channel,
                buffer->pvBuffer, buffer->cbBuffer);
              /* expire token. */
            buffer->cbBuffer = 0;
        }
    }
}

/*!
 * @brief Forward encrypted message content using registered callbacks.
 * @param channel Secure channel for which a message was just encrypted.
 *
 * @ingroup callback
 *
 * When a chunk of the stream is successfully encrypted, the locally produced
 * message must be transferred to the peer.  This function is invoked to forward
 * the message contents to client code for transfer.
 */
static void accept_encrypted_message ( struct secure_channel * channel )
{
    ULONG i;
      /* forward encrypted data. */
    for ( i = 0; (i < channel->embuffer.cBuffers); ++i )
    {
        PSecBuffer buffer = &channel->embuffer.pBuffers[i];
        if ( buffer->BufferType != SECBUFFER_EMPTY )
        {
            channel->accept_encrypted(channel,
                buffer->pvBuffer, buffer->cbBuffer);
            buffer->cbBuffer = 0;
        }
    }
      /* prepare for next message. */
    prepare_embuffer(channel);
}

/*!
 * @brief Forward decrypted message content using registered callbacks.
 * @param channel Secure channel for which a message was just decrypted.
 *
 * @ingroup callback
 *
 * When a received message is successfully decrypted, the chunk of the stream
 * must be processed by the application.  This function is invoked to forward
 * message contents to client code for processing.
 */
static void accept_decrypted_message ( struct secure_channel * channel )
{
    ULONG i;
    void * extradata = 0;
    size_t extrasize = 0;
      /* forward decrypted data. */
    for ( i = 0; (i < channel->dmbuffer.cBuffers); ++i )
    {
        PSecBuffer buffer = &channel->dmbuffer.pBuffers[i];
        if ( buffer->BufferType == SECBUFFER_DATA )
        {
            channel->accept_decrypted(channel,
                buffer->pvBuffer, buffer->cbBuffer);
            buffer->cbBuffer = 0;
        }
        if ( buffer->BufferType == SECBUFFER_EXTRA )
        {
            extrasize = buffer->cbBuffer;
            extradata = buffer->pvBuffer;
        }
    }
      /* prepare for next message. */
    prepare_dmbuffer(channel);
      /* schedule use of leftovers. */
    if ((extradata != 0) && (extrasize > 0))
    {
        channel_copy(&channel->embuffer.pBuffers[0],
            channel->stream_size, extradata, extrasize);
    }
}

/*!
 * @brief Acquire security credentials.
 *
 * @ingroup server
 */
static void secure_channel_server_setup (
    struct security_credentials * credentials,
    struct security_certificate * certificate )
{
    SECURITY_STATUS result;
    
      /* describe expected behavior. */
    credentials->identity.dwVersion = SCHANNEL_CRED_VERSION;
    credentials->identity.dwFlags =
        SCH_CRED_NO_DEFAULT_CREDS |
        SCH_CRED_NO_SYSTEM_MAPPER |
        SCH_CRED_REVOCATION_CHECK_CHAIN;
    credentials->identity.dwMinimumCipherStrength = 128;
    
      /* server-side certificate is required. */
    if ( certificate->handle && (certificate->handle != 0)) {
        credentials->identity.paCred = &certificate->handle;
        credentials->identity.cCreds = 1;
    }
    
      /* Acquire the handle. */
    result = AcquireCredentialsHandleW(
        0, PACKAGE_NAME, SECPKG_CRED_INBOUND,
        0, &credentials->identity, 0, 0,
        &credentials->handle, 0
        );
    if ( FAILED(result) )
    {
        printf("Server: AcquireCredentialsHandle(): 0x%08x\n", result);
    }
}

/*!
 * @brief Acquire security credentials.
 *
 * @ingroup client
 */
static void secure_channel_client_setup (
    struct security_credentials * credentials,
    struct security_certificate * certificate )
{
    SECURITY_STATUS result;
    
      /* describe expected behavior. */
    credentials->identity.dwVersion = SCHANNEL_CRED_VERSION;
    credentials->identity.dwFlags =
        SCH_CRED_NO_DEFAULT_CREDS |
        SCH_CRED_NO_SYSTEM_MAPPER |
        SCH_CRED_REVOCATION_CHECK_CHAIN;
    credentials->identity.dwMinimumCipherStrength = 128;
    
      /* client-side certificate is optional. */
    if ( certificate && (certificate->handle != 0) ) {
        credentials->identity.paCred = &certificate->handle;
        credentials->identity.cCreds = 1;
    }
    
      /* Acquire the handle. */
    result = AcquireCredentialsHandleW(
        0, PACKAGE_NAME, SECPKG_CRED_OUTBOUND,
        0, &credentials->identity, 0, 0,
        &credentials->handle, 0
        );
    if ( FAILED(result) )
    {
        printf("Client: AcquireCredentialsHandle(): 0x%08x\n", result);
    }
}

/*!
 * @brief Request channel limits from security package.
 * @param channel Channel for which buffer sizes are to be requested.
 *
 * @ingroup memory
 *
 * After negotiation is complete, the maximum buffer sizes may be determined by
 * checking the selected encryption algorithm (many parameters, including the
 * cipher strength influence the maximum message size).  This function is called
 * to ask the security package what those limits are, so that the proper amount
 * of memory can be allocated.
 */
static void secure_channel_fetch_sizes ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    SecPkgContext_StreamSizes sizes;
      /* fetch minimal buffer sizes. */
    result = QueryContextAttributes
        (&channel->handle, SECPKG_ATTR_STREAM_SIZES, &sizes);
    if ( FAILED(result) )
    {
        printf("%s: QueryContextAttributes(): 0x%08x\n",
            channel_role(channel), result);
    }
      /* copy interesting fields. */
    channel->header_size = sizes.cbHeader;
    channel->stream_size = sizes.cbMaximumMessage;
    channel->footer_size = sizes.cbTrailer;
}

/*!
 * @brief Apply some control information to the secure channel state.
 *
 * @ingroup control
 */
static SECURITY_STATUS channel_apply
    ( struct secure_channel * channel, void * data, DWORD size )
{
    SECURITY_STATUS result;
    SecBuffer token;
    SecBufferDesc buffer;
    token.BufferType = SECBUFFER_TOKEN;//SECBUFFER_PKG_PARAMS;
    token.cbBuffer = size;
    token.pvBuffer = data;
    buffer.ulVersion = SECBUFFER_VERSION;
    buffer.cBuffers = 1;
    buffer.pBuffers = &token;
      /* apply token buffer. */
    result = ApplyControlToken(&channel->handle, &buffer);
    if ( FAILED(result) )
    {
        printf("%s: ApplyControlToken(): 0x%08x\n",
            channel_role(channel), result);
        channel->state = secure_channel_failed;
        channel->error = secure_channel_fail;
    }
    return (result);
}

/*!
 * @brief Notify peer of request to renegotiate.
 *
 * @ingroup control
 */
static void channel_reconnect_status ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    SCHANNEL_SESSION_TOKEN token;
      /* setup token. */
    token.dwTokenType = SCHANNEL_SESSION;
    token.dwFlags = channel->allow_reconnect?
        SSL_SESSION_ENABLE_RECONNECTS : SSL_SESSION_DISABLE_RECONNECTS;
      /* apply token. */
    result = channel_apply(channel, &token, sizeof(token));
}

/*!
 * @brief Auxiliary, low-level, negotiation function.
 *
 * @ingroup client
 */
static SECURITY_STATUS secure_channel_client_token
    ( struct secure_channel * channel, PCredHandle lhs, PCredHandle rhs,
    PSecBufferDesc put, PSecBufferDesc get, SEC_WCHAR * target )
{
    SECURITY_STATUS result;
    DWORD query;
    DWORD reply;
      /* flags. */
    query =
        //ISC_REQ_ALLOCATE_MEMORY   |
        ISC_REQ_SEQUENCE_DETECT   |
        ISC_REQ_REPLAY_DETECT     |
        ISC_REQ_CONFIDENTIALITY   |
        ISC_RET_EXTENDED_ERROR    |
        ISC_REQ_STREAM            |
        ISC_REQ_MANUAL_CRED_VALIDATION;
      /* negotiate. */
    result = InitializeSecurityContextW(
        &channel->credentials.handle, lhs, target,
        query, 0, 0, put, 0, rhs, get, &reply, 0);
      /* */
    if ( FAILED(result) )
    {
        if ( result == SEC_E_INCOMPLETE_MESSAGE )
        {
            channel->need_push = 1;
            channel->need_pull = 0;
        }
        if ( result == SEC_I_RENEGOTIATE )
        {
            return (result);
        }
        if ( result != SEC_E_INCOMPLETE_MESSAGE )
        {
            printf("%s: InitializeSecurityContext(): 0x%08x\n",
                channel_role(channel), result);
        }
    }
      /* */
    if ((result == SEC_I_COMPLETE_NEEDED) ||
        (result == SEC_I_COMPLETE_AND_CONTINUE))
    {
        result = CompleteAuthToken(&channel->handle, &channel->embuffer);
        if ( FAILED(result) )
        {
            printf("%s: CompleteAuthToken(): 0x%08x\n",
                channel_role(channel), result);
        }
    }
    return (result);
}

/*!
 * @brief Produce initial negotiation token ("ClientHello").
 *
 * @ingroup client
 */
static void secure_channel_client_token_1 ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    prepare_otbuffer(channel);
    result = secure_channel_client_token(channel,
        0, &channel->handle, 0, &channel->otbuffer, 0);
      /* negotiation in progress. */
    if ( result == SEC_I_CONTINUE_NEEDED )
    {
        printf("Client: obtained context handle.\n");
        accept_token(channel);
        prepare_itbuffer(channel);
        channel->state = secure_channel_unsafe;
    }
}

/*!
 * @brief Produce additional negotiation tokens.
 *
 * @ingroup client
 */
static void secure_channel_client_token_2 ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    if ( channel->itbuffer.pBuffers[0].cbBuffer <= 0 ) {
        return;
    }
    prepare_otbuffer(channel);
    result = secure_channel_client_token(channel,
        &channel->handle, 0, &channel->itbuffer, &channel->otbuffer, 0);
      /* server requested client certificate and we didn't send one. */
    if ( result == SEC_I_INCOMPLETE_CREDENTIALS )
    {
        printf("Client: credentials required!\n");
        channel->state = secure_channel_failed;
        channel->error = secure_channel_fail;
    }
      /* token produced */
    if ( result == SEC_I_CONTINUE_NEEDED )
    {
        printf("Client: continue negotiation.\n");
        accept_token(channel);
        prepare_itbuffer(channel);
    }
      /* token produced, negotiation complete */
    if ( result == SEC_E_OK )
    {
        printf("Client: negotiation complete!\n");
        accept_token(channel);
        secure_channel_fetch_sizes(channel);
        acquire_stream_buffers(channel);
        //release_token_buffers(channel);
        channel->state = secure_channel_secure;
        //channel_reconnect_status(channel);
        channel->requested_renegotiation = 0;
    }
}

/*!
 * @brief Produce re-negotiation REQUEST token.
 * @ingroup client
 */
static void secure_channel_client_token_0 ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    prepare_otbuffer(channel);
    result = secure_channel_client_token(channel,
        &channel->handle, 0, 0, &channel->otbuffer, 0);
      /* token produced */
    if ( result == SEC_I_CONTINUE_NEEDED )
    {
        printf("Client: re-negotiation requested.\n");
        accept_token(channel);
        prepare_itbuffer(channel);
        channel->requested_renegotiation = 1;
    }
}

/*!
 * @brief Produce re-negotiation token (different from REQUEST token).
 * @ingroup client
 */
static void secure_channel_client_token_4 ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    prepare_otbuffer(channel);
    result = secure_channel_client_token(channel,
        &channel->handle, 0, &channel->itbuffer, &channel->otbuffer, 0);
      /* token produced. */
    if ( result == SEC_I_CONTINUE_NEEDED )
    {
        accept_token(channel);
        prepare_itbuffer(channel);
        channel->state = secure_channel_unsafe;
    }
}

/*!
 * @brief Produce alert token.
 *
 * @ingroup client
 */
static void secure_channel_client_token_5 ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    prepare_ctbuffers(channel);
    result = secure_channel_client_token(channel,
        &channel->handle, 0, &channel->itbuffer, &channel->otbuffer, 0);
      /* token produced. */
    if ( result == SEC_E_OK )
    {
        printf("Client: alert token produced.\n");
        accept_token(channel);
    }
}

/*!
 * @brief Produce shutdown notification token.
 *
 * @ingroup client
 */
static void secure_channel_client_token_3 ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    prepare_ctbuffers(channel);
    result = secure_channel_client_token(channel,
        &channel->handle, 0, &channel->itbuffer, &channel->otbuffer, 0);
      /* token produced */
    if ( result == SEC_E_OK )
    {
        printf("Client: shutdown has begun.\n");
        accept_token(channel);
        channel->state = secure_channel_expire;
    }
}

/*!
 * @brief Auxiliary, low-level, negotiation function.
 *
 * @ingroup server
 */
static SECURITY_STATUS secure_channel_server_token
    ( struct secure_channel * channel, PCredHandle lhs, PCredHandle rhs,
    PSecBufferDesc put, PSecBufferDesc get )
{
    SECURITY_STATUS result;
    DWORD query;
    DWORD reply;
      /* */
    query =
        //ASC_REQ_ALLOCATE_MEMORY   |
        ASC_REQ_SEQUENCE_DETECT   |
        ASC_REQ_REPLAY_DETECT     |
        ASC_REQ_CONFIDENTIALITY   |
        ASC_RET_EXTENDED_ERROR    |
        ASC_REQ_STREAM;
    if ( channel->mutual_authentication ) {
        query |= ASC_REQ_MUTUAL_AUTH;
    }
      /* */
    result = AcceptSecurityContext(
        &channel->credentials.handle, lhs, put, query, 0, rhs, get, &reply, 0);
      /* */
    if ( FAILED(result) )
    {
        if ( result == SEC_E_INCOMPLETE_MESSAGE )
        {
            channel->need_push = 1;
            channel->need_pull = 0;
        }
        if ( result != SEC_E_INCOMPLETE_MESSAGE )
        {
            printf("%s: AcceptSecurityContext(): 0x%08x\n",
                channel_role(channel), result);
            channel->state = secure_channel_failed;
            channel->error = secure_channel_fail;
        }
    }
      /* */
    if ((result == SEC_I_COMPLETE_NEEDED) ||
        (result == SEC_I_COMPLETE_AND_CONTINUE))
    {
        result = CompleteAuthToken(rhs, get);
        if ( FAILED(result) )
        {
            printf("%s: CompleteAuthToken(): 0x%08x\n",
                channel_role(channel), result);
            channel->state = secure_channel_failed;
            channel->error = secure_channel_fail;
        }
    }
    return (result);
}

/*!
 * @brief Produce initial neogitation token ("ServerHello").
 *
 * @ingroup server
 */
static void secure_channel_server_token_1 ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    if ( channel->itbuffer.pBuffers[0].cbBuffer <= 0 ) {
        return;
    }
    prepare_otbuffer(channel);
    result = secure_channel_server_token(channel,
        0, &channel->handle, &channel->itbuffer, &channel->otbuffer);
      /* token produced, continue negotiation. */
    if ( result == SEC_I_CONTINUE_NEEDED )
    {
        printf("Server: obtained context handle.\n");
        accept_token(channel);
        prepare_itbuffer(channel);
        channel->state = secure_channel_unsafe;
    }
}

/*!
 * @brief Produce additional neogitation tokens.
 *
 * @ingroup server
 */
static void secure_channel_server_token_2 ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    if ( channel->itbuffer.pBuffers[0].cbBuffer <= 0 ) {
        return;
    }
    prepare_otbuffer(channel);
    result = secure_channel_server_token(channel,
        &channel->handle, 0, &channel->itbuffer, &channel->otbuffer);
      /* token produced, continue negotiation. */
    if ( result == SEC_I_CONTINUE_NEEDED )
    {
        printf("Server: continue negotiation.\n");
        accept_token(channel);
        prepare_itbuffer(channel);
    }
      /* negotiation complete. */
    if ( result == SEC_E_OK )
    {
        printf("Server: negotiation complete!\n");
        accept_token(channel);
        secure_channel_fetch_sizes(channel);
        acquire_stream_buffers(channel);
        //release_token_buffers(channel);
        channel->state = secure_channel_secure;
        //channel_reconnect_status(channel);
    }
      /* peer rejected renegotiation request. */
    if ( result == SEC_I_NO_RENEGOTIATION )
    {
        printf("Server: re-negotiation rejected!\n");
        channel->state = secure_channel_failed;
        channel->error = secure_channel_fail;
    }
}

/*!
 * @brief Produce re-negotiation request token.
 *
 * @ingroup server
 */
static void secure_channel_server_token_0 ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    prepare_ctbuffers(channel);
    result = secure_channel_server_token(channel,
        &channel->handle, 0, 0, &channel->otbuffer);
      /* token produced, expect token in return. */
    if ( result == SEC_E_OK )
    {
        printf("Server: requested re-negotiation.\n");
        accept_token(channel);
        prepare_itbuffer(channel);
        /* NOTE: the client may have already encrypted one or messages, so the
             channel must keep decrypting data until the peer actually responds
             to the re-negotiation request. */
    }
}

/*!
 * @brief Produce shutdown notification token.
 *
 * @ingroup server
 */
static void secure_channel_server_token_3 ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    prepare_ctbuffers(channel);
    result = secure_channel_server_token(channel,
        &channel->handle, 0, &channel->itbuffer, &channel->otbuffer);
      /* token produced. */
    if ( result == SEC_E_OK )
    {
        printf("Server: shutdown initiated.\n");
        accept_token(channel);
        channel->state = secure_channel_expire;
    }
}

/*!
 * @brief Produce alert token.
 *
 * @ingroup server
 */
static void secure_channel_server_token_5 ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    prepare_ctbuffers(channel);
    result = secure_channel_server_token(channel,
        &channel->handle, 0, &channel->itbuffer, &channel->otbuffer);
      /* token produced. */
    if ( result == SEC_E_OK )
    {
        printf("Server: alert token produced.\n");
        accept_token(channel);
    }
}

/*!
 * @brief Trigger TLS alert.
 * @param channel Secure channel instance for which to prepare alert token.
 * @param fatal Set to 1 if the channel cannot recover from @a status.
 * @param status TLS status code (reason for failure).
 *
 * @ingroup control
 *
 * @param channel
 * @param fatal 1 if the event cannot be recovered from, 0 otherwise.
 * @param status TLS status.
 * @pre channel->state == secure_channel_secure
 */
static void channel_alert
    ( struct secure_channel * channel, int fatal, int status )
{
    SECURITY_STATUS result;
    SCHANNEL_ALERT_TOKEN alert;
    alert.dwTokenType   = SCHANNEL_ALERT;
    alert.dwAlertType   = fatal? TLS1_ALERT_FATAL : TLS1_ALERT_WARNING;
    alert.dwAlertNumber = status;
    result = channel_apply(channel, &alert, sizeof(alert));
    if ( result == SEC_E_OK )
    {
        //acquire_token_buffers(channel);
        if ( channel->role == secure_channel_client ) {
            secure_channel_client_token_5(channel);
        }
        if ( channel->role == secure_channel_server ) {
            secure_channel_server_token_5(channel);
        }
    }
}

/*!
 * @brief Encrypt chunk of stream as message.
 *
 * @ingroup exchange
 *
 * @param channel
 * @param buffer Buffer containing chunk to encrypt.
 * @pre channel->state == secure_channel_secure
 */
static void secure_channel_encrypt
    ( struct secure_channel * channel, PSecBufferDesc buffer )
{
    SECURITY_STATUS result;
    if ( buffer->pBuffers[1].cbBuffer <= 0 ) {
        return;
    }
    result = EncryptMessage(&channel->handle, 0, buffer, 0);
    if ( FAILED(result) )
    {
        printf("%s, EncryptMessage(): 0x%08x\n",
            channel_role(channel), result);
        channel->state = secure_channel_failed;
        channel->error = secure_channel_fail;
    }
      /* message encrypted, forward contents. */
    if ( result == SEC_E_OK ) {
        printf("%s, message encrypted.\n", channel_role(channel));
        accept_encrypted_message(channel);
    }
}

/*!
 * @brief Attempt to decrypt message as chunk of stream.
 *
 * @ingroup exchange
 *
 * @param channel
 * @param buffer Buffer containing message to decrypt.
 * @pre channel->state == secure_channel_secure
 */
static void secure_channel_decrypt
    ( struct secure_channel * channel, PSecBufferDesc buffer )
{
    SECURITY_STATUS result;
    if ( buffer->pBuffers[0].cbBuffer <= 0 ) {
        return;
    }
    result = DecryptMessage(&channel->handle, buffer, 0, 0);
    if ( FAILED(result) )
    {
        if ( result == SEC_E_INCOMPLETE_MESSAGE )
        {
            channel->need_push = 1;
            channel->need_pull = 0;
        }
        else if ( result != SEC_E_INCOMPLETE_MESSAGE )
        {
            printf("%s: DecryptMessage(): 0x%08x\n",
                channel_role(channel), result);
            channel->state = secure_channel_failed;
            channel->error = secure_channel_fail;
        }
    }
      /* peer has shutdown channel. */
    if ( result == SEC_I_CONTEXT_EXPIRED )
    {
        printf("%s: peer requested shutdown.\n", channel_role(channel));
        // Win2K bug: SEC_I_CONTEXT_EXPIRED might not be returned.
        //            Check for decrypted data buffer of length 0.
          /**/
        //release_stream_buffers(channel);
        //release_token_buffers(channel);
        channel->state = secure_channel_expire;
    }
      /* peer requested re-negotiation. */
    if ( result == SEC_I_RENEGOTIATE )
    {
        printf("%s: peer requested re-negotiation.\n", channel_role(channel));
        if ( channel->allow_renegotiation )
        {
            printf("  -- proceeding.\n");
            channel->state = secure_channel_unsafe;
            accept_overflow(channel);
            if ( channel->role == secure_channel_server )
            {
                prepare_itbuffer(channel);
                channel_copy(&channel->itbuffer.pBuffers[0],
                    channel->token_size,
                    channel->dmbuffer.pBuffers[1].pvBuffer,
                    channel->dmbuffer.pBuffers[1].cbBuffer);
                secure_channel_server_token_2(channel);
            }
            if ( channel->role == secure_channel_client )
            {
                  /* If the client requested re-negotiation, we've been
                     decrypting pending messages while waiting for an OK from
                     the server.  Thus, we've just received the server's reply
                     to the negotiation request; proceed! */
                if ( channel->requested_renegotiation )
                {
                    prepare_itbuffer(channel);
                    channel_copy(&channel->itbuffer.pBuffers[0],
                        channel->token_size,
                        channel->dmbuffer.pBuffers[1].pvBuffer,
                        channel->dmbuffer.pBuffers[1].cbBuffer);
                    secure_channel_client_token_2(channel);
                }
                else {
                    secure_channel_client_token_4(channel);
                }
            }
        }
        else
        {
            printf("  -- rejecting.\n");
            channel_alert(channel, 0, TLS1_ALERT_NO_RENEGOTIATION);
        }
    }
      /* message decrypted. */
    if ( result == SEC_E_OK ) {
        printf("%s: Message decrypted.\n", channel_role(channel));
        accept_overflow(channel);
        accept_decrypted_message(channel);
    }
}

void security_package_setup ( struct security_package * package )
{
    SECURITY_STATUS result;
    PSecPkgInfoW description;
    result = QuerySecurityPackageInfoW(PACKAGE_NAME, &description);
    if ( FAILED(result) )
    {
        printf("QuerySecurityPackageInfo(): 0x%08x\n", result);
        return;
    }
    package->token_size = description->cbMaxToken;
    FreeContextBuffer(description);
}

void secure_channel_clear ( struct secure_channel * channel )
{
    memset(channel, 0, sizeof(struct secure_channel));
    channel->state = secure_channel_virgin;
    channel->error = secure_channel_good;
    channel->allow_reconnect     = 1;
    channel->allow_renegotiation = 1;
    channel->itbuffer.ulVersion = SECBUFFER_VERSION;
    channel->itbuffer.pBuffers = channel->buffers+0;
    channel->itbuffer.cBuffers = 2;
    channel->otbuffer.ulVersion = SECBUFFER_VERSION;
    channel->otbuffer.pBuffers = channel->buffers+2;
    channel->otbuffer.cBuffers = 2;
    channel->embuffer.ulVersion = SECBUFFER_VERSION;
    channel->embuffer.pBuffers = channel->buffers+4;
    channel->embuffer.cBuffers = 4;
    channel->dmbuffer.ulVersion = SECBUFFER_VERSION;
    channel->dmbuffer.pBuffers = channel->buffers+8;
    channel->dmbuffer.cBuffers = 4;
}

void secure_channel_setup ( const struct security_package * package,
    struct secure_channel * channel, enum secure_channel_role role )
{
      /* acquire credentials. */
    channel->role = role;
    if ( channel->role == secure_channel_client )
    {
        secure_channel_client_setup
            (&channel->credentials, &channel->certificate);
    }
    if ( channel->role == secure_channel_server )
    {
        secure_channel_server_setup
            (&channel->credentials, &channel->certificate);
    }
      /* allocate token buffers for negotiation. */
    channel->token_size = package->token_size;
    acquire_token_buffers(channel);
      /* start negotiation. */
    if ( channel->role == secure_channel_client ) {
        secure_channel_client_token_1(channel);
    }
    if ( channel->role == secure_channel_server ) {
        prepare_itbuffer(channel);
    }
}

size_t secure_channel_push
    ( struct secure_channel * channel, const char * data, size_t size )
{
      /* feed channel until engine blocks or all data is processed. */
    size_t used = 0;
    while ((used < size) && (channel->error == secure_channel_good))
    {
          /* server starts negotiation in response to client token. */
        if ( channel->state == secure_channel_virgin )
        {
            used += channel_copy(&channel->itbuffer.pBuffers[0],
                channel->token_size, data+used, size-used);
            secure_channel_server_token_1(channel);
        }
           /* negotiation isn't quite finished, keep processing tokens. */
        if ( channel->state == secure_channel_unsafe )
        {
            used += channel_copy(&channel->itbuffer.pBuffers[0],
                channel->token_size, data+used, size-used);
            if ( channel->role == secure_channel_client ) {
                secure_channel_client_token_2(channel);
            }
            if ( channel->role == secure_channel_server ) {
                secure_channel_server_token_2(channel);
            }
        }
          /* session has been secured, encrypt data! */
        if ( channel->state == secure_channel_secure )
        {
              /* prepare data only, wait for manual flush. */
            used += channel_copy(&channel->embuffer.pBuffers[1],
                channel->stream_size, data+used, size-used);
        }
    }
    return (used);
}

size_t secure_channel_pull
    ( struct secure_channel * channel, const char * data, size_t size )
{
      /* feed channel until engine blocks or all data is processed. */
    size_t used = 0;
    while ((used < size) && (channel->error == secure_channel_good))
    {
          /* server starts negotiation in response to client token. */
        if ( channel->state == secure_channel_virgin )
        {
            used += channel_copy(&channel->itbuffer.pBuffers[0],
                channel->token_size, data+used, size-used);
            secure_channel_server_token_1(channel);
        }
           /* negotiation isn't quite finished, keep processing tokens. */
        if ( channel->state == secure_channel_unsafe )
        {
            used += channel_copy(&channel->itbuffer.pBuffers[0],
                channel->token_size, data+used, size-used);
            if ( channel->role == secure_channel_client ) {
                secure_channel_client_token_2(channel);
            }
            if ( channel->role == secure_channel_server ) {
                secure_channel_server_token_2(channel);
            }
        }
          /* can't decrypt data until channel is secured. */
        if ( channel->state == secure_channel_secure )
        {
              /* prepare data for decryption. */
            used += channel_copy(&channel->dmbuffer.pBuffers[0],
                channel->stream_size, data+used, size-used);
              /* attempt to decrypt message. */
            secure_channel_decrypt(channel, &channel->dmbuffer);
        }
    }
    return (used);
}

void secure_channel_flush ( struct secure_channel * channel )
{
    secure_channel_encrypt(channel, &channel->embuffer);
}

void secure_channel_renegotiate ( struct secure_channel * channel )
{
    if ( channel->role == secure_channel_client ) {
        secure_channel_client_token_0(channel);
    }
    if ( channel->role == secure_channel_server ) {
        secure_channel_server_token_0(channel);
    }
}

void secure_channel_close ( struct secure_channel * channel )
{
    SECURITY_STATUS result;
    DWORD token = SCHANNEL_SHUTDOWN;
    result = channel_apply(channel, &token, sizeof(token));
      /* token queued internally. */
    if ( result == SEC_E_OK )
    {
          /* extract token. */
        if ( channel->role == secure_channel_client ) {
            secure_channel_client_token_3(channel);
        }
        if ( channel->role == secure_channel_server ) {
            secure_channel_server_token_3(channel);
        }
    }
}
