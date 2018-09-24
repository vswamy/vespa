// Copyright 2018 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
#pragma once

#include "openssl_typedefs.h"
#include <vespa/vespalib/net/tls/crypto_codec.h>

namespace vespalib::net::tls::impl {

/*
 * Server-side codec facade for auto-inferring whether a client connection
 * is using TLS or legacy plaintext RPC by looking at the first N bytes
 * of a client's sent data. Depending on the outcome, client data will
 * either be dispatched to a CryptoCodec (TLS) or copied directly (plaintext).
 *
 * Makes certain assumptions on how the client will send ClientHello
 * records (in particular, no fragmentation).
 *
 * Must for obvious reasons only be used to wrap a codec in server mode.
 */
class TlsProtocolSnoopingCodec : public CryptoCodec {
    enum class CodecState {
        AwaitingHeaderMagic,
        PlaintextPassthrough,
        TlsConnection
    };

    std::unique_ptr<CryptoCodec> _tls_codec;
    CodecState _state;
public:
    // TODO inject nested codec instead?
    TlsProtocolSnoopingCodec(::SSL_CTX& ctx, Mode mode);
    ~TlsProtocolSnoopingCodec() override;

    size_t min_encode_buffer_size() const noexcept override;
    size_t min_decode_buffer_size() const noexcept override;

    HandshakeResult handshake(const char* from_peer, size_t from_peer_buf_size,
                              char* to_peer, size_t to_peer_buf_size) noexcept override;
    EncodeResult encode(const char* plaintext, size_t plaintext_size,
                        char* ciphertext, size_t ciphertext_size) noexcept override;
    DecodeResult decode(const char* ciphertext, size_t ciphertext_size,
                        char* plaintext, size_t plaintext_size) noexcept override;
};

}
