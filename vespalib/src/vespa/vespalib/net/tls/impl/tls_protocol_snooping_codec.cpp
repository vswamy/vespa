// Copyright 2018 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
#include "tls_protocol_snooping_codec.h"
#include "openssl_crypto_codec_impl.h"
#include <vespa/vespalib/net/tls/crypto_exception.h>
#include <vespa/vespalib/net/tls/protocol_snooping.h>

#include <vespa/log/log.h>
LOG_SETUP(".vespalib.net.tls.tls_protocol_snooping_codec");

#include <stdio.h>

namespace vespalib::net::tls::impl {

// Ideally we'd lazily initialize the codec, but that requires keeping a stable SSL_CTX ref,
// and SSL_CTX_up_ref isn't available until OpenSSL 1.1.0
TlsProtocolSnoopingCodec::TlsProtocolSnoopingCodec(::SSL_CTX& ctx, Mode mode)
    : _tls_codec(std::make_unique<OpenSslCryptoCodecImpl>(ctx, mode)),
      _state(CodecState::AwaitingHeaderMagic)
{
    LOG_ASSERT(mode == Mode::Server);
}

TlsProtocolSnoopingCodec::~TlsProtocolSnoopingCodec() = default;

size_t TlsProtocolSnoopingCodec::min_encode_buffer_size() const noexcept {
    return OpenSslCryptoCodecImpl::MaximumTlsFrameSize;
}

size_t TlsProtocolSnoopingCodec::min_decode_buffer_size() const noexcept {
    return OpenSslCryptoCodecImpl::MaximumFramePlaintextSize;
}

namespace {

void log_tls_snooping_warning(const char* description, const char* buf) {
    LOG(warning, "TLS ClientHello mismatch: %s", description);
    LOG(warning, "First 8 bytes of packet header: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
}

}

HandshakeResult TlsProtocolSnoopingCodec::handshake(const char* from_peer, size_t from_peer_buf_size,
                                                               char* to_peer, size_t to_peer_buf_size) noexcept {
    if (_state == CodecState::AwaitingHeaderMagic) {
        if (from_peer_buf_size < min_header_bytes_to_observe()) {
            return {0, 0, HandshakeResult::State::NeedsMorePeerData};
        }
        auto snoop_result = snoop_client_hello_header(from_peer);
        if (snoop_result == TlsSnoopingResult::ProbablyTls) {
            _state = CodecState::TlsConnection;
        } else {
            if (snoop_result != TlsSnoopingResult::HandshakeMismatch) {
                log_tls_snooping_warning(describe_result(snoop_result), from_peer);
            }
            _state = CodecState::PlaintextPassthrough;
        }
    }
    if (_state == CodecState::TlsConnection) {
        return _tls_codec->handshake(from_peer, from_peer_buf_size, to_peer, to_peer_buf_size);
    } else {
        // Note: no data is marked as consumed, we've just secretly peeked at it.
        // Let the first peeked bytes be used by the higher level protocol as usual.
        return {0, 0, HandshakeResult::State::Done};
    }
}

EncodeResult TlsProtocolSnoopingCodec::encode(const char* plaintext, size_t plaintext_size,
                                                         char* ciphertext, size_t ciphertext_size) noexcept {
    if (_state == CodecState::TlsConnection) {
        return _tls_codec->encode(plaintext, plaintext_size, ciphertext, ciphertext_size);
    } else { // Plaintext pass-through mode
        const auto to_copy = std::min(plaintext_size, ciphertext_size);
        if (to_copy != 0) { // if 0, may have nullptr buffer which is undefined for memcpy even with size == 0
            memcpy(ciphertext, plaintext, to_copy);
        }
        return {to_copy, to_copy, false};
    }
}

DecodeResult TlsProtocolSnoopingCodec::decode(const char* ciphertext, size_t ciphertext_size,
                                                         char* plaintext, size_t plaintext_size) noexcept {
    if (_state == CodecState::TlsConnection) {
        return _tls_codec->decode(ciphertext, ciphertext_size, plaintext, plaintext_size);
    } else { // Plaintext pass-through mode
        const auto to_copy = std::min(ciphertext_size, plaintext_size);
        if (to_copy != 0) { // if 0, may have nullptr buffer which is undefined for memcpy even with size == 0
            memcpy(plaintext, ciphertext, to_copy);
        }
        return {to_copy, to_copy, DecodeResult::State::OK};
    }
}

}
