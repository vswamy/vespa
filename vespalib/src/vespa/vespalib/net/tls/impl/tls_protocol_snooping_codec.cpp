// Copyright 2018 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
#include "tls_protocol_snooping_codec.h"
#include "openssl_crypto_codec_impl.h"
#include <vespa/vespalib/net/tls/crypto_exception.h>

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

constexpr size_t min_header_size_to_observe = 8;

// Precondition for all helper functions: buffer is at least `min_header_size_to_observe` bytes long

// From RFC 5246:
// 0x16 - Handshake content type byte of TLSCiphertext record
// 0x03 - First byte of 2-byte ProtocolVersion, always 3 on TLSv1.2 and v1.3
inline bool is_tls_handshake_packet(const char* buf) {
    return ((buf[0] == 0x16) && (buf[1] == 0x03));
}

// Next is the TLS minor version, either 1 or 3 depending on version (though the
// RFCs say it _should_ be 1 for backwards compatibility reasons).
// Yes, the TLS spec says that you should technically ignore the protocol version
// field here, but we want all the signals we can get.
inline bool is_expected_tls_protocol_version(const char* buf) {
    return ((buf[2] == 0x01) || (buf[2] == 0x03));
}

// Length is big endian u16 in bytes 3, 4
inline uint16_t tls_record_length(const char* buf) {
    return (uint16_t(static_cast<unsigned char>(buf[3]) << 8)
            + static_cast<unsigned char>(buf[4]));
}

// First byte of Handshake record in byte 5, which shall be ClientHello (0x01)
inline bool is_client_hello_handshake_record(const char* buf) {
    return (buf[5] == 0x01);
}

// Last 2 bytes are the 2 first big-endian bytes of a 3-byte Handshake
// record length field. No support for records that are large enough that
// the MSB should ever be non-zero.
inline bool client_hello_record_size_within_expected_bounds(const char* buf) {
    return (buf[6] == 0x00);
}

void log_tls_mismatch_warning(const char* description, const char* buf) {
    LOG(warning, "TLS ClientHello mismatch: %s", description);
    LOG(warning, "First 8 bytes of packet header: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
}

// The byte after the MSB of the 24-bit handshake record size should be equal
// to the most significant byte of the record length value, minus the Handshake
// record header size.
// Again, we make the assumption that ClientHello messages are not fragmented,
// so their max size must be <= 16KiB. This also just happens to be a lower
// number than the minimum FS4/FRT packet type byte at the same location.
// Oooh yeah, leaky abstractions to the rescue!
inline bool handshake_record_size_matches_length(const char* buf, uint16_t length) {
    return (static_cast<unsigned char>(buf[7]) == ((length - 4) >> 8));
}

// Precondition: buf is at least `min_header_size_to_observe` bytes long. This is the minimum amount
// of bytes always sent for a packet in our existing plaintext production protocols and
// therefore the maximum we can expect to always be present.
// Yes, this is a pragmatic and delightfully leaky abstraction.
bool probably_tls_client_hello(const char* buf) {
    if (!is_tls_handshake_packet(buf)) {
        LOG(debug, "TLS header handshake bytes did not match; not a TLS connection");
        return false;
    }
    // Logging note: we expect it is so rare to get a false positive handshake prefix
    // match when the connection is not TLS that we choose to log any further failed
    // checks as warnings to increase visibility.

    if (!is_expected_tls_protocol_version(buf)) {
        log_tls_mismatch_warning("ProtocolVersion mismatch", buf);
        return false;
    }
    // Length of TLS record follows. Must be <= 16KiB + 2048 (16KiB + 256 on v1.3).
    // We expect that the first record contains _only_ a ClientHello with no coalescing
    // and no fragmentation. This is technically a violation of the TLS spec, but this
    // particular detection logic is only intended to be used against other Vespa nodes
    // where we control frame sizes and where such fragmentation should not take place.
    // We also do not support TLSv1.3 0-RTT which may trigger early data.
    uint16_t length = tls_record_length(buf);
    if (length > (16384 + 2048)) {
        log_tls_mismatch_warning("ClientHello record size is greater than TLS spec allows", buf);
        return false;
    }
    if (!is_client_hello_handshake_record(buf)) {
        log_tls_mismatch_warning("header not ClientHello", buf);
        return false;
    }
    if (!client_hello_record_size_within_expected_bounds(buf)) {
        log_tls_mismatch_warning("ClientHello record is too big (fragmented?)", buf);
        return false;
    }
    if (!handshake_record_size_matches_length(buf, length)) {
        log_tls_mismatch_warning("record size mismatch", buf);
        return false;
    }
    // Hooray! It very probably most likely is a TLS connection! :D
    LOG(debug, "Handshake matches TLS heuristics, assuming TLS connection");
     return true;
}

}

HandshakeResult TlsProtocolSnoopingCodec::handshake(const char* from_peer, size_t from_peer_buf_size,
                                                               char* to_peer, size_t to_peer_buf_size) noexcept {
    if (_state == CodecState::AwaitingHeaderMagic) {
        if (from_peer_buf_size < min_header_size_to_observe) {
            return {0, 0, HandshakeResult::State::NeedsMorePeerData};
        }
        if (probably_tls_client_hello(from_peer)) {
            _state = CodecState::TlsConnection;
        } else {
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
