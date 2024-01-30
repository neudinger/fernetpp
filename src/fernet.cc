#include <iostream>
#include <memory>
#include <type_traits>
#include <limits>
#include <stdexcept>
#include <bit>
#include <bitset>
#include <chrono>
#include <string_view>
#include <ranges>
#include <regex>
#include <format>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <ranges>
#include <algorithm>
#include <vector>
#include <array>
#include <forward_list>
#include <functional>
#include <iterator>
#include <concepts>
#include <list>
#include <span>

#include <ctime>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cassert>

#include <openssl/crypto.h> // OPENSSL_secure_clear_free
#include <openssl/evp.h>    // EVP_CIPHER_CTX_FLAG_WRAP_ALLOW
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
// https://github.com/fernet/spec/blob/master/Spec.md

#include "fernet.hh"

inline constexpr uint8_t operator"" _uint8_t(unsigned long long arg) noexcept
{
    return static_cast<uint8_t>(arg);
}

// This document describes version 0x80 (currently the only version) of the fernet format.
static Fernet::byte constexpr version{128_uint8_t},
    VERSION_SIZE{sizeof(Fernet::byte)},
    TIME_SIZE{sizeof(std::time_t)},
    NONCE_SIZE{16_uint8_t},
    HMAC_SIZE{32_uint8_t}, /* = EVP_MD_get_size(EVP_MD_fetch(NULL, "SHA256", NULL)) */
    KEY_SIZE{32_uint8_t};

using EVP_CIPHER_CTX_unique_ptr = typename std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
using EVP_MD_CTX_unique_ptr = typename std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)>;
using EVP_MAC_CTX_unique_ptr = typename std::unique_ptr<EVP_MAC_CTX, decltype(&::EVP_MAC_CTX_free)>;
using OSSL_LIB_CTX_unique_ptr = typename std::unique_ptr<OSSL_LIB_CTX, decltype(&::OSSL_LIB_CTX_free)>;

typedef union byte_time
{
    Fernet::byte const *_timestamps_bytes_c; //[sizeof(uint64_t)];
    Fernet::byte *_timestamps_bytes;         //[sizeof(uint64_t)];
    uint64_t *_timestamps;
    byte_time(uint64_t *timestamps) : _timestamps(timestamps) {}
    byte_time(Fernet::secure_string::const_iterator const &token_it) : _timestamps_bytes_c(reinterpret_cast<Fernet::byte const *>(token_it.base())) {}
    byte_time(char const *token_ptr) : _timestamps_bytes_c(reinterpret_cast<Fernet::byte const *>(token_ptr)) {}
} byte_time;

static uint64_t const calcDecodeLength(Fernet::secure_string const &b64input)
{ // Calculates the length of a decoded string
    uint64_t len{0UL}, padding{0UL};

    if (not(len = strnlen(b64input.data(), std::ssize(b64input))) or std::empty(b64input))
        throw std::runtime_error("b64input is empty");

    if (b64input[len - 1UL] == '=' && b64input[len - 2UL] == '=') // last two chars are =
        padding = 2UL;
    else if (b64input[len - 1UL] == '=') // last char is =
        padding = 1UL;

    return (len * 3UL) / 4UL - padding;
}
static Fernet::secure_string const base64Decode(Fernet::secure_string const &b64message,
                                                uint64_t const paddingsize = 0)
{
    // Decodes a base64 encoded string
    // std::cout << "b64message " << b64message << std::endl;
    // std::cout << "paddingsize " << paddingsize << std::endl;

    Fernet::secure_string outbuffer;
    if (std::empty(b64message))
        throw std::bad_array_new_length();

    uint64_t decodeBlocksize{0UL};
    uint64_t const decodeLen{calcDecodeLength(b64message) + 2UL};

    outbuffer.reserve(decodeLen);
    outbuffer.resize(decodeLen, 0);
    if ((decodeBlocksize = EVP_DecodeBlock(reinterpret_cast<Fernet::byte *>(std::data(outbuffer)),
                                           reinterpret_cast<Fernet::byte const *>(b64message.data()),
                                           strnlen(b64message.c_str(), std::ssize(b64message)))) > decodeLen or
        decodeBlocksize < decodeLen - 2UL)
        throw std::runtime_error(std::format("EVP_DecodeBlock not correctly decoded decodeBlocksize={} decodeLen={}", decodeBlocksize, decodeLen));

    outbuffer.resize(decodeBlocksize - paddingsize);
    return outbuffer;
}
static Fernet::secure_string base64Encode(Fernet::secure_string const &input)
{ // Encodes a binary safe base 64 string
    Fernet::secure_string outbuffer;

    if (std::empty(input) and not std::size(input))
        throw std::bad_array_new_length();
    uint64_t const encoded_size{4UL * ((std::size(input) + 2UL) / 3UL) + 1UL};
    outbuffer.reserve(encoded_size);
    outbuffer.resize(encoded_size - 1, 0);
    if (EVP_EncodeBlock(reinterpret_cast<Fernet::byte *>(std::data(outbuffer)),
                        reinterpret_cast<Fernet::byte const *>(input.data()),
                        std::size(input)) not_eq encoded_size - 1)
    {
        perror("EVP_EncodeBlock not correctly encoded\n");
        throw std::bad_alloc();
    }
    // outbuffer.resize(encoded_size - 1);
    return std::move(outbuffer);
}
static Fernet::secure_string urlsafe_base64Encode(Fernet::secure_string const &input)
{
    auto standard_b64(base64Encode(input));
    for (auto &val : standard_b64)
        switch (val)
        {
        case '+':
            val = '-';
            break;
        case '/':
            val = '_';
            break;
        default:
            break;
        }

    return std::move(standard_b64);
}
static Fernet::secure_string urlsafe_base64Decode(Fernet::secure_string const &input)
{

    auto urlsafe_b64(input);

    for (auto &val : urlsafe_b64)
        switch (val)
        {
        case '-':
            val = '+';
            break;
        case '_':
            val = '/';
            break;
        default:
            break;
        }
    uint64_t const paddingsize = std::ranges::count(urlsafe_b64, '=');
    std::cout << __LINE__ << " paddingsize " << paddingsize << std::endl;

    uint64_t const padding_required = 4 - ((strnlen(urlsafe_b64.c_str(), std::ssize(urlsafe_b64)) - paddingsize) % 4);
    std::cout << __LINE__ << " padding_required " << padding_required << std::endl;

    if (not(padding_required == paddingsize))
        for ([[maybe_unused]] auto const &_ :
             std::ranges::iota_view{0UL, padding_required - paddingsize})
        {
            std::ignore = _;
            urlsafe_b64.append("=");
        }
    return std::move(base64Decode(urlsafe_b64, paddingsize));
}

Fernet::Fernet(Fernet::secure_string const &key) : _key(urlsafe_base64Decode(key))
{
    // std::cout << _key << std::endl;
    // std::cout << strnlen(this->_key.c_str(), std::ssize(this->_key) + 1) << std::endl;
    std::cout << std::ssize(this->_key) << std::endl;
    if (strnlen(this->_key.c_str(), std::ssize(this->_key) + 1) not_eq 32UL)
        throw std::runtime_error("key must be exactly 32");
}
void Fernet::init()
{
    // OpenSSL_add_all_algorithms();
    // ERR_load_crypto_strings();
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_digest(EVP_sha256());
}
Fernet::secure_string Fernet::HMAC_SHA256(Fernet::secure_string const &data,
                                          Fernet::secure_string const &key)
{
    Fernet::secure_string digest;

    uint32_t static const digest_length{static_cast<uint32_t>(EVP_MD_size(EVP_sha256()))};
    digest.resize(digest_length);

    size_t out_len = 0;
    // EVP_MD_CTX_unique_ptr mctx(EVP_MD_CTX_new(), ::EVP_MD_CTX_free);
    OSSL_LIB_CTX_unique_ptr library_context(OSSL_LIB_CTX_new(), ::OSSL_LIB_CTX_free);

    EVP_MAC_CTX_unique_ptr mac_ctx(EVP_MAC_CTX_new(EVP_MAC_fetch(library_context.get(), "HMAC", NULL)), ::EVP_MAC_CTX_free);

    std::string_view digest_name{"SHA256"};
    std::array ossl_params{OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                            const_cast<char *>(std::data(digest_name)),
                                                            digest_name.size()),
                           OSSL_PARAM_construct_end()};

    assert(HMAC_SIZE == digest_length);

    /* Initialise the HMAC operation */
    if (not EVP_MAC_init(mac_ctx.get(),
                         reinterpret_cast<Fernet::byte const *>(std::data(key)),
                         16, ossl_params.data() /* params */))
    {
        throw std::runtime_error("EVP_MAC_init() failed");
    }

    /* Make one or more calls to process the data to be authenticated */
    if (not EVP_MAC_update(mac_ctx.get(),
                           reinterpret_cast<Fernet::byte const *>(std::data(data)),
                           data.size()))
    {
        throw std::runtime_error("EVP_MAC_update() failed");
    }

    /* Make a call to the final with a NULL buffer to get the length of the MAC */
    if (!EVP_MAC_final(mac_ctx.get(), NULL, &out_len, 0))
    {
        throw std::runtime_error("EVP_MAC_final() failed");
    }

    std::cout << __LINE__ << " out_len " << out_len << std::endl;

    /* Make one call to the final to get the MAC */
    if (!EVP_MAC_final(mac_ctx.get(),
                       reinterpret_cast<Fernet::byte *>(std::data(digest)),
                       &out_len, out_len))
    {
        throw std::runtime_error("EVP_MAC_final() failed");
    }

    BIO_dump_indent_fp(stdout, digest.data(), out_len, 2);

    std::cout << __LINE__ << " out_len " << out_len << " digest_length " << digest_length << std::endl;

    if (out_len != digest_length)
    {
        throw std::runtime_error("Generated MAC has an unexpected length");
    }

    return digest;
}
Fernet::secure_string Fernet::gen_nonce()
{
    Fernet::secure_string nonce = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    // Fernet::secure_string nonce;
    // nonce.resize(NONCE_SIZE);
    // if (RAND_bytes(reinterpret_cast<Fernet::byte *>(std::data(nonce)), NONCE_SIZE) not_eq 1)
    //     throw std::runtime_error("RAND_bytes for iv failed");
    return std::move(nonce);
}
void Fernet::nonce_setup(Fernet::byte *nonce)
{
    if (RAND_bytes(nonce, NONCE_SIZE) not_eq 1)
        throw std::runtime_error("RAND_bytes for iv failed");
}
Fernet::secure_string Fernet::AES_128_CBC_decrypt(Fernet::secure_string const &key,
                                                  Fernet::secure_string const &nonce,
                                                  Fernet::secure_string const &ctext)
{
    Fernet::secure_string rtext;
    EVP_CIPHER_CTX_unique_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int outlen{0}, outlen2{0};

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), NULL,
                           reinterpret_cast<Fernet::byte const *>(key.data()),
                           reinterpret_cast<Fernet::byte const *>(nonce.data())) not_eq 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    rtext.resize(ctext.size(), 0);

    if (EVP_DecryptUpdate(ctx.get(),
                          reinterpret_cast<Fernet::byte *>(std::data(rtext)),
                          &outlen,
                          reinterpret_cast<Fernet::byte const *>(ctext.data()),
                          static_cast<int>(ctext.size())) not_eq 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");

    if (not EVP_DecryptFinal_ex(ctx.get(),
                                reinterpret_cast<Fernet::byte *>(std::data(rtext)) + outlen,
                                &outlen2))
        throw std::runtime_error("EVP_DecryptFinal_ex failed");

    // Set recovered text size now that we know it
    rtext.resize(outlen + outlen2);
    return rtext;
}
Fernet::secure_string Fernet::AES_128_CBC_encrypt(Fernet::secure_string const &key,
                                                  Fernet::secure_string const &nonce,
                                                  Fernet::secure_string const &ptext)
{
    Fernet::secure_string ctext;
    EVP_CIPHER_CTX_unique_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    int outlen{0}, outlen2{0};

    static uint64_t const cipher_block_size{(uint64_t)EVP_CIPHER_block_size(EVP_aes_128_cbc())};
    uint64_t const buffer_size{ptext.size() + cipher_block_size};
    ctext.resize(buffer_size);

    if (not EVP_EncryptInit_ex2(ctx.get(), EVP_aes_128_cbc(),
                                reinterpret_cast<Fernet::byte const *>(key.data()),
                                reinterpret_cast<Fernet::byte const *>(nonce.data()), NULL))
        throw std::runtime_error("EVP_EncryptInit_ex2 failed");

    if (not EVP_EncryptUpdate(ctx.get(),
                              reinterpret_cast<Fernet::byte *>(std::data(ctext)),
                              &outlen,
                              reinterpret_cast<Fernet::byte const *>(std::data(ptext)),
                              static_cast<int>(ptext.size())))
        throw std::runtime_error("EVP_EncryptUpdate failed");

    if (not EVP_EncryptFinal_ex(ctx.get(),
                                reinterpret_cast<Fernet::byte *>(std::data(ctext)) + outlen,
                                &outlen2))
        throw std::runtime_error("EVP_EncryptFinal_ex failed");

    // Set cipher text size now that we know it
    ctext.resize(outlen + outlen2);

    return std::move(ctext);
}
uint64_t Fernet::timestamp_byteswap(uint64_t const &timestamp)
{
    uint64_t _timestamp{timestamp};
    if (std::endian::native not_eq std::endian::big)
        _timestamp = std::byteswap(timestamp);
    return _timestamp;
}

Fernet::secure_string Fernet::encrypt(Fernet::secure_string const &plain_text,
                                      std::time_t const current_time)
{
    assert(version == 128_uint8_t);
    uint64_t time{timestamp_byteswap(current_time)};
    byte_time timestamp_view(&time);

    Fernet::secure_string token;
    token.reserve(VERSION_SIZE +
                  TIME_SIZE +
                  NONCE_SIZE +
                  (plain_text.size() + NONCE_SIZE) +
                  HMAC_SIZE);

    token.resize(VERSION_SIZE, 0);
    token[0] = version;

    std::span timestamp_range_view{timestamp_view._timestamps_bytes_c, TIME_SIZE};
    std::copy_n(timestamp_range_view.begin(), TIME_SIZE, std::back_inserter(token));
    Fernet::secure_string const nonce{gen_nonce()};
    std::copy_n(nonce.begin(), NONCE_SIZE, std::back_inserter(token));

    auto const enc_key_view{this->_key | std::views::drop(16)};
    Fernet::secure_string enc_key(enc_key_view.data(), enc_key_view.size());
    Fernet::secure_string cypher_text{Fernet::AES_128_CBC_encrypt(enc_key, nonce, plain_text)};

    token.resize(token.size() + cypher_text.size());

    std::memcpy(std::data(token) + (VERSION_SIZE + TIME_SIZE + NONCE_SIZE),
                cypher_text.data(), cypher_text.size());

    Fernet::secure_string const hash{HMAC_SHA256(token, this->_key)};

    std::copy_n(hash.begin(), HMAC_SIZE, std::back_inserter(token));

    return urlsafe_base64Encode(token);
}

Fernet::secure_string Fernet::decrypt(Fernet::secure_string const &token,
                                      uint64_t ttl,
                                      std::time_t current_time)
{
    Fernet::secure_string const decoded_token{urlsafe_base64Decode(token)};

    Fernet::byte version{static_cast<byte>((decoded_token | std::views::take(1)).front())};
    assert(version == 128_uint8_t && "Fernet version not know");

    if (version not_eq 128_uint8_t)
        throw std::runtime_error("Fernet version not know");

    Fernet::secure_string nonce;
    nonce.reserve(NONCE_SIZE);
    std::copy_n(decoded_token.begin() + (VERSION_SIZE + TIME_SIZE),
                NONCE_SIZE,
                std::back_inserter(nonce));

    auto const token_timestamp_view{decoded_token |
                                    std::views::drop(VERSION_SIZE) |
                                    std::views::take(TIME_SIZE)};
    byte_time token_timestamp(token_timestamp_view.data());
    uint64_t const timestamp{timestamp_byteswap(*token_timestamp._timestamps)};

    if (ttl and (timestamp - ttl) < 0)
        throw std::runtime_error("TTL Expired");

    Fernet::secure_string const token_data{std::string_view(decoded_token.begin(),
                                                            decoded_token.end() - HMAC_SIZE)};

    Fernet::secure_string hash_computed;
    hash_computed.reserve(HMAC_SIZE);

    std::ranges::copy(HMAC_SHA256(token_data, this->_key), std::back_inserter(hash_computed));

    Fernet::secure_string const hash_recieved{std::string_view(decoded_token.end() - HMAC_SIZE,
                                                               decoded_token.end())};

    if (not std::ranges::equal(hash_computed, hash_recieved))
        throw std::runtime_error(std::format("hash_computed {} not eq hash_recieved {}", hash_computed, hash_recieved));

    Fernet::secure_string const cypher_text{std::string_view(decoded_token.begin() +
                                                                 VERSION_SIZE +
                                                                 TIME_SIZE +
                                                                 NONCE_SIZE,
                                                             decoded_token.end() - HMAC_SIZE)};

    auto const enc_key_view{this->_key | std::views::drop(16)};

    return std::move(AES_128_CBC_decrypt({enc_key_view.data(), enc_key_view.size()}, nonce, cypher_text));
}