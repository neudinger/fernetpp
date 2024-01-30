#include <format>
#include <ranges>
#include <memory> // std::unique_ptr
#include <algorithm> // std::count

#include <cstring> // strnlen
#include <cassert> // assert

#include <openssl/core_names.h> // OSSL_MAC_PARAM_DIGEST
#include <openssl/rand.h>       // RAND_bytes
#include <openssl/err.h>        // ERR_load_crypto_strings

// https://github.com/fernet/spec/blob/master/Spec.md

#include <fernet/fernet.hh>

using EVP_CIPHER_CTX_unique_ptr = typename std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
using EVP_MD_CTX_unique_ptr = typename std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)>;
using EVP_MAC_CTX_unique_ptr = typename std::unique_ptr<EVP_MAC_CTX, decltype(&::EVP_MAC_CTX_free)>;
using EVP_MAC_unique_ptr = typename std::unique_ptr<EVP_MAC, decltype(&::EVP_MAC_free)>;
using OSSL_LIB_CTX_unique_ptr = typename std::unique_ptr<OSSL_LIB_CTX, decltype(&::OSSL_LIB_CTX_free)>;
using byte = uint8_t;

inline constexpr byte operator"" _uint8_t(unsigned long long arg) noexcept
{
    return static_cast<byte>(arg);
}
inline constexpr byte operator"" _byte(unsigned long long arg) noexcept
{
    return static_cast<byte>(arg);
}

// This document describes version 0x80 (currently the only version) of the fernet format.
static byte constexpr FERNET_VERSION{128_uint8_t},
    VERSION_SIZE{sizeof(byte)},
    TIME_SIZE{sizeof(std::time_t)},
    NONCE_SIZE{16_uint8_t},
    HMAC_SIZE{32_uint8_t}, /* = EVP_MD_get_size(EVP_MD_fetch(NULL, "SHA256", NULL)) */
    KEY_SIZE{32_uint8_t};

typedef union byte_time
{
    byte const *_timestamps_bytes_c; //[sizeof(uint64_t)];
    byte *_timestamps_bytes;         //[sizeof(uint64_t)];
    int64_t *_timestamps;
    byte_time(int64_t *timestamps) : _timestamps(timestamps) {}
    byte_time(Fernet::secure_string::const_iterator const &token_it) : _timestamps_bytes_c(reinterpret_cast<byte const *>(token_it.base())) {}
    byte_time(char const *token_ptr) : _timestamps_bytes_c(reinterpret_cast<byte const *>(token_ptr)) {}
} byte_time;

static inline uint64_t calcDecodeLength(Fernet::secure_string const &b64input)
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
static inline Fernet::secure_string base64Decode(Fernet::secure_string const &b64message,
                                                 uint64_t const paddingsize = 0)
{
    Fernet::secure_string outbuffer;
    if (std::empty(b64message))
        throw std::bad_array_new_length();

    uint64_t decodeBlocksize{0UL};
    uint64_t const decodeLen{calcDecodeLength(b64message) + 2UL};

    outbuffer.resize(decodeLen, 0);
    if ((decodeBlocksize = EVP_DecodeBlock(reinterpret_cast<byte *>(std::data(outbuffer)),
                                           reinterpret_cast<byte const *>(b64message.data()),
                                           static_cast<int>(strnlen(b64message.c_str(), std::ssize(b64message))))) > decodeLen or
        decodeBlocksize < decodeLen - 2UL)
        throw std::runtime_error(std::format("EVP_DecodeBlock not correctly decoded decodeBlocksize={} decodeLen={}", decodeBlocksize, decodeLen));

    outbuffer.resize(decodeBlocksize - paddingsize);
    return outbuffer;
}
static inline Fernet::secure_string base64Encode(Fernet::secure_string const &input)
{ // Encodes a binary safe base 64 string
    Fernet::secure_string outbuffer;

    if (std::empty(input) and not std::size(input))
        throw std::bad_array_new_length();

    uint64_t const encoded_size{4UL * ((std::ssize(input) + 2UL) / 3UL) + 1UL};
    outbuffer.reserve(encoded_size);
    outbuffer.resize(encoded_size - 1, 0);

    using EVP_EncodeBlock_rt = std::invoke_result<decltype(&EVP_EncodeBlock), unsigned char *, const unsigned char *, int>::type;

    if (EVP_EncodeBlock(reinterpret_cast<byte *>(std::data(outbuffer)),
                        reinterpret_cast<byte const *>(input.data()),
                        static_cast<int>(std::ssize(input))) not_eq static_cast<EVP_EncodeBlock_rt>(encoded_size - 1UL))
    {
        perror("EVP_EncodeBlock not correctly encoded\n");
        throw std::bad_alloc();
    }
    return outbuffer;
}
static inline void init()
{
    // OpenSSL_add_all_algorithms();
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_digest(EVP_sha256());
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha256());
    ERR_load_crypto_strings();
}
static inline void nonce_setup(byte *nonce)
{
    if (not RAND_bytes(nonce, NONCE_SIZE))
        throw std::runtime_error("RAND_bytes for iv failed");
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

    return standard_b64;
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

    uint64_t const
        paddingsize(std::count(urlsafe_b64.end() - 4, urlsafe_b64.end(), '=')),
        padding_required{4UL - ((strnlen(urlsafe_b64.c_str(), std::ssize(urlsafe_b64)) - paddingsize) % 4)};

    if (not(padding_required == paddingsize))
        for ([[maybe_unused]] auto const &_ :
             std::ranges::iota_view{0UL, padding_required - paddingsize})
        {
            std::ignore = _;
            urlsafe_b64.append("=");
        }
    return base64Decode(urlsafe_b64, padding_required);
}
static inline Fernet::secure_string HMAC_SHA256(Fernet::secure_string const &data,
                                                Fernet::secure_string const &key)
{
    Fernet::secure_string digest;

#if not defined(NDEBUG)
    uint32_t static const digest_length{static_cast<uint32_t>(EVP_MD_size(EVP_sha256()))};
    assert(HMAC_SIZE == digest_length);
#endif

    digest.resize(HMAC_SIZE, 0);

    OSSL_LIB_CTX_unique_ptr library_context(OSSL_LIB_CTX_new(), ::OSSL_LIB_CTX_free);
    EVP_MAC_unique_ptr mac_alg(EVP_MAC_fetch(library_context.get(), "HMAC", NULL), ::EVP_MAC_free);
    EVP_MAC_CTX_unique_ptr mac_ctx(EVP_MAC_CTX_new(mac_alg.get()), ::EVP_MAC_CTX_free);

    size_t out_len{0};
    std::string_view static const digest_name{"SHA256"};
    std::array const ossl_params{OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                                  const_cast<char *>(std::data(digest_name)),
                                                                  digest_name.size()),
                                 OSSL_PARAM_construct_end()};

    /* Initialise the HMAC operation */
    if (not EVP_MAC_init(mac_ctx.get(),
                         reinterpret_cast<byte const *>(std::data(key)),
                         16, ossl_params.data() /* params */))
        throw std::runtime_error("EVP_MAC_init() failed");

    /* Make one or more calls to process the data to be authenticated */
    if (not EVP_MAC_update(mac_ctx.get(),
                           reinterpret_cast<byte const *>(std::data(data)),
                           data.size()))
        throw std::runtime_error("EVP_MAC_update() failed");

    /* Make a call to the final with a NULL buffer to get the length of the MAC */
    if (!EVP_MAC_final(mac_ctx.get(), NULL, &out_len, 0))
        throw std::runtime_error("EVP_MAC_final() failed");

    /* Make one call to the final to get the MAC */
    if (!EVP_MAC_final(mac_ctx.get(),
                       reinterpret_cast<byte *>(std::data(digest)),
                       &out_len, out_len))
    {
        throw std::runtime_error("EVP_MAC_final() failed");
    }

    if (out_len not_eq HMAC_SIZE)
        throw std::runtime_error("Generated MAC has an unexpected length");

    return digest;
}
static inline Fernet::secure_string gen_nonce()
{
    Fernet::secure_string nonce;
    nonce.resize(NONCE_SIZE);
    if (not RAND_bytes(reinterpret_cast<byte *>(std::data(nonce)), NONCE_SIZE))
        throw std::runtime_error("RAND_bytes for iv failed");
    return nonce;
}
static inline Fernet::secure_string AES_128_CBC_decrypt(Fernet::secure_string const &key,
                                                        Fernet::secure_string const &nonce,
                                                        Fernet::secure_string const &ctext)
{
    Fernet::secure_string rtext;
    EVP_CIPHER_CTX_unique_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int outlen{0}, outlen2{0};

    if (not EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), NULL,
                               reinterpret_cast<byte const *>(key.data()),
                               reinterpret_cast<byte const *>(nonce.data())))
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    rtext.resize(ctext.size(), 0);

    if (not EVP_DecryptUpdate(ctx.get(),
                              reinterpret_cast<byte *>(std::data(rtext)),
                              &outlen,
                              reinterpret_cast<byte const *>(ctext.data()),
                              static_cast<int>(ctext.size())))
        throw std::runtime_error("EVP_DecryptUpdate failed");

    if (not EVP_DecryptFinal_ex(ctx.get(),
                                reinterpret_cast<byte *>(std::data(rtext)) + outlen,
                                &outlen2))
        throw std::runtime_error("EVP_DecryptFinal_ex failed");

    // Set recovered text size now that we know it
    rtext.resize(outlen + outlen2);
    return rtext;
}
static inline Fernet::secure_string AES_128_CBC_encrypt(Fernet::secure_string const &key,
                                                        Fernet::secure_string const &nonce,
                                                        Fernet::secure_string const &ptext)
{
    Fernet::secure_string ctext;
    EVP_CIPHER_CTX_unique_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    int outlen{0}, outlen2{0};

    static uint64_t const cipher_block_size{static_cast<uint64_t>(EVP_CIPHER_block_size(EVP_aes_128_cbc()))};
    uint64_t const buffer_size{ptext.size() + cipher_block_size};
    ctext.resize(buffer_size);

    if (not EVP_EncryptInit_ex2(ctx.get(), EVP_aes_128_cbc(),
                                reinterpret_cast<byte const *>(key.data()),
                                reinterpret_cast<byte const *>(nonce.data()), NULL))
        throw std::runtime_error("EVP_EncryptInit_ex2 failed");

    if (not EVP_EncryptUpdate(ctx.get(),
                              reinterpret_cast<byte *>(std::data(ctext)),
                              &outlen,
                              reinterpret_cast<byte const *>(std::data(ptext)),
                              static_cast<int>(ptext.size())))
        throw std::runtime_error("EVP_EncryptUpdate failed");

    if (not EVP_EncryptFinal_ex(ctx.get(),
                                reinterpret_cast<byte *>(std::data(ctext)) + outlen,
                                &outlen2))
        throw std::runtime_error("EVP_EncryptFinal_ex failed");

    // Set cipher text size now that we know it
    ctext.resize(outlen + outlen2);

    return ctext;
}
static inline int64_t timestamp_byteswap(int64_t const &timestamp)
{
    int64_t _timestamp{timestamp};
    if (std::endian::native not_eq std::endian::big)
        _timestamp = std::byteswap(timestamp);
    return _timestamp;
}

Fernet::Fernet(Fernet::secure_string const &key) : _key(urlsafe_base64Decode(key))
{
    if (std::ssize(this->_key) not_eq 32UL)
        throw std::runtime_error(std::format("key must be exactly 32 curent key size: {}", this->_key));
}
Fernet::secure_string Fernet::encrypt(Fernet::secure_string const &plain_text,
                                      std::time_t const current_time)
{
    assert(FERNET_VERSION == 128_uint8_t);
    int64_t time{timestamp_byteswap(current_time)};
    byte_time timestamp_view(&time);

    Fernet::secure_string token;
    token.reserve(VERSION_SIZE +
                  TIME_SIZE +
                  NONCE_SIZE +
                  (plain_text.size() + NONCE_SIZE) +
                  HMAC_SIZE);

    token.resize(VERSION_SIZE, 0);
    token[0] = FERNET_VERSION;

    std::span timestamp_range_view{timestamp_view._timestamps_bytes_c, TIME_SIZE};
    std::copy_n(timestamp_range_view.begin(), TIME_SIZE, std::back_inserter(token));
    Fernet::secure_string const nonce{gen_nonce()};
    std::copy_n(nonce.begin(), NONCE_SIZE, std::back_inserter(token));

    auto const enc_key_view{this->_key | std::views::drop(16)};
    Fernet::secure_string const cypher_text{AES_128_CBC_encrypt(/* key  */ {enc_key_view.data(), enc_key_view.size()},
                                                                /* nonce  */ nonce,
                                                                /* ptext  */ plain_text)};

    token.resize(token.size() + cypher_text.size());

    std::memcpy(std::data(token) + (VERSION_SIZE + TIME_SIZE + NONCE_SIZE),
                cypher_text.data(), cypher_text.size());

    Fernet::secure_string const hash{HMAC_SHA256(token, this->_key)};

    std::copy_n(hash.begin(), HMAC_SIZE, std::back_inserter(token));

    return urlsafe_base64Encode(token);
}

Fernet::secure_string Fernet::decrypt(Fernet::secure_string const &token,
                                      int64_t ttl,
                                      std::time_t current_time)
{
    Fernet::secure_string const decoded_token{urlsafe_base64Decode(token)};

    byte const version{static_cast<byte>((decoded_token | std::views::take(1)).front())};
    assert(version == 128_uint8_t && "Fernet version not know");

    if (version not_eq 128_uint8_t or
        version not_eq FERNET_VERSION)
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
    int64_t const timestamp{timestamp_byteswap(*token_timestamp._timestamps)};

    if (ttl and (timestamp + ttl) < current_time)
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

    return AES_128_CBC_decrypt({enc_key_view.data(), enc_key_view.size()}, nonce, cypher_text);
}
