#include <cstring> // memcpy

#include <openssl/core_names.h> // OSSL_MAC_PARAM_DIGEST
#include <openssl/rand.h>       // RAND_bytes
#include <openssl/err.h>        // ERR_load_crypto_strings
#include <expected>
#include <bit>
#include <format>
#include <ranges>
#include <memory>    // std::unique_ptr
#include <algorithm> // std::count

// https://github.com/fernet/spec/blob/master/Spec.md

#include <fernet/fernet.hh>

using EVP_CIPHER_CTX_unique_ptr = typename std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
using EVP_MD_CTX_unique_ptr = typename std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)>;
using EVP_MAC_CTX_unique_ptr = typename std::unique_ptr<EVP_MAC_CTX, decltype(&::EVP_MAC_CTX_free)>;
using EVP_MAC_unique_ptr = typename std::unique_ptr<EVP_MAC, decltype(&::EVP_MAC_free)>;
using OSSL_LIB_CTX_unique_ptr = typename std::unique_ptr<OSSL_LIB_CTX, decltype(&::OSSL_LIB_CTX_free)>;
using byte = uint8_t;

[[nodiscard("Byte literal must be used")]]
inline constexpr byte
operator"" _uint8_t(unsigned long long arg) noexcept
{
    return static_cast<byte>(arg);
}

[[nodiscard("Byte literal must be used")]]
inline constexpr byte
operator"" _byte(unsigned long long arg) noexcept
{
    return static_cast<byte>(arg);
}

// This document describes version 0x80 (currently the only version) of the fernet format.
static byte constexpr FERNET_VERSION{128_uint8_t},
    CYPHER_BLOCK_SIZE{16_uint8_t},
    VERSION_SIZE{sizeof(byte)},
    TIME_SIZE{sizeof(std::time_t)},
    NONCE_SIZE{16_uint8_t},
    HMAC_SIZE{32_uint8_t}, /* = EVP_MD_get_size(EVP_MD_fetch(NULL, "SHA256", NULL)) */
    KEY_SIZE{32_uint8_t};

typedef union [[nodiscard]] byte_time
{
    byte const *_timestamps_bytes_c;
    byte *_timestamps_bytes;
    int64_t *_timestamps;
    byte_time(int64_t *timestamps) : _timestamps(timestamps) {}
    byte_time(Fernet::secure_string::const_iterator const &token_it) : _timestamps_bytes_c(reinterpret_cast<byte const *>(token_it.base())) {}
    byte_time(char const *token_ptr) : _timestamps_bytes_c(reinterpret_cast<byte const *>(token_ptr)) {}
} byte_time;

[[nodiscard("Must use calcDecodeLength return value")]] [[using gnu: always_inline, pure, hot, access(read_only, 1)]]
static inline std::expected<uint64_t, std::string>
calcDecodeLength(Fernet::secure_string const &b64input) noexcept
{
    uint64_t const len{b64input.size()};

    if (not len) [[unlikely]]
        return std::unexpected("calcDecodeLength input: b64input is empty");

    uint64_t const padding(std::count(b64input.end() - 4, b64input.end(), '='));

    return (((len * 3UL) / 4UL) - padding);
}

[[nodiscard("Must use base64Decode return value")]] [[using gnu: always_inline, pure, hot, access(read_only, 1)]]
static inline std::expected<Fernet::secure_string, std::string>
base64Decode(Fernet::secure_string const &b64message) noexcept
{
    Fernet::secure_string outbuffer;

    if (b64message.empty()) [[unlikely]]
        return std::unexpected("base64Decode input: b64message is empty");

    FERNET_ASSIGN_OR_RAISE(uint64_t const decodeLen, calcDecodeLength(b64message))

    outbuffer.resize(decodeLen + 2UL, '\0');
    if (EVP_DecodeBlock(reinterpret_cast<byte *>(outbuffer.data()),
                        reinterpret_cast<byte const *>(b64message.data()),
                        static_cast<int>(b64message.size())) == -1) [[unlikely]]
        return std::unexpected(std::format("EVP_DecodeBlock not correctly decoded : can not decode the base64 of {}", b64message.c_str()));
    outbuffer.resize(decodeLen);
    return outbuffer;
}

[[nodiscard("Must use base64Encode return value")]] [[using gnu: always_inline, pure, hot, access(read_only, 1)]]
static inline std::expected<Fernet::secure_string, std::string>
base64Encode(Fernet::secure_string const &input) noexcept
{
    Fernet::secure_string outbuffer;

    if (not input.size()) [[unlikely]]
        return std::unexpected("base64Encode input: input is empty");

    uint64_t const encoded_size{4UL * ((input.size() + 2UL) / 3UL)};
    outbuffer.resize(encoded_size, '\0');

    using EVP_EncodeBlock_rt = std::invoke_result<decltype(&EVP_EncodeBlock), unsigned char *, const unsigned char *, int>::type;

    if (EVP_EncodeBlock(reinterpret_cast<byte *>(outbuffer.data()),
                        reinterpret_cast<byte const *>(input.data()),
                        static_cast<int>(input.size())) not_eq static_cast<EVP_EncodeBlock_rt>(encoded_size)) [[unlikely]]
        return std::unexpected("EVP_EncodeBlock not correctly encoded");
    return outbuffer;
}

[[noreturn]] [[using gnu: always_inline, hot]]
static inline void
init()
{
    // OpenSSL_add_all_algorithms();
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_digest(EVP_sha256());
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha256());
    ERR_load_crypto_strings();
}

[[nodiscard("Must use urlsafe base64Encode return value")]] [[using gnu: always_inline, pure, hot, access(read_only, 1)]]
static inline std::expected<Fernet::secure_string, std::string>
urlsafe_base64Encode(Fernet::secure_string const &input) noexcept
{
    FERNET_ASSIGN_OR_RAISE(auto standard_b64, base64Encode(input))
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

[[nodiscard("Must use urlsafe base64 return value")]] [[using gnu: always_inline, pure, hot, access(read_only, 1)]]
static inline std::expected<Fernet::secure_string, std::string>
urlsafe_base64Decode(Fernet::secure_string const &input) noexcept
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

    if (urlsafe_b64.size() % 4UL) [[likely]]
        for ([[maybe_unused]] auto const &_ :
             std::ranges::iota_view{0UL, (4UL - (urlsafe_b64.size() % 4UL))})
        {
            std::ignore = _;
            urlsafe_b64.append("=");
        }
    return base64Decode(urlsafe_b64);
}

[[nodiscard("Must use HMAC_SHA256 return value")]] [[using gnu: always_inline, pure, hot, access(read_only, 1), access(read_only, 2)]]
static inline std::expected<std::array<byte, HMAC_SIZE>, std::string>
HMAC_SHA256(Fernet::secure_string const &data,
            Fernet::secure_string const &key) noexcept
{
    std::array<byte, HMAC_SIZE> digest{0};

    // #if not defined(NDEBUG)
    //     uint32_t static const digest_length{static_cast<uint32_t>(EVP_MD_size(EVP_sha256()))};
    //     assert(HMAC_SIZE == digest_length && "HMAC_SIZE == digest_length must be equal");
    // #endif

    OSSL_LIB_CTX_unique_ptr library_context(OSSL_LIB_CTX_new(), ::OSSL_LIB_CTX_free);
    EVP_MAC_unique_ptr mac_alg(EVP_MAC_fetch(library_context.get(), "HMAC", NULL), ::EVP_MAC_free);
    EVP_MAC_CTX_unique_ptr mac_ctx(EVP_MAC_CTX_new(mac_alg.get()), ::EVP_MAC_CTX_free);
    std::string_view static const digest_name{"SHA256"};
    std::array const ossl_params{OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                                  const_cast<char *>(digest_name.data()),
                                                                  digest_name.size()),
                                 OSSL_PARAM_construct_end()};
    size_t out_len{0};
    /* Initialise the HMAC SHA256 operation */
    if (not EVP_MAC_init(mac_ctx.get(),
                         reinterpret_cast<byte const *>(key.data()),
                         key.size(), ossl_params.data())) [[unlikely]]
        return std::unexpected("EVP_MAC_init() failed");

    /* Make one or more calls to process the data to be authenticated */
    if (not EVP_MAC_update(mac_ctx.get(),
                           reinterpret_cast<byte const *>(data.data()),
                           data.size())) [[unlikely]]
        return std::unexpected("EVP_MAC_update() failed");

    /* Make a call to the final with a NULL buffer to get the length of the MAC */
    if (not EVP_MAC_final(mac_ctx.get(), NULL, &out_len, 0)) [[unlikely]]
        return std::unexpected("EVP_MAC_final() failed");

    /* Make one call to the final to get the MAC */
    if (not EVP_MAC_final(mac_ctx.get(),
                          reinterpret_cast<byte *>(digest.data()),
                          &out_len, out_len)) [[unlikely]]
        return std::unexpected("EVP_MAC_final() failed");

    if (out_len not_eq HMAC_SIZE) [[unlikely]]
        return std::unexpected("Generated MAC has an unexpected length");

    return digest;
}

[[nodiscard("Must use HMAC_SHA256 return value")]] [[using gnu: always_inline, pure, hot]]
static inline std::expected<std::array<byte, NONCE_SIZE>, std::string>
gen_nonce() noexcept
{
    std::array<byte, NONCE_SIZE> nonce{0};
    if (not RAND_bytes(reinterpret_cast<byte *>(nonce.data()), NONCE_SIZE)) [[unlikely]]
        return std::unexpected("RAND_bytes for iv failed");
    return nonce;
}

[[nodiscard("Must use AES_128_CBC_decrypt return value")]] [[using gnu: always_inline, pure, hot, access(read_only, 1), access(read_only, 2), access(read_only, 3)]]
static inline std::expected<Fernet::secure_string, std::string>
AES_128_CBC_decrypt(Fernet::secure_string const &key,
                    std::array<byte, NONCE_SIZE> const &nonce,
                    Fernet::secure_string const &ctext) noexcept
{
    Fernet::secure_string raw_text;
    EVP_CIPHER_CTX_unique_ptr cipher_ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int outlen{0}, outlen2{0};

    if (not EVP_DecryptInit_ex(cipher_ctx.get(), EVP_aes_128_cbc(), NULL,
                               reinterpret_cast<byte const *>(key.data()),
                               reinterpret_cast<byte const *>(nonce.data()))) [[unlikely]]
        return std::unexpected("EVP_DecryptInit_ex failed");

    raw_text.resize(ctext.size(), '\0');

    if (not EVP_DecryptUpdate(cipher_ctx.get(),
                              reinterpret_cast<byte *>(raw_text.data()),
                              &outlen,
                              reinterpret_cast<byte const *>(ctext.data()),
                              static_cast<int>(ctext.size()))) [[unlikely]]
        return std::unexpected("EVP_DecryptUpdate failed");

    if (not EVP_DecryptFinal_ex(cipher_ctx.get(),
                                reinterpret_cast<byte *>(raw_text.data()) + outlen,
                                &outlen2)) [[unlikely]]
        return std::unexpected("EVP_DecryptFinal_ex failed");

    raw_text.resize(outlen + outlen2);
    return raw_text;
}

[[nodiscard("Must use AES_128_CBC_encrypt return value")]] [[using gnu: always_inline, pure, hot, access(read_only, 1), access(read_only, 2), access(read_only, 3)]]
static inline std::expected<Fernet::secure_string, std::string>
AES_128_CBC_encrypt(Fernet::secure_string const &key,
                    std::array<byte, NONCE_SIZE> const &nonce,
                    Fernet::secure_string const &ptext) noexcept
{
    Fernet::secure_string cypher_text;
    EVP_CIPHER_CTX_unique_ptr const ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int outlen{0}, outlen2{0};

    // #if not defined(NDEBUG)
    // static uint64_t const cipher_block_size{static_cast<uint64_t>(EVP_CIPHER_block_size(EVP_aes_128_cbc()))};
    // assert(cipher_block_size == CYPHER_BLOCK_SIZE && "cipher_block_size == CYPHER_BLOCK_SIZE must be equal");
    // #endif

    if (not EVP_EncryptInit_ex2(ctx.get(), EVP_aes_128_cbc(),
                                reinterpret_cast<byte const *>(key.data()),
                                reinterpret_cast<byte const *>(nonce.data()), NULL)) [[unlikely]]
        return std::unexpected("EVP_EncryptInit_ex2 failed");

    uint64_t const cipher_text_len{ptext.size() + CYPHER_BLOCK_SIZE - (ptext.size() % CYPHER_BLOCK_SIZE)};
    cypher_text.resize(cipher_text_len, '\0');

    if (not EVP_EncryptUpdate(ctx.get(),
                              reinterpret_cast<byte *>(cypher_text.data()),
                              &outlen,
                              reinterpret_cast<byte const *>(ptext.data()),
                              static_cast<int>(ptext.size()))) [[unlikely]]
        return std::unexpected("EVP_EncryptUpdate failed");

    if (not EVP_EncryptFinal_ex(ctx.get(),
                                reinterpret_cast<byte *>(cypher_text.data()) + outlen,
                                &outlen2)) [[unlikely]]
        return std::unexpected("EVP_EncryptFinal_ex failed");

    return cypher_text;
}

[[nodiscard("Must use timestamp_byteswap return value")]] [[using gnu: always_inline, pure, hot, access(read_only, 1)]]
static inline std::expected<int64_t, std::string>
timestamp_byteswap(int64_t const &timestamp) noexcept
{
    if (std::endian::native == std::endian::little) [[likely]]
        return std::byteswap(timestamp);
    else if (std::endian::native == std::endian::big)
        return timestamp;
    else [[unlikely]]
        return std::unexpected("Endianness Error");
}

Fernet::Fernet(Fernet::secure_string const &key) noexcept : _key(urlsafe_base64Decode(key).value_or(Fernet::gen_rand_key().value_or("0000000000000000000000000000000")))
{
}

[[nodiscard("Must use gen_rand_key return value")]] [[using gnu: pure, hot]]
std::expected<Fernet::secure_string, std::string>
Fernet::gen_rand_key() noexcept
{
    std::array<char, KEY_SIZE> keys{0};
    if (not RAND_bytes(reinterpret_cast<byte *>(keys.data()), KEY_SIZE)) [[unlikely]]
        return std::unexpected("RAND_bytes for iv failed");
    return urlsafe_base64Encode(/* Fernet::secure_string const &input */ {keys.data(), keys.size()});
}

[[nodiscard("Must use encrypt return value")]] [[using gnu: pure, hot, access(read_only, 1)]]
std::expected<Fernet::secure_string, std::string>
Fernet::encrypt(Fernet::secure_string const &plain_text,
                std::time_t const current_time) const noexcept
{
    // assert(FERNET_VERSION == 128_uint8_t);
    FERNET_ASSIGN_OR_RAISE(int64_t timestamp, timestamp_byteswap(/* int64_t const &timestamp */ current_time))

    byte_time const timestamp_view(&timestamp);

    Fernet::secure_string token;
    token.reserve(VERSION_SIZE +
                  TIME_SIZE +
                  NONCE_SIZE +
                  (plain_text.size() + NONCE_SIZE) +
                  HMAC_SIZE);

    token.resize(VERSION_SIZE, '\0');
    token[0] = FERNET_VERSION;

    std::span<const byte, TIME_SIZE> const timestamp_range_view{timestamp_view._timestamps_bytes_c, TIME_SIZE};
    std::copy_n(timestamp_range_view.begin(), TIME_SIZE, std::back_inserter(token));

    FERNET_ASSIGN_OR_RAISE(auto const &nonce, gen_nonce())

    std::copy_n(nonce.begin(), NONCE_SIZE, std::back_inserter(token));

    auto const enc_key_view{this->_key | std::views::drop(16)};

    FERNET_ASSIGN_OR_RAISE(auto const &cypher_text, AES_128_CBC_encrypt(/* key  */ {enc_key_view.data(), enc_key_view.size()},
                                                                        /* nonce  */ nonce,
                                                                        /* ptext  */ plain_text))

    token.resize(token.size() + cypher_text.size(), '\0');
    std::memcpy(token.data() + (VERSION_SIZE + TIME_SIZE + NONCE_SIZE),
                cypher_text.data(), cypher_text.size());

    auto const hmac_key_view{this->_key | std::views::take(16)};

    FERNET_ASSIGN_OR_RAISE(auto const &hmac_sha256_digest,
                           HMAC_SHA256(/* Fernet::secure_string const &data */ token,
                                       /* Fernet::secure_string const &key */ {hmac_key_view.data(), hmac_key_view.size()}))

    std::copy_n(hmac_sha256_digest.begin(), HMAC_SIZE, std::back_inserter(token));

    return urlsafe_base64Encode(/* Fernet::secure_string const &input */ token);
}

[[nodiscard("Must use decrypt return value")]] [[using gnu: pure, hot, access(read_only, 1)]]
std::expected<Fernet::secure_string, std::string>
Fernet::decrypt(Fernet::secure_string const &token,
                int64_t const ttl,
                std::time_t current_time) const noexcept
{
    FERNET_ASSIGN_OR_RAISE(auto const &decoded_token,
                           urlsafe_base64Decode(/* Fernet::secure_string const &input */ token))

    byte const version{static_cast<byte>((decoded_token | std::views::take(1)).front())};

    if (version not_eq FERNET_VERSION) [[unlikely]]
        return std::unexpected("Fernet version not know");

    std::array<byte, NONCE_SIZE> nonce;
    std::memcpy(nonce.data(), decoded_token.data() + (VERSION_SIZE + TIME_SIZE), NONCE_SIZE);
    auto const token_timestamp_view{decoded_token |
                                    std::views::drop(VERSION_SIZE) |
                                    std::views::take(TIME_SIZE)};
    byte_time token_timestamp(token_timestamp_view.data());

    FERNET_ASSIGN_OR_RAISE(int64_t const timestamp,
                           timestamp_byteswap(/* int64_t const &timestamp */ *token_timestamp._timestamps))

    if (ttl and (timestamp + ttl) < current_time)
        return std::unexpected("TTL Expired");

    Fernet::secure_string const token_data{std::string_view(decoded_token.begin(),
                                                            decoded_token.end() - HMAC_SIZE)};

    auto const hmac_key_view{this->_key | std::views::take(16)};

    FERNET_ASSIGN_OR_RAISE(auto const &hmac_sha256_computed,
                           HMAC_SHA256(/* Fernet::secure_string const &data */ token_data,
                                       /* Fernet::secure_string const &key */ {hmac_key_view.data(), hmac_key_view.size()}))

    auto const hash_recieved_view{decoded_token | std::views::drop(decoded_token.size() - HMAC_SIZE)};
    if (not std::ranges::equal(hmac_sha256_computed, hash_recieved_view,
                               [](byte const left, byte const right) -> bool
                               { return left == right; })) [[unlikely]]
        return std::unexpected(std::format("hash_computed are not eq to the hash_recieved "));

    Fernet::secure_string const cypher_text{std::string_view(decoded_token.begin() +
                                                                 VERSION_SIZE +
                                                                 TIME_SIZE +
                                                                 NONCE_SIZE,
                                                             decoded_token.end() - HMAC_SIZE)};

    auto const enc_key_view{this->_key | std::views::drop(16)};
    return AES_128_CBC_decrypt(/* Fernet::secure_string const &key */ {enc_key_view.data(), enc_key_view.size()},
                               /* std::array<byte, NONCE_SIZE> const &nonce */ nonce,
                               /* Fernet::secure_string const &ctext */ cypher_text);
}
