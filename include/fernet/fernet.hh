#pragma once

#if not defined(FERNET_HH)
#define FERNET_HH
#include <ctime> // std::time_t

#include <optional>
#include <expected>
#include <limits> // std::numeric_limits
#include <memory> // std::

#include <openssl/crypto.h> // OPENSSL_secure_clear_free
#include <openssl/evp.h>    // EVP_CIPHER_CTX_FLAG_WRAP_ALLOW

#include <string_view>
#include <algorithm>
#include <array>
#include <iostream>
#include <iterator>
#include <string>

using namespace std::literals;

#define FERNET_EXPAND(x) x
#define FERNET_STRINGIFY(x) #x
#define FERNET_CONCAT(x, y) x##y
#define FERNET_ASSIGN_OR_RAISE_NAME(x, y) FERNET_CONCAT(x, y)
#define FERNET_ASSIGN_OR_RAISE_IMPL(result_name, definition, expression) \
    auto const &result_name = (expression);                              \
    if (not(result_name.has_value())) [[likely]]                         \
        return std::unexpected(result_name.error());                     \
    definition = result_name.value();

/// \brief Execute an expression that returns a Result, extracting its value
/// into the variable defined by `lhs` (or returning a Status on error).
///
/// Example: Assigning to a new value:
///   FERNET_ASSIGN_OR_RAISE(auto value, MaybeGetValue(arg));
///
/// Example: Assigning to an existing value:
///   ValueType value;
///   FERNET_ASSIGN_OR_RAISE(value, MaybeGetValue(arg));
///
/// WARNING: FERNET_ASSIGN_OR_RAISE expands into multiple statements;
/// it cannot be used in a single statement (e.g. as the body of an if
/// statement without {})!
///
/// WARNING: FERNET_ASSIGN_OR_RAISE `std::move`s its right operand. If you have
/// an lvalue Result which you *don't* want to move out of cast appropriately.
///
/// WARNING: FERNET_ASSIGN_OR_RAISE is not a single expression; it will not
/// maintain lifetimes of all temporaries in `rexpr` (e.g.
/// `FERNET_ASSIGN_OR_RAISE(auto x, MakeTemp().GetResultRef());`
/// will most likely segfault)!
#define FERNET_ASSIGN_OR_RAISE(definition, expression) \
    FERNET_ASSIGN_OR_RAISE_IMPL(FERNET_ASSIGN_OR_RAISE_NAME(_error_or_value_, __COUNTER__), definition, expression)

// Fernet is a symmetric encryption method which makes sure that the message encrypted cannot be manipulated/read without the key.
// It uses URL safe encoding for the keys.
// Fernet also uses 128-bit AES in CBC mode and PKCS7 padding, with HMAC using SHA256 for authentication.
// The IV is created from openssl RAND_bytes.
// All of this is the kind of thing that good software needs.
// AES is top drawer encryption, and SHA-256 avoids many of the problems caused by MD5 and SHA-1 (as the length of the hash values is too small).
// With CBC (Cipher Block Chaining) we get a salted output, and which is based on a random value (the IV value).
// And with HMAC we can provide authenticated access from both sides.
// In this case we will use scrypt to generate the encryption key from a salt value and a password.
// To generate the same encryption key we need the salt value and the password

// https://docs.oracle.com/cd/E19205-01/819-3703/15_3.htm
// https://en.cppreference.com/w/cpp/named_req/Allocator

typedef struct [[nodiscard]] Fernet final
{
    template <typename T>
    struct zallocator
    {
    public:
        typedef T value_type;
        typedef value_type *pointer;
        typedef const value_type *const_pointer;
        typedef value_type &reference;
        typedef const value_type &const_reference;
        typedef std::size_t size_type;
        typedef std::ptrdiff_t difference_type;

        zallocator() noexcept
        {
        }

        template <class U>
        zallocator(const zallocator<U> &) noexcept
        {
        }

        pointer address(reference v) const { return &v; }
        const_pointer address(const_reference v) const { return &v; }

        pointer allocate(size_type n) const
        {
            if (n > std::numeric_limits<size_type>::max() / sizeof(T))
                throw std::bad_alloc();
            return static_cast<pointer>(OPENSSL_secure_zalloc(n * sizeof(value_type)));
        }

        pointer operator=(pointer p)
        {
            if (std::size(p) > std::numeric_limits<size_type>::max() / sizeof(T))
                throw std::bad_alloc();
            return static_cast<pointer>(OPENSSL_secure_zalloc(std::size(p) * sizeof(value_type)));
        }

        void deallocate(pointer p, size_type n) const
        {
            OPENSSL_secure_clear_free(p, n * sizeof(T));
        }

        size_type max_size(void) const
        {
            return std::numeric_limits<size_type>::max() / sizeof(T);
        }

        template <typename U>
        struct rebind
        {
            typedef zallocator<U> other;
        };
        template <typename U, typename... Args>
        void construct(U *ptr, Args &&...args) const
        {
            ::new (static_cast<void *>(ptr)) U(std::forward<Args>(args)...);
        }

        template <typename U>
        void destroy(U *ptr) const
        {
            ptr->~U();
        }
    };

    using secure_string = std::basic_string<char, std::char_traits<char>, zallocator<char>>;

private:
    std::string const _key;

public:
    ~Fernet(void) = default;
    Fernet(Fernet const &) = delete;
    Fernet(secure_string const &) noexcept;
    Fernet(void) = delete;

    // https://en.wikipedia.org/wiki/Const_(computer_programming)
    // http://duramecho.com/ComputerInformation/WhyHowCppConst.html
    // https://google.github.io/styleguide/cppguide.html#Use_of_const

    [[nodiscard("Must use encrypt return value")]] [[using gnu: pure, hot, access(read_only, 1)]]
    std::expected<secure_string, std::string> encrypt(secure_string const &plain_text,
                                                      std::time_t current_time = std::time(nullptr)) const noexcept;

    [[nodiscard("Must use decrypt return value")]] [[using gnu: pure, hot, access(read_only, 1)]]
    std::expected<secure_string, std::string> decrypt(secure_string const &token,
                                                      int64_t ttl = 0U,
                                                      std::time_t current_time = std::time(nullptr)) const noexcept;

    [[nodiscard("Must use gen_rand_key return value")]] [[using gnu: pure, hot]]
    static std::expected<secure_string, std::string> gen_rand_key() noexcept;

} Fernet;

template <class T, class U>
[[using gnu: pure, hot, access(read_only, 1), access(read_only, 2)]]
constexpr bool operator==(const Fernet::zallocator<T> &, const Fernet::zallocator<U> &) noexcept { return true; }

template <class T, class U>
[[using gnu: pure, hot, access(read_only, 1), access(read_only, 2)]]
constexpr bool operator!=(const Fernet::zallocator<T> &lhs, const Fernet::zallocator<U> &rhs) noexcept { return not ::operator==(lhs, rhs); }

#endif // FERNET_HH
