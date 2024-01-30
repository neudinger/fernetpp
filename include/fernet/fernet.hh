#pragma once

#if not defined(FERNET_HH)
#define FERNET_HH

#include <openssl/crypto.h> // OPENSSL_secure_clear_free
#include <openssl/evp.h>    // EVP_CIPHER_CTX_FLAG_WRAP_ALLOW
#include <limits>           // std::numeric_limits
#include <memory>           // std::bad_alloc

#include <ctime> // std::time_t

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

    pointer address(reference v) const { return &v; }
    const_pointer address(const_reference v) const { return &v; }

    pointer allocate(size_type n /* , const void *hint = 0 */)
    {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T))
            throw std::bad_alloc();
        return static_cast<pointer>(OPENSSL_secure_zalloc(n * sizeof(value_type)));
        // return static_cast<pointer>(::operator new(n * sizeof(value_type)));
    }

    void deallocate(pointer p, size_type n)
    {
        OPENSSL_secure_clear_free(p, n * sizeof(T));
        // OPENSSL_cleanse(p, n * sizeof(T));
        // ::operator delete(p);
    }

    size_type max_size() const
    {
        return std::numeric_limits<size_type>::max() / sizeof(T);
    }

    template <typename U>
    struct rebind
    {
        typedef zallocator<U> other;
    };
    template <typename U, typename... Args>
    void construct(U *ptr, Args &&...args)
    {
        ::new (static_cast<void *>(ptr)) U(std::forward<Args>(args)...);
    }

    template <typename U>
    void destroy(U *ptr)
    {
        ptr->~U();
    }
};

typedef struct Fernet
{
    using secure_string = std::basic_string<char, std::char_traits<char>, zallocator<char>>;

private:
    secure_string _key;

public:
    ~Fernet() = default;
    Fernet(Fernet const &) = delete;
    Fernet(secure_string const &);

    secure_string encrypt(secure_string const &plain_text,
                          std::time_t current_time = std::time(nullptr));

    secure_string decrypt(secure_string const &token,
                          int64_t ttl = 0U,
                          std::time_t current_time = std::time(nullptr));

} Fernet;

#endif // FERNET_HH
