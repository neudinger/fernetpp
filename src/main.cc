
// Fernet

/*

version | Timestamp | IV |  Cypher (Payload)    | HMAC

8 bits  |   64      | 128 | ... | 256

1 bytes |   8       | 16  | ... |   32

 */

#include <functional>
#include <ctime>
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
#include <cassert>
#include <regex>
#include <format>

// https://www.redhat.com/en/blog/introduction-fernet-tokens-red-hat-openstack-platform
// https://docs.openstack.org/keystone/pike/admin/identity-fernet-token-faq.html

#include <openssl/crypto.h> // OPENSSL_secure_clear_free
#include <openssl/evp.h>    // EVP_CIPHER_CTX_FLAG_WRAP_ALLOW

#include <iomanip>
#include <iostream>
#include <sstream>
#include <ranges>

#include "fernet.hh"

int main()
{
    // std::string sss = "1234567890123456789012345678901";
    // secure_string plain_text_a = "Now is the time for all good men to come to the aide of their country";

    // secure_string key = "00000000000000000000000000000000";
    // auto base64_val = base64Encode("<<???>>");
    // std::cout << base64_val << std::endl;
    // std::cout << "1 " << base64Decode(base64_val) << std::endl;
    // secure_string todecode = "PDw/Pz8+Pg==";
    // std::cout << "2 " << base64Decode(todecode) << std::endl;

    // std::cout << "1 " << urlsafe_base64Encode("<<???>>") << std::endl;
    // std::cout << "2 " << std::endl
    //           << urlsafe_base64Decode("PDw_Pz8-Pg+==") << std::endl;
    // std::cout << "2 " << urlsafe_base64Decode(urlsafe_base64Encode("<<???>>")) << std::endl;

    // {
    //     auto ecryptedtext = Fernet::AES_128_CBC_encrypt("qwertyuiop", nonce, "hello");
    //     std::cout << Fernet::AES_128_CBC_decrypt("qwertyuiop", nonce, ecryptedtext) << std::endl;
    //     // std::cout << Fernet::ba
    // }
    // {
    //     auto fernet = Fernet("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA");
    //     Fernet::secure_string ptext = "hello";
    //     Fernet::secure_string fernet_token = fernet.encrypt(ptext, 0);
    //     std::cout << "fernet_token :" << fernet_token << std::endl;
    //     Fernet::secure_string data = fernet.decrypt(fernet_token);
    //     std::cout << "data :" << data << std::endl;
    // }
    // {
    //     auto fernet = Fernet("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=");
    //     Fernet::secure_string ptext = "Now is the time for all good men to come to the aide of their country";
    //     Fernet::secure_string fernet_token = fernet.encrypt(ptext, 0UL);
    //     std::cout << "fernet_token :" << fernet_token << std::endl;
    //     Fernet::secure_string data = fernet.decrypt(fernet_token);
    //     std::cout << "data :" << data << std::endl;
    // }

    {
        auto fernet = Fernet("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
        Fernet::secure_string ptext = "hello";
        Fernet::secure_string fernet_token = fernet.encrypt(ptext, 499162800);
        std::cout << "fernet_token : " << fernet_token << std::endl;
        Fernet::secure_string data = fernet.decrypt(fernet_token);
        std::cout << "data : " << data << std::endl;
    }
    {
        auto gen_fernet = Fernet("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
        std::cout << gen_fernet.decrypt("gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==") << std::endl;
    }
    exit(-1);
    // {
    //     auto fernet = Fernet("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
    //     Fernet::secure_string ptext = "Now is the time for all good men to come to the aide of their country";
    //     Fernet::secure_string fernet_token = fernet.encrypt(ptext);
    //     std::cout << "fernet_token :" << fernet_token << std::endl;
    //     Fernet::secure_string data = fernet.decrypt(fernet_token);
    //     std::cout << "data :" << data << std::endl;
    // }

    // secure_string data2 = fernet.decrypt_at_time(token
    // /* ttl */
    // /* current_time */);

    // exit(0);

    // const std::uint16_t i = 0b11000001;
    // std::cout << "i          = " << i
    //   << " bytes " << std::bitset<16>(i)
    //   << "\t" << std::bitset<16>(std::byteswap(i)) << std::endl;

    // version | Timestamp | IV |  Cypher (Payload)    | HMAC
    // 1 bytes |   8       | 16  | ... |   32
    // 8 bits  |   64      | 128 | ... | 256

    // foo f;
    // f.helloworld();

    // uint8_t message[] = "A secret message. Not for prying eyes.";
    // uint8_t key[] = "sJriZXXtrJeNRPFsPmiD7jIfIv8q_0AeGH2dWyXCItQ=";
    // uint8_t iv[] = "qwertyuiopasdfgh";
    // uint8_t *ariaoutputbuf_encrypted;
    // uint64_t const ariaoutputbuf_encrypt_len = aria_cbc_encrypt(message, sizeof(message),
    //                                                             key, sizeof(key) - 1,
    //                                                             iv, 16,
    //                                                              &ariaoutputbuf_encrypted);
    // b"\x80"
    // + current_time.to_bytes(length=8, byteorder="big")

    // std::cout << "SHA256 " << EVP_MAC_CTX_get_mac_size(EVP_get_digestbyname("AES-128-CBC")) << std::endl;
    // EVP_MD_block_size();
    return 0;
}
