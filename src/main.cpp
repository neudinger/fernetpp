#include <fernet/fernet.hh>

// https://www.redhat.com/en/blog/introduction-fernet-tokens-red-hat-openstack-platform
// https://docs.openstack.org/keystone/pike/admin/identity-fernet-token-faq.html

#include <iostream>

int main()
{
    {
        auto const rand_key{Fernet::gen_rand_key()};
        auto fernet_tokenizer = Fernet(rand_key);
        std::string const secure_string_session{R"({"answer":42,"obiwan":"hight ground"})"};
        Fernet::secure_string fernet_token = fernet_tokenizer.encrypt({secure_string_session.data()});
        auto const message_recieved{fernet_tokenizer.decrypt(fernet_token)};
        std::cout << std::boolalpha << std::ranges::equal(message_recieved, secure_string_session) << std::endl;
    }
    {
        auto fernet{Fernet("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA")};
        Fernet::secure_string ptext = "hello";
        std::string fernetstring(fernet.encrypt(ptext));
        Fernet::secure_string data{fernet.decrypt({fernetstring.data()})};
        std::cout << std::boolalpha << std::ranges::equal(ptext, data) << std::endl;
    }
    {
        auto fernet = Fernet("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA");
        Fernet::secure_string ptext = "hello";
        Fernet::secure_string fernet_token = fernet.encrypt(ptext, 0);
        Fernet::secure_string data = fernet.decrypt(fernet_token);
        std::cout << std::boolalpha << std::ranges::equal(ptext, data) << std::endl;
    }
    {
        auto fernet = Fernet("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=");
        Fernet::secure_string ptext = "Now is the time for all good men to come to the aide of their country";
        Fernet::secure_string fernet_token = fernet.encrypt(ptext, 0UL);
        Fernet::secure_string data = fernet.decrypt(fernet_token);
        std::cout << std::boolalpha << std::ranges::equal(ptext, data) << std::endl;
    }
    {
        auto fernet = Fernet("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
        Fernet::secure_string ptext = "hello";
        Fernet::secure_string fernet_token = fernet.encrypt(ptext, 499162800);
        Fernet::secure_string data = fernet.decrypt(fernet_token);
        std::cout << std::boolalpha << std::ranges::equal(ptext, data) << std::endl;
    }
    {
        auto gen_fernet = Fernet("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
        std::cout << "data : " << gen_fernet.decrypt("gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==") << std::endl;
    }
    {
        auto fernet = Fernet("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
        Fernet::secure_string ptext = "Now is the time for all good men to come to the aide of their country";
        Fernet::secure_string fernet_token = fernet.encrypt(ptext);
        Fernet::secure_string data = fernet.decrypt(fernet_token);
        std::cout << std::boolalpha << std::ranges::equal(ptext, data) << std::endl;
    }
    return 0;
}
