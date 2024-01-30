#include <fernet/fernet.hh>

// https://www.redhat.com/en/blog/introduction-fernet-tokens-red-hat-openstack-platform
// https://docs.openstack.org/keystone/pike/admin/identity-fernet-token-faq.html


#include <iostream>

int main()
{
    {
        auto fernet = Fernet("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA");
        Fernet::secure_string ptext = "hello";
        Fernet::secure_string fernet_token = fernet.encrypt(ptext, 0);
        std::cout << "fernet_token :" << fernet_token << std::endl;
        Fernet::secure_string data = fernet.decrypt(fernet_token);
        std::cout << "data :" << data << std::endl;
    }
    {
        auto fernet = Fernet("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=");
        Fernet::secure_string ptext = "Now is the time for all good men to come to the aide of their country";
        Fernet::secure_string fernet_token = fernet.encrypt(ptext, 0UL);
        std::cout << "fernet_token :" << fernet_token << std::endl;
        Fernet::secure_string data = fernet.decrypt(fernet_token);
        std::cout << "data :" << data << std::endl;
    }
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
        std::cout << "data : " << gen_fernet.decrypt("gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==") << std::endl;
    }
    {
        auto fernet = Fernet("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
        Fernet::secure_string ptext = "Now is the time for all good men to come to the aide of their country";
        Fernet::secure_string fernet_token = fernet.encrypt(ptext);
        std::cout << "fernet_token :" << fernet_token << std::endl;
        Fernet::secure_string data = fernet.decrypt(fernet_token);
        std::cout << "data :" << data << std::endl;
    }
    return 0;
}