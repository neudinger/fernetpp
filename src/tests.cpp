// https://www.redhat.com/en/blog/introduction-fernet-tokens-red-hat-openstack-platform
// https://docs.openstack.org/keystone/pike/admin/identity-fernet-token-faq.html
#include <iostream>
#include <string>
#include <tuple>

#include <crypto/hash/FNV1a.hpp>
#include <fernet/fernet.hh>

// #include <catch2/catch_all.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>

constexpr uint32_t hash(uint32_t in)
{
    constexpr uint32_t r[]{
        0xdf15236c, 0x16d16793, 0x3a697614, 0xe0fe08e4,
        0xa3a53275, 0xccc10ff9, 0xb92fae55, 0xecf491de,
        0x36e86773, 0x0ed24a6a, 0xd7153d80, 0x84adf386,
        0x17110e76, 0x6d411a6a, 0xcbd41fed, 0x4b1d6b30};
    uint32_t out{in ^ r[in & 0xF]};
    out ^= std::rotl(in, 020) ^ r[(in >> 010) & 0xF];
    out ^= std::rotl(in, 010) ^ r[(in >> 020) & 0xF];
    out ^= std::rotr(in, 010) ^ r[(in >> 030) & 0xF];
    return out;
}

// template <size_t N>
// constexpr uint32_t hash(char const (&str)[N])
// {
//     uint32_t h{};
//     for (uint32_t i{}; i < N; ++i)
//         h ^= uint32_t(str[i]) << (i % 4 * 8);
//     return hash(h);
// }

// template <size_t N>
// constexpr uint32_t constexpr_rand_impl(char const (&file)[N], uint32_t line, uint32_t column = 0x8dc97987)
// {
//     return hash(hash(__TIME__) ^ hash(file) ^ hash(line) ^ hash(column));
// }

template <StringLike Str>
constexpr uint32_t constexpr_rand_impl(Str &file, uint32_t line, uint32_t column = 0x8dc97987)
{
    return hash(FNV1a(__TIME__) ^ FNV1a(file) ^ hash(line) ^ hash(column));
}

#define RANDOM constexpr_rand_impl(__FILE__, __LINE__)

constexpr static auto to_int(const char *str, int offset)
{
    return static_cast<uint32_t>(str[offset] - '0') * 10 +
           static_cast<uint32_t>(str[offset + 1] - '0');
}

constexpr static uint64_t seed()
{
    auto t = __TIME__;
    uint64_t l = to_int(t, 0) * 60 * 60;
    l += to_int(t, 3) * 60;
    l += to_int(t, 6);
    return l;
}

consteval static uint64_t xorshift64(uint64_t seed)
{
    uint64_t x = seed;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

constinit const static uint64_t g_seed = seed();

consteval static uint64_t rand(uint64_t level)
{
    if (level == 0)
        return xorshift64(g_seed);
    return xorshift64(rand(level - 1));
}

static int Factorial(int number)
{
    return number <= 1 ? number : Factorial(number - 1) * number; // fail
    // return number <= 1 ? 1      : Factorial( number - 1 ) * number;  // pass
}

TEST_CASE("rand number", "[tag]")
{
    UNSCOPED_INFO("Info from helper");
    INFO("Test case start");
    auto _rand = rand(10);
    CAPTURE(_rand);
    REQUIRE(_rand not_eq 0);
    INFO("The number is " << _rand);
    CHECK(false);
}

SCENARIO("vector can be sized and resized")
{
    GIVEN("An empty vector")
    {
        auto v = std::vector<std::string>{};

        // Validate assumption of the GIVEN clause
        THEN("The size and capacity start at 0")
        {
            REQUIRE(v.size() == 0);
            REQUIRE(v.capacity() == 0);
        }

        // Validate one use case for the GIVEN object
        WHEN("push_back() is called")
        {
            v.push_back("hullo");

            THEN("The size changes")
            {
                REQUIRE(v.size() == 1);
                REQUIRE(v.capacity() >= 1);
            }
        }
    }
}

TEMPLATE_TEST_CASE("vectors can be sized and resized", "[vector][template]", int, std::string, (std::tuple<int, float>))
{

    std::vector<TestType> v(5);

    REQUIRE(v.size() == 5);
    REQUIRE(v.capacity() >= 5);

    SECTION("resizing bigger changes size and capacity")
    {
        v.resize(10);

        REQUIRE(v.size() == 10);
        REQUIRE(v.capacity() >= 10);
    }
    SECTION("resizing smaller changes size but not capacity")
    {
        v.resize(0);

        REQUIRE(v.size() == 0);
        REQUIRE(v.capacity() >= 5);

        SECTION("We can use the 'swap trick' to reset the capacity")
        {
            std::vector<TestType> empty;
            empty.swap(v);

            REQUIRE(v.capacity() == 0);
        }
    }
    SECTION("reserving smaller does not change size or capacity")
    {
        v.reserve(0);

        REQUIRE(v.size() == 5);
        REQUIRE(v.capacity() >= 5);
    }
}

TEST_CASE("Factorials of 1 and higher are computed (pass)", "[single-file]")
{
    REQUIRE(Factorial(1) == 1);
    REQUIRE(Factorial(2) == 2);
    REQUIRE(Factorial(3) == 6);
    REQUIRE(Factorial(10) == 3628800);
}

TEST_CASE("states of inputs unchanged", "[single-file]")
{

    REQUIRE(printf("Hello, World!\n") == 14);
}

TEMPLATE_TEST_CASE("vectors can be sized and resized", "[vector][template]", int, std::string, (std::tuple<int, float>))
{
}

#include <chrono>

int main(/* int argc, char const *argv[] */)
{

    // std::cout << RANDOM << std::endl;
    // {
    //     std::cout << rand(10) << std::endl;
    //     auto const expected_key = Fernet::gen_rand_key();
    //     if (expected_key.has_value())
    //         std::cout << expected_key.value() << std::endl;
    //     else
    //         std::cout << expected_key.error() << std::endl;
    // }
    // {
    //     auto const expected_key = Fernet::gen_rand_key();
    //     if (expected_key.has_value())
    //         std::cout << expected_key.value() << std::endl;
    //     else
    //         std::cerr << expected_key.error() << std::endl;
    //     auto const rand_key{expected_key.value()};
    //     auto fernet_tokenizer = Fernet(rand_key);
    //     std::string const secure_string_session{R"({"answer":42,"obiwan":"high ground"})"};
    //     auto const fernet_token = fernet_tokenizer.encrypt({secure_string_session.data()});
    //     if (fernet_token.has_value())
    //         std::cout << fernet_token.value() << std::endl;
    //     else
    //         std::cerr << fernet_token.error() << std::endl;
    //     auto const message_received{fernet_tokenizer.decrypt(fernet_token.value())};
    //     if (fernet_token.has_value())
    //         std::cout << fernet_token.value() << std::endl;
    //     else
    //         std::cerr << fernet_token.error() << std::endl;
    //     std::cout << std::boolalpha << std::ranges::equal(message_received.value(), secure_string_session) << std::endl;
    // }
    // {
    //     auto fernet{Fernet("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA")};
    //     Fernet::secure_string ptext = "hello";
    //     std::string fernetstring(fernet.encrypt(ptext).value());
    //     Fernet::secure_string data{fernet.decrypt({fernetstring.data()}).value()};
    //     std::cout << std::boolalpha << std::ranges::equal(ptext, data) << std::endl;
    // }
    // {
    //     auto fernet = Fernet("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA");
    //     Fernet::secure_string ptext = "hello";
    //     Fernet::secure_string fernet_token = fernet.encrypt(ptext, 0).value();
    //     Fernet::secure_string data = fernet.decrypt(fernet_token).value();
    //     std::cout << std::boolalpha << std::ranges::equal(ptext, data) << std::endl;
    // }
    // {
    //     auto fernet = Fernet("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=");
    //     Fernet::secure_string ptext = "Now is the time for all good men to come to the aide of their country";
    //     Fernet::secure_string fernet_token = fernet.encrypt(ptext, 0UL).value();
    //     Fernet::secure_string data = fernet.decrypt(fernet_token).value();
    //     std::cout << std::boolalpha << std::ranges::equal(ptext, data) << std::endl;
    // }
    // {
    //     auto fernet = Fernet("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
    //     Fernet::secure_string ptext = "hello";
    //     Fernet::secure_string fernet_token = fernet.encrypt(ptext, 499162800).value();
    //     std::cout << fernet_token << std::endl;
    //     Fernet::secure_string data = fernet.decrypt(fernet_token).value();
    //     std::cout << std::boolalpha << std::ranges::equal(ptext, data) << std::endl;
    // }
    {
        // https://en.cppreference.com/w/cpp/chrono/c/strftime
        std::tm tp{};
        std::istringstream ss("1985-10-26T01:20:01-07:00");
        ss >> std::get_time(&tp, "%Y-%m-%dT%H:%M:%S");
        if (ss.fail())
            std::cout << "Parse failed\n";
        else
        {
            std::cout << std::put_time(&tp, "%c") << '\n';
            std::time_t now =  mktime(&tp);
            std::cout << now /* 499162801 */ << '\n';
            auto gen_fernet = Fernet("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
            std::cout << "data : " << gen_fernet.decrypt("gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==", 60, now).value_or("error") << std::endl;
        }
    }
    // {
    //     auto fernet_tokenizer = Fernet("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
    //     Fernet::secure_string ptext = "Now is the time for all good men to come to the aide of their country";
    //     Fernet::secure_string fernet_token = fernet_tokenizer.encrypt(ptext).value();
    //     Fernet::secure_string data = fernet_tokenizer.decrypt(fernet_token).value();
    //     Fernet::secure_string pptext;
    //     pptext = data;
    //     std::cout << "pptext " << pptext << std::endl;
    //     std::cout << std::boolalpha << std::ranges::equal(ptext, data) << std::endl;
    // }

    return 0;
}
