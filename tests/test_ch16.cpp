// Challenge 16 tests - CBC bitflipping attack
extern "C" {
#include "ch16_cbc_bitflip.h"
}
#include <gtest/gtest.h>
#include <cstdio>

// can't just type ;admin=true; because it gets sanitized
TEST(Ch16, NoDirectInjection)
{
    uint8_t cipher[512];
    int len = bitflip_encrypt(";admin=true;", cipher, sizeof(cipher));
    ASSERT_GT(len, 0);
    EXPECT_FALSE(bitflip_check_admin(cipher, len));
}

// the bitflip attack should give us admin
TEST(Ch16, BitflipAttack)
{
    // encrypt with placeholder chars where we want ; and =
    uint8_t cipher[512];
    int len = bitflip_encrypt("XadminXtrueX", cipher, sizeof(cipher));
    ASSERT_GT(len, 0);

    // flip the bits
    int ret = cbc_bitflip_attack(cipher, len);
    ASSERT_EQ(ret, 0);

    // should be admin now
    int is_admin = bitflip_check_admin(cipher, len);
    printf("  admin: %s\n", is_admin ? "yes!" : "no");
    EXPECT_TRUE(is_admin);
}
