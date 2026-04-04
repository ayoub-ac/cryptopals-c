// Challenge 13 tests - ECB cut-and-paste
extern "C" {
#include "ch13_ecb_cutpaste.h"
}
#include <gtest/gtest.h>
#include <cstring>
#include <cstdio>

// check that we can parse key=value strings correctly
TEST(Ch13, KVParse)
{
    kv_map map;
    int n = kv_parse("foo=bar&baz=qux&zap=zazzle", &map);
    ASSERT_EQ(n, 3);
    EXPECT_STREQ(map.pairs[0].key, "foo");
    EXPECT_STREQ(map.pairs[0].value, "bar");
    EXPECT_STREQ(map.pairs[1].key, "baz");
    EXPECT_STREQ(map.pairs[1].value, "qux");
    EXPECT_STREQ(map.pairs[2].key, "zap");
    EXPECT_STREQ(map.pairs[2].value, "zazzle");
}

// profile_for should build the right string
TEST(Ch13, ProfileFor)
{
    char profile[128];
    profile_for("foo@bar.com", profile, sizeof(profile));
    EXPECT_STREQ(profile, "email=foo@bar.com&uid=10&role=user");
}

// make sure you can't just inject role=admin in the email
TEST(Ch13, ProfileForSanitize)
{
    char profile[128];
    profile_for("foo@bar.com&role=admin", profile, sizeof(profile));
    // & and = should be gone, role stays as user
    EXPECT_TRUE(strstr(profile, "role=user") != NULL);
}

// the actual attack: forge a ciphertext that decrypts to role=admin
TEST(Ch13, CutAndPaste)
{
    uint8_t forged[256];
    size_t forged_len;

    int ret = ecb_cut_and_paste(forged, &forged_len);
    ASSERT_EQ(ret, 0);

    kv_map map;
    int n = decrypt_profile(forged, forged_len, &map);
    ASSERT_GT(n, 0);

    // check if we got admin
    const char *role = NULL;
    for (int i = 0; i < map.count; i++) {
        if (strcmp(map.pairs[i].key, "role") == 0) {
            role = map.pairs[i].value;
            break;
        }
    }

    printf("  forged role: %s\n", role ? role : "not found");
    ASSERT_NE(role, (const char *)NULL);
    EXPECT_STREQ(role, "admin");
}
