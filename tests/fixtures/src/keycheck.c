/* keycheck — the single-binary fixture: a key check called from main.
 *
 * Built non-PIE and without debug info, as an ordinary gcc/glibc executable,
 * because the tests rely on what that produces: .init mapped at 0x401000,
 * crt1's _start and crti's _init, and a main whose calling convention
 * auto-analysis leaves unknown. Not stripped: the tests find functions by name.
 */
#include <stdio.h>
#include <string.h>

static const char BANNER[] = "== keycheck keygen-me ==";

/* Weights each character by its position; accepts a 12-character key whose
 * weighted sum is 42 mod 97. The loop gives the decompiler locals to name. */
int check_key(const char *key)
{
    size_t length = strlen(key);
    int sum = 0;

    if (length != 12)
        return 0;
    for (size_t i = 0; i < length; i++)
        sum += (unsigned char)key[i] * (int)(i + 1);
    return sum % 97 == 42;
}

int main(int argc, char **argv)
{
    puts(BANNER);
    if (argc != 2) {
        printf("usage: %s <key>\n", argv[0]);
        return 2;
    }
    if (check_key(argv[1])) {
        puts("key accepted");
        return 0;
    }
    puts("key rejected");
    return 1;
}
