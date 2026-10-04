/* crackme — the second ELF: a password copied to the heap and compared.
 * Imports strcmp, malloc and memcpy, which the multi-program tests look for. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char SECRET[] = "fixture-password";

int main(int argc, char **argv)
{
    if (argc != 2) {
        puts("usage: crackme <password>");
        return 2;
    }
    size_t length = strlen(argv[1]);
    char *copy = malloc(length + 1);
    if (copy == NULL)
        return 3;
    memcpy(copy, argv[1], length + 1);
    int ok = strcmp(copy, SECRET) == 0;
    free(copy);
    puts(ok ? "correct" : "wrong");
    return ok ? 0 : 1;
}
