/* layout — the fixture for type, control-flow, search and patch tools.
 *
 * Each function exists to give one tool family a known answer:
 *
 *   score_record    reads a struct through a pointer at fixed offsets, so a
 *                   struct defined and applied to its parameter turns
 *                   *(int *)(p + 8) back into p->weight
 *   classify        a switch over an enum: a known set of basic blocks
 *   stage_a/b/c     a call chain main -> stage_a -> stage_b -> stage_c ->
 *                   score_record, for call-path search
 *   is_licensed     compares against the magic constant 0xC0FFEE42; the one
 *                   conditional branch decides the result, so inverting it is
 *                   an observable patch
 *
 * Built like keycheck: non-PIE, -O0, no debug info, not stripped.
 */
#include <stdio.h>
#include <stdlib.h>

enum color { RED = 1, GREEN = 2, BLUE = 4, ALPHA = 8 };

struct record {
    int id;             /* offset 0  */
    short flags;        /* offset 4  */
    short kind;         /* offset 6  */
    int weight;         /* offset 8  */
    char tag[12];       /* offset 12 */
    long long total;    /* offset 24 */
};

int score_record(struct record *r)
{
    int score = r->id * 3 + r->weight;

    if (r->flags & 1)
        score += r->kind;
    r->total += score;
    return score + r->tag[0];
}

int classify(enum color c)
{
    switch (c) {
    case RED:
        return 10;
    case GREEN:
        return 20;
    case BLUE:
        return 40;
    case ALPHA:
        return 80;
    default:
        return -1;
    }
}

int stage_c(struct record *r) { return score_record(r) + 1; }
int stage_b(struct record *r) { return stage_c(r) * 2; }
int stage_a(struct record *r) { return stage_b(r) - 3; }

int is_licensed(unsigned int key)
{
    if (key == 0xC0FFEE42u)
        return 1;
    return 0;
}

int main(int argc, char **argv)
{
    struct record r = { 7, 1, 2, 100, "fixture", 0 };
    unsigned int key = argc > 1 ? (unsigned int)strtoul(argv[1], NULL, 16) : 0;

    printf("score %d, class %d\n", stage_a(&r), classify((enum color)argc));
    puts(is_licensed(key) ? "licensed" : "unlicensed");
    return 0;
}
