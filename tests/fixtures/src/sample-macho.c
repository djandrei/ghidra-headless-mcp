/* sample-macho — an arm64 Mach-O that calls the Objective-C runtime, so the
 * mixed-format project holds an _objc_msgSend import that only Mach-O has.
 * Declared by hand: there is no Apple SDK in the build, and the runtime is
 * left to dynamic lookup at link time. It is never run. */
#include <stdio.h>

typedef void *id;
typedef void *SEL;

extern id objc_getClass(const char *name);
extern SEL sel_registerName(const char *name);
extern id objc_msgSend(id self, SEL op, ...);

int main(void)
{
    id cls = objc_getClass("NSObject");
    SEL description = sel_registerName("description");
    id result = ((id (*)(id, SEL))objc_msgSend)(cls, description);
    printf("%p\n", result);
    return result != NULL ? 0 : 1;
}
