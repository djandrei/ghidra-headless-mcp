/* sample-pe32 — a 32-bit Windows executable for the mixed-format project.
 * Imports GetModuleHandleA, GetProcAddress and CreateFileA from kernel32;
 * it is never run. */
#include <windows.h>

int main(void)
{
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC tick = GetProcAddress(kernel32, "GetTickCount");
    HANDLE file = CreateFileA("fixture.txt", GENERIC_READ, 0, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    return tick != NULL ? 0 : 1;
}
