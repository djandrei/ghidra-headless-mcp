/* chainimpl.dll — where do_work is implemented. Exports it, imports nothing
 * of that name: the terminal layer resolve_symbol should report. */
__declspec(dllexport) int do_work(int value)
{
    return value * 3 + 1;
}
