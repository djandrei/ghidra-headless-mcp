/* chainfwd.dll — re-exports do_work, implemented by a call into chainimpl.dll.
 * It both exports and imports do_work, which is how resolve_symbol recognises
 * a forwarder (the shape of kernel32's stubs over kernelbase). */
__declspec(dllimport) int do_work(int value);

int forward_do_work(int value)
{
    return do_work(value);
}
