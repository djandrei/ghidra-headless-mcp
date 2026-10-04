/* chainapp.exe — imports do_work from chainfwd.dll: the consumer layer. */
__declspec(dllimport) int do_work(int value);

int main(void)
{
    return do_work(2) == 7 ? 0 : 1;
}
