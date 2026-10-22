/* Tiny test program for feature-extractor parity tests (built with mingw-w64). */
#include <windows.h>
#include <stdio.h>
__declspec(dllexport) int fenrir_parity_export(int x) { return x * 2; }
int main(void) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    printf("Fenrir parity sample at %s; see https://example.com and HKEY_LOCAL_MACHINE c:\\temp\n", path);
    MessageBeep(MB_OK);
    return fenrir_parity_export(21) == 42 ? 0 : 1;
}
