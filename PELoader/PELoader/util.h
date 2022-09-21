#include <Windows.h>
#include <iostream>

DWORD translate_protect(DWORD sec_charact);
bool is_compatibile(BYTE *implant_dll);

void encryptFile(const char* payloadPath, char* outputPath);
BYTE* decryptFile(const char* payloadPath, OUT size_t& r_size);


PIMAGE_NT_HEADERS get_nt_headers(const BYTE* virtualpointer);
size_t getSizeOfImage(wchar_t* FilePath);
