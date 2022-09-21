#include "util.h"
#include "aes.h"
#include <peconv.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#pragma warning(disable:4996)


DWORD translate_protect(DWORD sec_charact)
{
	if ((sec_charact & IMAGE_SCN_MEM_EXECUTE)
		&& (sec_charact & IMAGE_SCN_MEM_READ)
		&& (sec_charact & IMAGE_SCN_MEM_WRITE))
	{
		return PAGE_EXECUTE_READWRITE;
	}
	if ((sec_charact & IMAGE_SCN_MEM_EXECUTE)
		&& (sec_charact & IMAGE_SCN_MEM_READ))
	{
		return PAGE_EXECUTE_READ;
	}
	if (sec_charact & IMAGE_SCN_MEM_EXECUTE)
	{
		return PAGE_EXECUTE_READ;
	}

	if ((sec_charact & IMAGE_SCN_MEM_READ)
		&& (sec_charact & IMAGE_SCN_MEM_WRITE))
	{
		return PAGE_READWRITE;
	}
	if (sec_charact &  IMAGE_SCN_MEM_READ) {
		return PAGE_READONLY;
	}

	return PAGE_READWRITE;
}

bool is_compatibile(BYTE *implant_dll)
{
	bool is_payload64 = peconv::is64bit(implant_dll);
#ifdef _WIN64
	if (!is_payload64) {
		std::cerr << "For 64 bit loader you MUST use a 64 bit payload!\n";
		return false;
	}
#else
	if (is_payload64) {
		std::cerr << "For 32 bit loader you MUST use a 32 bit payload!\n";
		return false;
	}
#endif
	return true;
}


DWORD EncryptString(const unsigned char* lpData, const char* lpKey, unsigned char*& lpOut, DWORD dwDataSize)
{
	unsigned char btBlock[16];
	unsigned char btKey[16];
	unsigned int dwOutLen = 0;
	unsigned int iMul = 0;

	if ((dwDataSize % 16))
		iMul = 1;

	dwOutLen = ((dwDataSize / 16) + iMul) * 16;

	lpOut = (unsigned char*)malloc(dwOutLen + 1);

	memset(lpOut, 0x00, dwOutLen + 1);

	memset(btKey, 0x00, 16);

	memcpy(btKey, lpKey, strlen(lpKey) > 16 ? 16 : strlen(lpKey));

	for (int i = 0; i * 16 < dwDataSize; ++i) {

		unsigned int uiBlockSize = 16;

		if ((dwDataSize - (i * 16)) < 16)
			uiBlockSize = (dwDataSize - (i * 16));

		memset(btBlock, 0x00, 16);
		memcpy(btBlock, lpData + (i * 16), uiBlockSize);

		AES_ECB_encrypt(lpData + (i * 16), btKey, lpOut + (i * 16), 16);
	}

	return dwOutLen;
}

DWORD DecryptString(const unsigned char* lpData, const char* lpKey, unsigned char*& lpOut, DWORD dwDataSize)
{
	unsigned char btKey[16];
	unsigned int dwOutLen = 0;
	unsigned int iMul = 0;

	if ((dwDataSize % 16))
		iMul = 1;

	dwOutLen = ((dwDataSize / 16) + iMul) * 16;

	lpOut = (unsigned char*)malloc(dwOutLen + 1);

	memset(lpOut, 0x00, dwOutLen + 1);

	memset(btKey, 0x00, 16);

	memcpy(btKey, lpKey, strlen(lpKey) > 16 ? 16 : strlen(lpKey));

	for (int i = 0; i * 16 < dwDataSize; ++i) {
		AES_ECB_decrypt(lpData + (i * 16), btKey, lpOut + (i * 16), 16);
	}

	return dwOutLen;
}


PIMAGE_NT_HEADERS get_nt_headers(const BYTE* virtualpointer)
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeader;

	// Check dos_header == MZ
	dosHeader = (PIMAGE_DOS_HEADER)virtualpointer;
	// needed fields: e_magix and e_lfanew (ntHeader offset)
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	// Get pointer to NT header
	ntHeader = (PIMAGE_NT_HEADERS)((PCHAR)(virtualpointer)+dosHeader->e_lfanew);
	// needed fields: Signature 
	// FileHeader, OptionalFileHeader
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	return ntHeader;
}

size_t getSizeOfImage(wchar_t* FilePath) {
	NTSTATUS status = 0;
	HANDLE hFile = NULL;
	size_t img_size = 0;
	PIMAGE_NT_HEADERS ntHeader = NULL;
	PIMAGE_DOS_HEADER dosHeader;
	DWORD  dwBytesRead = 0;
	// Offset of file - NtReadFile
	OVERLAPPED ol = { 0 };

	// NtCreateFile
	hFile = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == NULL) {
		printf("CreateFileW error : 0x%x", GetLastError());
		return 0;
	}
	// Partially read the file instead of mapping the whole dll.
	// We need only the headers to get SizeOfImage
	// Try to guess dosHeader->e_lfanew : 0x100 is a reasonable value as most of the DLLs has dosHeader->e_lfanew <= 0x100
#define GUESS 0x100
	// Define buffersize at compile time so we can allocate the buffer in the stack
#define BUFFERSIZE ( sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + GUESS )
	char   ReadBuffer[BUFFERSIZE] = { 0 };
	// Read PE
	// ol == 0 --> OFFSET = 0 
	// NtReadFile
	status = ReadFile(hFile, ReadBuffer, BUFFERSIZE, &dwBytesRead, &ol);
	if (!NT_SUCCESS(status))
	{
		printf("NtReadFile: 0x%x\n", status);
		CloseHandle(hFile);
		return 0;
	}
	dosHeader = (PIMAGE_DOS_HEADER)ReadBuffer;
	// check if our guess was lucky
	if (dosHeader->e_lfanew <= GUESS) {
		// We already read enough bytes - we can read the NT Headers
		ntHeader = get_nt_headers((const BYTE*)ReadBuffer);
	}
	else {
		// read again
		// We shouldn't arrive here very often as we "guessed" a very common value of dosHeader->e_lfanew 

		// Read starting from offset dosHeader->e_lfanew - we are interested only to the NT headers.
		// https://stackoverflow.com/questions/40945819/read-file-from-100th-byte
		ol.Offset = dosHeader->e_lfanew;
		// We can reuse the same buffer
		// NtReadFile
		status = ReadFile(hFile, ReadBuffer, BUFFERSIZE, &dwBytesRead, &ol);
		if (!NT_SUCCESS(status))
		{
			printf("NtReadFile: 0x%x\n", status);
			CloseHandle(hFile);
			return 0;
		}
		ntHeader = (PIMAGE_NT_HEADERS)ReadBuffer;
	}

	if (ntHeader != NULL && ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		img_size = ntHeader->OptionalHeader.SizeOfImage;
	}
	// Close Handles
	CloseHandle(hFile);
	return img_size;
}

void encryptFile(const char* payloadPath, char* outputPath) {

	size_t payloadSize = 0;

	BYTE* payloadBuf = peconv::load_file(payloadPath, payloadSize);
	if (payloadBuf == NULL) {
		std::cerr << "Cannot read payload!" << std::endl;
		return;
	}

	unsigned char* lpszEncryptedString = nullptr;
	DWORD dwEncryptedSize = EncryptString(payloadBuf, "Hagrid29", lpszEncryptedString, payloadSize);
	char outputPath2[sizeof(payloadPath) + 5];
	if (outputPath == nullptr) {
		const char* suffix = ".enc";
		strcpy(outputPath2, payloadPath);
		strcat(outputPath2, suffix);
		outputPath = outputPath2;
	}
	FILE* file = fopen(outputPath, "wb");
	fwrite(lpszEncryptedString, 1, dwEncryptedSize, file);
}

BYTE* decryptFile(const char* payloadPath, OUT size_t& r_size) {

	size_t payloadSize = 0;

	BYTE* payladBuf = peconv::load_file(payloadPath, payloadSize);
	if (payladBuf == NULL) {
		std::cerr << "Cannot read payload!" << std::endl;
		return NULL;
	}
	unsigned char* lpszDecryptedString = nullptr;
	DWORD dwDecryptedSize = DecryptString(payladBuf, "Hagrid29", lpszDecryptedString, payloadSize);

	r_size = dwDecryptedSize;
	return lpszDecryptedString;
}

