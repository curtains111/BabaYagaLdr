# BabaYagaLdr

EDRs Tested Against: SentinelOne

BabaYagaLdr is a proof-of-concept (PoC) tool designed for advanced shellcode injection and execution with an emphasis on evasion techniques to bypass Endpoint Detection and Response (EDR) solutions. It leverages various anti-detection strategies, including process injection, API obfuscation, and stealthy memory manipulation, to avoid triggering common security mechanisms.

Key Features
Dynamic API Resolution: Instead of directly importing functions like VirtualAllocEx and WriteProcessMemory, BabaYagaLdr resolves them dynamically at runtime using GetProcAddress. This reduces the visibility of critical API calls in memory and avoids static detection.

Stealthy Memory Allocation:

Allocates memory in the target process as read-write (RW), copies the shellcode, and only later changes the memory permissions to read-execute (RX). This avoids triggering heuristics that flag memory marked as executable during allocation.
Randomizes the placement of the shellcode in memory, reducing predictable patterns.
APC Queue for Execution: Uses the QueueUserAPC mechanism to execute the shellcode in a thread of the target process. This method avoids creating new threads, reducing detection likelihood.

Memory Obfuscation:

Fills the memory space with cryptographically random data before inserting the shellcode, blending it into the memory environment.
Securely erases shellcode from local memory after injection using SecureZeroMemory to prevent forensic recovery.
Targeted Execution: Injects the shellcode into a suspended process (e.g., notepad.exe) to avoid creating suspicious processes like cmd.exe or werfault.exe.

EDR Evasion: Employs techniques to avoid detection based on MITRE ATT&CK techniques, including:

Defense Evasion: Dynamic API resolution, memory obfuscation, and stealthy shellcode execution.
Execution: Indirect execution using APC queues.
Privilege Escalation: Injecting into privileged processes if necessary.
