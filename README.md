# Windows Privilege Elevation Tool

## Overview

This program is designed to elevate privileges from an administrative account to the `NT AUTHORITY\SYSTEM` account on Windows systems. It utilizes native NT system calls to interact directly with the operating system, manipulating access tokens and processes to achieve privilege escalation. After obtaining `NT AUTHORITY\SYSTEM` privileges, it creates a new process under this context and subsequently escalates privileges to the `TrustedInstaller` user.

## Workflow

1. Opens the current process' access token.
2. Sets `SE_DEBUG_PRIVILEGE`.
3. Opens the `winlogon.exe` process.
4. Impersonates the logged user.
5. Duplicates `winlogon.exe`'s access token.
6. Creates a new process (part two of the program).
7. The second PE (Portable Executable):
   - Starts the TrustedInstaller service.
   - Gets the TrustedInstaller service's PID.
   - Retrieves its first thread.
   - Impersonates the thread.
   - Creates a new process (`powershell.exe`) under the TrustedInstaller context.

## Files

### 1. `get_nt.cpp`
- Implements the main logic for privilege escalation to `NT AUTHORITY\SYSTEM`.

### 2. `get_nt.h`
- Header file containing definitions, macros, structs, and function prototypes for `get_nt.cpp`.

### 3. `get_nt_64.asm`
- Assembly code using indirect syscalls to implement low-level NT functions.

### 4. `get_ti.cpp`
- Implements the main logic for privilege escalation to the TrustedInstaller user.

### 5. `get_ti.h`
- Header file containing definitions, macros, structs, and function prototypes for `get_ti.cpp`.

### 6. `get_ti_64.asm`
- Assembly code using indirect syscalls for low-level NT functions required by `get_ti.cpp`.

> Note: Elevating privileges to `NT AUTHORITY\SYSTEM` is a prerequisite to starting the Service Manager and TrustedInstaller service.

## Build Instructions

To compile and run the tool:
1. Use Visual Studio for C++ files and MASM for the assembly files.
2. Compile `get_nt.cpp`, `get_nt.h`, and `get_nt_64.asm` into an executable.
3. Similarly, compile `get_ti.cpp`, `get_ti.h`, and `get_ti_64.asm` into a second executable.
4. Run the first executable as an administrator.

## Warning

This tool is intended for **educational purposes only**. Unauthorized use of privilege escalation tools may result in severe legal consequences and violate ethical standards. Ensure you have explicit permission before using this tool on any system. 

## License 

This project is distributed under the GNU General Public License. Refer to the [LICENSE](LICENSE) file for details.
