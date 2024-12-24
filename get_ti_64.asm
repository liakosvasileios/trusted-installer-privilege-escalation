PUBLIC mNtOpenProcess				
PUBLIC addrNtOpenProcess			
PUBLIC mNtAllocateVirtualMemory
PUBLIC addrNtAllocateVirtualMemory
PUBLIC mNtWriteVirtualMemory
PUBLIC addrNtWriteVirtualMemory
PUBLIC mNtCreateThreadEx
PUBLIC addrNtCreateThreadEx
PUBLIC mNtClose
PUBLIC addrNtClose
PUBLIC mNtAdjustPrivilegesToken
PUBLIC addrNtAdjustPrivilegesToken
PUBLIC mNtDuplicateToken
PUBLIC addrNtDuplicateToken
PUBLIC mNtOpenProcessToken
PUBLIC addrNtOpenProcessToken
PUBLIC mNtQueryInformationToken
PUBLIC addrNtQueryInformationToken
PUBLIC mNtSetInformationThread
PUBLIC addrNtSetInformationThread
PUBLIC mZwImpersonateThread
PUBLIC addrZwImpersonateThread

.DATA 
mNtOpenProcess DWORD 0
addrNtOpenProcess QWORD 0
mNtAllocateVirtualMemory DWORD 0
addrNtAllocateVirtualMemory QWORD 0
mNtWriteVirtualMemory DWORD 0
addrNtWriteVirtualMemory QWORD 0
mNtCreateThreadEx DWORD 0
addrNtCreateThreadEx QWORD 0
mNtClose DWORD 0
addrNtClose QWORD 0
mNtAdjustPrivilegesToken DWORD 0
addrNtAdjustPrivilegesToken QWORD 0
mNtDuplicateToken DWORD 0
addrNtDuplicateToken QWORD 0
mNtOpenProcessToken DWORD 0
addrNtOpenProcessToken QWORD 0
mNtQueryInformationToken DWORD 0
addrNtQueryInformationToken QWORD 0
mNtSetInformationThread DWORD 0
addrNtSetInformationThread QWORD 0
mZwImpersonateThread DWORD 0
addrZwImpersonateThread QWORD 0

.CODE 
align 16

NtOpenProcess PROC
	mov r10, rcx
	mov eax, mNtOpenProcess
	jmp QWORD PTR [addrNtOpenProcess]
NtOpenProcess ENDP

NtAllocateVirtualMemory PROC
	mov r10, rcx
	mov eax, mNtAllocateVirtualMemory
	jmp QWORD PTR [addrNtAllocateVirtualMemory]
NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
	mov r10, rcx
	mov eax, mNtWriteVirtualMemory
	jmp QWORD PTR [addrNtWriteVirtualMemory]
NtWriteVirtualMemory ENDP

NtCreateThreadEx PROC
	mov r10, rcx
	mov eax, mNtCreateThreadEx
	jmp QWORD PTR [addrNtCreateThreadEx]
NtCreateThreadEx ENDP

NtClose PROC
	mov r10, rcx
	mov eax, mNtClose
	jmp QWORD PTR [addrNtClose]
NtClose ENDP

NtAdjustPrivilegesToken PROC
	mov r10, rcx
	mov eax, mNtAdjustPrivilegesToken
	jmp QWORD PTR [addrNtAdjustPrivilegesToken]
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
	mov r10, rcx
	mov eax, mNtDuplicateToken
	jmp QWORD PTR [addrNtDuplicateToken]
NtDuplicateToken ENDP

NtOpenProcessToken PROC
	mov r10, rcx
	mov eax, mNtOpenProcessToken
	jmp QWORD PTR [addrNtOpenProcessToken]
NtOpenProcessToken ENDP

NtQueryInformationToken PROC
	mov r10, rcx
	mov eax, mNtQueryInformationToken
	jmp QWORD PTR [addrNtQueryInformationToken]
NtQueryInformationToken ENDP

NtSetInformationThread PROC
	mov r10, rcx
	mov eax, mNtSetInformationThread
	jmp QWORD PTR [addrNtSetInformationThread]
NtSetInformationThread ENDP

ZwImpersonateThread PROC
	mov r10, rcx
	mov eax, mZwImpersonateThread
	jmp QWORD PTR [addrZwImpersonateThread]
ZwImpersonateThread ENDP

END