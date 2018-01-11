.intel_syntax noprefix
.CODE64
avatar_get_fs:
        push rbp
        mov rbp, rsp
        sub rsp, 0x100

        push rcx
        push r11
        push rsi
        push rdi
        
        mov rax, 0x9e
        mov rdi, 0x1003
        lea rsi, [rbp-0x20]
        syscall
        lea rsi, [rbp-0x20]
        mov rax, [rsi]

        pop rdi
        pop rsi
        pop r11
        pop rcx
        
        mov rsp, rbp
        pop rbp
avatar_get_fs_end:
        nop
