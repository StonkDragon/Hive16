    ldui r0 0x10
    mov r2 r0
    ldi r2 16

loop:
    stb r0 r0
    inc r0
    cmp r0 r2
    jlt loop

    halt
