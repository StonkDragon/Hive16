.org 0x0000
value: .word 0x1234

.org 0x8000
start:
    ldi r0 value
    ld r1 r0
    seti
    int
    halt

interrupt:
    ldi r3 0x34
    ldui r3 0x12
    popf
    ret

.org 0xfffc
.word start ; reset
.word interrupt ; interrupt
