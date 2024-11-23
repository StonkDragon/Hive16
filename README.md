# Hive16 Assembly Language
Hive16 is a simple 16-bit RISC architecture.

## Overview
- 16-bit instructions
- 8 16-bit general purpose registers
    - 1 stack pointer (sp)
    - 1 program counter (pc)
- zero flag (Z)
- negative flag (N)
- interrupt enable flag (I)
- run flag (R)
- 16-bit address space
- 16-bit data bus

## Memory Map
!!! TODO

## Interrupts
!!! TODO

## Instructions
| Name | Encoding | Approx. Cycles | Psuedo Code |
|------|----------|----------------|-------------|
| add | `0 0000 -- Rm:3 Rn:3 Rd:3` | 1 | Rd = Rn + Rm |
| sub | `0 0001 0- Rm:3 Rn:3 Rd:3` | 1 | Rd = Rn - Rm |
| cmp | `0 0001 1- Rm:3 Rn:3 --- ` | 1 | Z = (Rn == Rm), N = (Rn < Rm) |
| mul | `0 0010 -- Rm:3 Rn:3 Rd:3` | 1 | Rd = Rn * Rm |
| div | `0 0011 -0 Rm:3 Rn:3 Rd:3` | 1 | Rd = Rn / Rm |
| divs | `0 0011 -1 Rm:3 Rn:3 Rd:3` | 1 | Rd = Rn % Rm |
| mod | `0 0100 -0 Rm:3 Rn:3 Rd:3` | 1 | Rd = Rn / Rm |
| mods | `0 0100 -1 Rm:3 Rn:3 Rd:3` | 1 | Rd = Rn % Rm |
| and | `0 0101 0- Rm:3 Rn:3 Rd:3` | 1 | Rd = Rn & Rm |
| tst | `0 0101 1- Rm:3 Rn:3 --- ` | 1 | Z = (Rn & Rm == 0) |
| or | `0 0110 -- Rm:3 Rn:3 Rd:3` | 1 | Rd = Rn | Rm |
| xor | `0 0111 -- Rm:3 Rn:3 Rd:3` | 1 | Rd = Rn ^ Rm |
| not | `0 1000 -- ---  Rn:3 Rd:3` | 1 | Rd = ~Rn |
| lsl | `0 1001 -- Rm:3 Rn:3 Rd:3` | 1 | Rd = Rn << Rm |
| lsr | `0 1010 0- Rm:3 Rn:3 Rd:3` | 1 | Rd = Rn >> Rm |
| asr | `0 1010 1- Rm:3 Rn:3 Rd:3` | 1 | Rd = Rn >>> Rm |
| mov | `0 1011 -- Rm:3 ---  Rd:3` | 1 | Rd = Rm |
| inc | `0 1100 -- ---  ---  Rd:3` | 1 | Rd++ |
| dec | `0 1101 -- ---  ---  Rd:3` | 1 | Rd-- |
| ldi | `0 1110 Imm:8        Rd:3` | 1 | Rd = Rd[15:8] | Imm |
| ldui | `0 1111 Imm:8        Rd:3` | 1 | Rd = Rd[7:0] | (Imm << 8) |
| ld | `100 00 -0 ---  Rn:3 Rd:3` | 1 | Rd = [Rn] |
| ld2 | `100 00 -1 Rm:3 Rn:3 Rd:3` | 1 | Rd = [Rn + Rm] |
| st | `100 01 -0 ---  Rn:3 Rd:3` | 1 | [Rn] = Rd |
| st2 | `100 01 -1 Rm:3 Rn:3 Rd:3` | 1 | [Rn + Rm] = Rd |
| ldb | `100 10 -0 ---  Rn:3 Rd:3` | 1 | Rd = [Rn] |
| ldb2 | `100 10 -1 Rm:3 Rn:3 Rd:3` | 1 | Rd = [Rn + Rm] |
| stb | `100 11 -0 ---  Rn:3 Rd:3` | 1 | [Rn] = Rd |
| stb2 | `100 11 -1 Rm:3 Rn:3 Rd:3` | 1 | [Rn + Rm] = Rd |
| push | `1010 0 -- ---  ---  Rd:3` | 1 | [--sp] = Rd |
| pop | `1010 1 -- ---  ---  Rd:3` | 1 | Rd = [sp++] |
| jcc | `10110 Cond:3 Imm:s8     ` | 1 | if (Cond) pc += Imm |
| jccr | `10111 Cond:3 -----  Rn:3` | 1 | if (Cond) pc = Rn |
| jmp | `110 00 Imm:s11          ` | 1 | pc += Imm |
| jr | `110 01 -- ---  ---  Rd:3` | 1 | pc = Rd |
| call | `110 10 Imm:s11          ` | 1 | [--sp] = pc, pc += Imm |
| callr | `110 11 -- ---  ---  Rd:3` | 1 | [--sp] = pc, pc = Rd |
| clrz | `11100  00 000  000  --- ` | 1 | Z = 0 |
| setz | `11100  00 000  001  --- ` | 1 | Z = 1 |
| clrn | `11100  00 000  010  --- ` | 1 | N = 0 |
| setn | `11100  00 000  011  --- ` | 1 | N = 1 |
| clri | `11100  00 000  100  --- ` | 1 | I = 0 |
| seti | `11100  00 000  101  --- ` | 1 | I = 1 |
| halt | `11100  00 000  110  --- ` | 1 | R = 0 |
| nop | `11100  00 000  111  --- ` | 1 | R = 1 |

## Registers
| Name | Encoding |
|------|----------|
| r0 | 000 |
| r1 | 001 |
| r2 | 010 |
| r3 | 011 |
| r4 | 100 |
| r5 | 101 |
| sp | 110 |
| pc | 111 |

## Conditions
| Name | Encoding | Check |
|------|----------|-------|
| eq | 000 | Z == 1 |
| lt | 001 | N == 1 |
| le | 010 | (N == 1) or (Z == 1) |
| ne | 100 | Z == 0 |
| ge | 101 | N == 0 |
| gt | 110 | (N == 0) and (Z == 0) |
