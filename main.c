
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

struct cpu {
    unsigned short registers[8];

    #define PC registers[7]
    #define SP registers[6]

    unsigned char Z:1;
    unsigned char N:1;
    unsigned char I:1;
    unsigned char R:1;

    unsigned char memory[__UINT16_MAX__ + 1];

    unsigned char interrupt:1;

    #define FETCH8(cpu, addr) ((cpu)->memory[(addr)] & 0xFF)
    #define FETCH16(cpu, addr) (((cpu)->memory[(addr)] & 0xFF) | (((unsigned short) (cpu)->memory[(addr) + 1]) << 8))
    #define STORE8(cpu, addr, value) ((cpu)->memory[(addr)] = (value) & 0xFF)
    #define STORE16(cpu, addr, value) ((cpu)->memory[(addr)] = (value) & 0xFF, (cpu)->memory[(addr) + 1] = ((value) >> 8) & 0xFF)
};

union instruction {
    struct {
        unsigned char Rd:3;
        unsigned char Rn:3;
        unsigned char Rm:3;
        unsigned char isSigned:1;
        unsigned char discardRes:1;
        unsigned char opcode:5;
    } __attribute__((packed)) tri_reg;
    struct {
        unsigned char Rd:3;
        unsigned char imm8:8;
        unsigned char opcode:5;
    } __attribute__((packed)) reg_imm;
    struct {
          signed short simm11:11;
        unsigned char opcode:5;
    } __attribute__((packed)) imm;
    struct {
          signed short simm8:8;
        unsigned char cond:3;
        unsigned char opcode:5;
    } __attribute__((packed)) cond_imm;
    struct {
        unsigned char Rd:3;
        unsigned char _:5;
        unsigned char cond:3;
        unsigned char opcode:5;
    } __attribute__((packed)) cond_reg;
    struct {
        unsigned char arg2:3;
        unsigned char arg1:3;
        unsigned char misc_op:5;
        unsigned char opcode:5;
    } __attribute__((packed)) misc;
    unsigned short raw;
};

#define const_assert(expr, msg) struct { int static_assertion_failed : !!(expr); } __attribute__((unused)) static_assertion_failed = { 0 }

const_assert(sizeof(union instruction) == 2, "Instruction size is not 2 bytes");

static long int inline_strlen(const char* str) {
    long int len;

    if (str == NULL) {
        return 0;
    }

    for (len = 0; str[len]; len++);
    return len;
}

static int equals(const char* a, const char* b) {
    long int lenA;
    long int lenB;
    long int i;

    if (a == NULL || b == NULL) {
        return 0;
    }

    lenA = inline_strlen(a);
    lenB = inline_strlen(b);

    if (lenA != lenB) {
        return 0;
    }

    for (i = 0; i < lenA; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }

    return 1;
}

unsigned short extract_bits(unsigned short x, unsigned char first, unsigned char last) {
    unsigned short mask;
    unsigned short result;

    if (last < first) {
        fprintf(stderr, "Invalid range: %d to %d\n", first, last);
        exit(1);
    }

    /* mask to mask out the bits we want */
    mask = (1 << (last - first + 1)) - 1;

    /* shift the bits we want to the bottom of the word, then mask them */
    result = (x >> first) & mask;
    return result;
}

unsigned short deposit_bits(unsigned short x, unsigned char first, unsigned char last, unsigned short y) {
    unsigned short mask;
    unsigned short result;

    if (last < first) {
        fprintf(stderr, "Invalid range: %d to %d\n", first, last);
        exit(1);
    }

    /* mask to mask out the bits we want */
    mask = (1 << (last - first + 1)) - 1;

    /* mask out the bits we want to replace, shift the new bits to the correct position and or them in */
    result = (x & ~(mask << first)) | ((y & mask) << first);
    return result;
}

signed short extract_bits_signed(unsigned short x, unsigned char first, unsigned char last) {
    unsigned short mask;
    signed short result;

    if (last < first) {
        fprintf(stderr, "Invalid range: %d to %d\n", first, last);
        exit(1);
    }

    /* mask to mask out the bits we want */
    mask = (1 << (last - first + 1)) - 1;

    /* shift the bits we want to the bottom of the word, then mask them */
    result = (x >> first) & mask;

    /* sign extend the result */
    if (result & (1 << (last - first))) {
        /* mask is all 1s except for the lowest (last - first) bits */
        result |= ~mask;
    }
    return result;
}

unsigned short deposit_bits_signed(unsigned short x, unsigned char first, unsigned char last, signed short y) {
    unsigned short mask;
    unsigned short result;

    if (last < first) {
        fprintf(stderr, "Invalid range: %d to %d\n", first, last);
        exit(1);
    }

    /* mask to mask out the bits we want */
    mask = (1 << (last - first + 1)) - 1;

    /* mask out the bits we want to replace, shift the new bits to the correct position and or them in */
    result = (x & ~(mask << first)) | ((y & mask) << first);
    return result;
}

void abort_if_false(int condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "Assertion failed: %s\n", message);
        exit(1);
    }
}

#define EXRTACT_BITS(x, first, last) (abort_if_false(first <= last, "first > last"), extract_bits((x), (first), (last)))
#define DEPOSIT_BITS(x, first, last, y) (abort_if_false(first <= last, "first > last"), deposit_bits((x), (first), (last), (y)))
#define EXTRACT_BITS_SIGNED(x, first, last) (abort_if_false(first <= last, "first > last"), extract_bits_signed((x), (first), (last)))
#define DEPOSIT_BITS_SIGNED(x, first, last, y) (abort_if_false(first <= last, "first > last"), deposit_bits_signed((x), (first), (last), (y)))

#define OP_add          0x00
#define OP_sub          0x01
#define OP_mul          0x02
#define OP_div          0x03
#define OP_mod          0x04
#define OP_and          0x05
#define OP_or           0x06
#define OP_xor          0x07
#define OP_not          0x08
#define OP_lsl          0x09
#define OP_lsr          0x0a
#define OP_mov          0x0b
#define OP_inc          0x0c
#define OP_dec          0x0d
#define OP_ldi          0x0e
#define OP_ldui         0x0f

#define OP_ld           0x10
#define OP_st           0x11
#define OP_ldb          0x12
#define OP_stb          0x13

#define OP_push         0x14
#define OP_pop          0x15

#define OP_jcc          0x16
#define OP_jrcc         0x17

#define OP_jmp          0x18
#define OP_jr           0x19
#define OP_call         0x1a
#define OP_callr        0x1b

#define OP_misc         0x1c
#define OP_misc_flags   0x00

#define OP_ret          0x1c
#define OP_nop          0x1d
#define OP_unused       0x1e
#define OP_halt         0x1f

const char* conditions[] = {
    "eq",
    "lt",
    "le",
    "<unused>",
    "ne",
    "ge",
    "gt",
    NULL
};

const char* registers[] = {
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    NULL
};

unsigned short parse_register(const char* reg) {
    /* check if the register is of the form r[0-7] */
    if (reg[0] == 'r' && reg[1] >= '0' && reg[1] <= '7' && reg[2] == '\0') {
        return reg[1] - '0';
    
    /* check if the register is one of the special registers (pc, sp) */
    } else if (reg[0] == 'p' && reg[1] == 'c' && reg[2] == '\0') {
        return 7;
    } else if (reg[0] == 's' && reg[1] == 'p' && reg[2] == '\0') {
        return 6;
    }

    fprintf(stderr, "Invalid register: %s\n", reg);
    exit(1);
}

unsigned short parse_condition(const char* cond) {
    if (cond == NULL) {
        fprintf(stderr, "Invalid condition: %s\n", cond);
        exit(1);
    }
    if (cond[0] == '\0') {
        return 0;
    }
    if (equals(cond, "eq") || equals(cond, "z")) {
        return 0;
    }
    if (equals(cond, "lt")) {
        return 1;
    }
    if (equals(cond, "le")) {
        return 2;
    }
    if (equals(cond, "ne") || equals(cond, "nz")) {
        return 4;
    }
    if (equals(cond, "ge")) {
        return 5;
    }
    if (equals(cond, "gt")) {
        return 6;
    }

    fprintf(stderr, "Invalid condition: %s\n", cond);
    exit(1);
}

unsigned short parse_unsigned(const char* str) {
    unsigned short value;
    long int len;
    const char* begin;
    char* end;
    char base;

    if (str == NULL) {
        fprintf(stderr, "Invalid unsigned: %s\n", str);
        exit(1);
    }

    len = inline_strlen(str);
    if (len == 0) {
        fprintf(stderr, "Invalid unsigned: %s\n", str);
        exit(1);

    /* hex, binary, or octal */
    } else if (len > 1) {
        if (str[0] == '0') { /* hex, binary, or octal */
            if (str[1] == 'x') { /* hex */
                begin = str + 2;
                base = 16;
            } else if (str[1] == 'b') { /* binary */
                begin = str + 2;
                base = 2;
            } else { /* octal */
                begin = str + 1;
                base = 8;
            }
        } else { /* decimal */
            begin = str;
            base = 10;
        }
    
    /* decimal */
    } else {
        begin = str;
        base = 10;
    }

    value = strtoul(begin, &end, base);

    /* check if the entire string was consumed, if not, it's of the form (number)(garbage) */
    if (*end != '\0') {
        fprintf(stderr, "Invalid unsigned: %s\n", str);
        exit(1);
    }

    return value;
}

signed short parse_signed(const char* str) {
    unsigned short value;
    int sign;

    if (str == NULL) {
        fprintf(stderr, "Invalid signed: %s\n", str);
        exit(1);
    }

    /* check if the number is negative or positive, then parse the unsigned value */
    if (str[0] == '-') {
        sign = -1;
        str++;
    } else if (str[0] == '+') {
        sign = 1;
        str++;
    } else {
        sign = 1;
    }
    
    value = parse_unsigned(str);

    /* check if the value is within the signed range */
    if (value > 0x7FFF) {
        fprintf(stderr, "Invalid signed: %s\n", str);
        exit(1);
    }
    return value * sign;
}

char* vstrformat(const char* fmt, va_list args) {
    va_list argsCopy;
    long int len;
    char* str;

    va_copy(argsCopy, args);
    len = vsnprintf(NULL, 0, fmt, argsCopy);
    va_end(argsCopy);

    str = malloc(len + 1);
    if (str == NULL) {
        return NULL;
    }

    vsnprintf(str, len + 1, fmt, args);
    return str;
}

char* strformat(const char* fmt, ...) {
    va_list args;
    char* str;

    va_start(args, fmt);
    str = vstrformat(fmt, args);
    va_end(args);
    return str;
}

void check_free(void* ptr) {
    if (*(void**) ptr) {
        free(*(void**) ptr);
        *(void**) ptr = NULL;
    }
}

char* disassemble_op(union instruction instr, unsigned short pc) {
    switch (instr.tri_reg.opcode) {
        case OP_add:
            return strformat("add r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            break;
        case OP_sub:
            if (instr.tri_reg.discardRes) {
                return strformat("cmp r%d r%d", instr.tri_reg.Rn, instr.tri_reg.Rm);
            } else {
                return strformat("sub r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            }
            break;
        case OP_mul:
            return strformat("mul r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            break;
        case OP_div:
            if (instr.tri_reg.isSigned) {
                return strformat("divs r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            } else {
                return strformat("div r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            }
            break;
        case OP_mod:
            if (instr.tri_reg.isSigned) {
                return strformat("mods r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            } else {
                return strformat("mod r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            }
            break;
        case OP_and:
            if (instr.tri_reg.discardRes) {
                return strformat("tst r%d r%d", instr.tri_reg.Rn, instr.tri_reg.Rm);
            } else {
                return strformat("and r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            }
            break;
        case OP_or:
            return strformat("or r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            break;
        case OP_xor:
            return strformat("xor r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            break;
        case OP_not:
            return strformat("not r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn);
            break;
        case OP_lsl:
            return strformat("lsl r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            break;
        case OP_lsr:
            if (instr.tri_reg.isSigned) {
                return strformat("asr r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            } else {
                return strformat("lsr r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            }
            break;
        case OP_mov:
            return strformat("mov r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn);
            break;
        case OP_inc:
            return strformat("inc r%d", instr.tri_reg.Rd);
            break;
        case OP_dec:
            return strformat("dec r%d", instr.tri_reg.Rd);
            break;
        case OP_ldi:
            return strformat("ldi r%d 0x%02x", instr.reg_imm.Rd, instr.reg_imm.imm8);
            break;
        case OP_ldui:
            return strformat("ldui r%d 0x%02x", instr.reg_imm.Rd, instr.reg_imm.imm8);
            break;
        case OP_ld:
            if (instr.tri_reg.isSigned) {
                return strformat("ld r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            } else {
                return strformat("ld r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn);
            }
            break;
        case OP_st:
            if (instr.tri_reg.isSigned) {
                return strformat("st r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            } else {
                return strformat("st r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn);
            }
            break;
        case OP_ldb:
            if (instr.tri_reg.isSigned) {
                return strformat("ldb r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            } else {
                return strformat("ldb r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn);
            }
            break;
        case OP_stb:
            if (instr.tri_reg.isSigned) {
                return strformat("stb r%d r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn, instr.tri_reg.Rm);
            } else {
                return strformat("stb r%d r%d", instr.tri_reg.Rd, instr.tri_reg.Rn);
            }
            break;
        case OP_push:
            return strformat("push r%d", instr.tri_reg.Rd);
            break;
        case OP_pop:
            if (instr.tri_reg.Rd == 7) {
                return strformat("ret");
            } else {
                return strformat("pop r%d", instr.tri_reg.Rd);
            }
            break;
        case OP_jmp:
            return strformat("jmp 0x%04hx", (unsigned short) (pc + instr.imm.simm11 * 2));
            break;
        case OP_jr:
            return strformat("jr r%d", instr.tri_reg.Rd);
            break;
        case OP_call:
            return strformat("call 0x%04hx", (unsigned short) (pc + instr.imm.simm11 * 2));
            break;
        case OP_callr:
            return strformat("callr r%d", instr.tri_reg.Rd);
            break;
        case OP_jcc:
            return strformat("j%s 0x%04hx", conditions[instr.cond_imm.cond], (unsigned short) (pc + instr.cond_imm.simm8 * 2));
            break;
        case OP_jrcc:
            return strformat("jr%s r%d", conditions[instr.cond_reg.cond], instr.cond_reg.Rd);
            break;
        case OP_misc:
            switch (instr.misc.misc_op) {
                case OP_misc_flags:
                    switch (instr.misc.arg1) {
                        case 0:
                            return strformat("clrz");
                            break;
                        case 1:
                            return strformat("setz");
                            break;
                        case 2:
                            return strformat("clrn");
                            break;
                        case 3:
                            return strformat("setn");
                            break;
                        case 4:
                            return strformat("clri");
                            break;
                        case 5:
                            return strformat("seti");
                            break;
                        case 6:
                            return strformat("halt");
                            break;
                        case 7:
                            return strformat("nop");
                            break;
                    }
                    break;
            }
            break;
    }
    return NULL;
}

void cycle(struct cpu* cpu) {
    union instruction opcode;
    unsigned char op;
    unsigned char Rd;
    unsigned char Rn;
    unsigned char Rm;
    unsigned char imm8;
      signed char simm8;
    unsigned char isSigned;
    unsigned char isExtendedLoad;
    unsigned char keepResult;
      signed short simm11;
    unsigned char cond;
    unsigned short address;
    unsigned short result;
    int runInstr;
#if defined(DEBUG) && DEBUG == 1
    char* disassembled;
#endif
    
    /* fetch the opcode from memory */
    opcode.raw = FETCH16(cpu, cpu->PC);
    cpu->PC += 2;

    /* decode the opcode */
    op = opcode.imm.opcode;

    /* decode the operands */
    Rd = opcode.tri_reg.Rd;
    Rn = opcode.tri_reg.Rn;
    Rm = opcode.tri_reg.Rm;
    imm8 = opcode.reg_imm.imm8;
    isSigned = opcode.tri_reg.isSigned;
    isExtendedLoad = isSigned;
    keepResult = !opcode.tri_reg.discardRes;
    simm11 = opcode.imm.simm11;
    simm8 = opcode.cond_imm.simm8;
    cond = opcode.cond_imm.cond;

#if defined(DEBUG) && DEBUG == 1
    disassembled = disassemble_op(opcode, cpu->PC);

    printf("opcode: 0x%04hx\n", opcode.raw);
    printf("op: 0x%02hx (%s)\n", op, disassembled);

    printf("Z: %d\n", cpu->Z);
    printf("N: %d\n", cpu->N);
    printf("I: %d\n", cpu->I);

    check_free(&disassembled);
#endif

    switch (op) {
        case OP_add:
            if (isSigned) {
                result = (signed short)cpu->registers[Rn] + (signed short)cpu->registers[Rm];
            } else {
                result = cpu->registers[Rn] + cpu->registers[Rm];
            }
            cpu->Z = (result & 0xFFFF) == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            
            break;
        case OP_sub:
            if (isSigned) {
                result = (signed short)cpu->registers[Rn] - (signed short)cpu->registers[Rm];
            } else {
                result = cpu->registers[Rn] - cpu->registers[Rm];
            }
            cpu->Z = result == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            break;
        case OP_mul:
            result = cpu->registers[Rn] * cpu->registers[Rm];
            cpu->Z = (result & 0xFFFF) == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            break;
        case OP_div:
            if (cpu->registers[Rm] == 0) {
                fprintf(stderr, "Division by zero\n");
                exit(1);
            }
            if (isSigned) {
                result = (signed short)cpu->registers[Rn] / (signed short)cpu->registers[Rm];
            } else {
                result = cpu->registers[Rn] / cpu->registers[Rm];
            }
            cpu->Z = (result & 0xFFFF) == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            break;
        case OP_mod:
            if (cpu->registers[Rm] == 0) {
                fprintf(stderr, "Division by zero\n");
                exit(1);
            }
            if (isSigned) {
                result = (signed short)cpu->registers[Rn] % (signed short)cpu->registers[Rm];
            } else {
                result = cpu->registers[Rn] % cpu->registers[Rm];
            }
            cpu->Z = (result & 0xFFFF) == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            break;
        case OP_and:
            result = cpu->registers[Rn] & cpu->registers[Rm];
            cpu->Z = (result & 0xFFFF) == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            break;
        case OP_or:
            result = cpu->registers[Rn] | cpu->registers[Rm];
            cpu->Z = (result & 0xFFFF) == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            break;
        case OP_xor:
            result = cpu->registers[Rn] ^ cpu->registers[Rm];
            cpu->Z = (result & 0xFFFF) == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            break;
        case OP_not:
            result = ~cpu->registers[Rn];
            cpu->Z = (result & 0xFFFF) == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            break;
        case OP_lsl:
            result = cpu->registers[Rn] << cpu->registers[Rm];
            cpu->Z = (result & 0xFFFF) == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            break;
        case OP_lsr:
            if (isSigned) {
                result = (signed short)cpu->registers[Rn] >> cpu->registers[Rm];
            } else {
                result = cpu->registers[Rn] >> cpu->registers[Rm];
            }
            cpu->Z = (result & 0xFFFF) == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            break;
        case OP_mov:
            result = cpu->registers[Rn];
            cpu->Z = (result & 0xFFFF) == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            break;
        case OP_inc:
            result = cpu->registers[Rd] + 1;
            cpu->Z = (result & 0xFFFF) == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            break;
        case OP_dec:
            result = cpu->registers[Rd] - 1;
            cpu->Z = (result & 0xFFFF) == 0;
            cpu->N = (result & 0x8000) != 0;

            if (keepResult) {
                cpu->registers[Rd] = result;
            }
            break;
        case OP_ldi:
            cpu->registers[Rd] = (cpu->registers[Rd] & 0xFF00) | (imm8 << 0);
            break;
        case OP_ldui:
            cpu->registers[Rd] = (cpu->registers[Rd] & 0x00FF) | (imm8 << 8);
            break;
        case OP_ld:
            if (isExtendedLoad) {
                address = cpu->registers[Rn] + cpu->registers[Rm];
            } else {
                address = cpu->registers[Rn];
            }
            cpu->registers[Rd] = FETCH16(cpu, address);
            break;
        case OP_st:
            if (isExtendedLoad) {
                address = cpu->registers[Rn] + cpu->registers[Rm];
            } else {
                address = cpu->registers[Rn];
            }
            STORE16(cpu, address, cpu->registers[Rd]);
            break;
        case OP_ldb:
            if (isExtendedLoad) {
                address = cpu->registers[Rn] + cpu->registers[Rm];
            } else {
                address = cpu->registers[Rn];
            }
            cpu->registers[Rd] = FETCH8(cpu, address);
            break;
        case OP_stb:
            if (isExtendedLoad) {
                address = cpu->registers[Rn] + cpu->registers[Rm];
            } else {
                address = cpu->registers[Rn];
            }
            STORE8(cpu, address, cpu->registers[Rd]);
            break;
        case OP_push:
            STORE16(cpu, cpu->SP, cpu->registers[Rd]);
            cpu->SP -= 2;
            break;
        case OP_pop:
            cpu->SP += 2;
            cpu->registers[Rd] = FETCH16(cpu, cpu->SP);
            break;
        case OP_jcc:
            runInstr = 0;
            switch (cond) {
                case 0: /* eq */
                    runInstr = cpu->Z;
                    break;
                case 1: /* lt */
                    runInstr = cpu->N;
                    break;
                case 2: /* le */
                    runInstr = cpu->Z || cpu->N;
                    break;
                case 4: /* ne */
                    runInstr = !cpu->Z;
                    break;
                case 5: /* ge */
                    runInstr = !cpu->N;
                    break;
                case 6: /* gt */
                    runInstr = !cpu->Z && !cpu->N;
                    break;
                default:
                    fprintf(stderr, "Invalid condition: %d\n", cond);
                    exit(1);
                    break;
            }
            if (runInstr) {
                cpu->PC += simm8 * 2;
            }
            break;
        case OP_jrcc:
            runInstr = 0;
            switch (cond) {
                case 0: /* eq */
                    runInstr = cpu->Z;
                    break;
                case 1: /* lt */
                    runInstr = !cpu->N;
                    break;
                case 2: /* le */
                    runInstr = cpu->Z || !cpu->N;
                    break;
                case 4: /* ne */
                    runInstr = !cpu->Z;
                    break;
                case 5: /* ge */
                    runInstr = cpu->N;
                    break;
                case 6: /* gt */
                    runInstr = !cpu->Z && cpu->N;
                    break;
                default:
                    fprintf(stderr, "Invalid condition: %d\n", cond);
                    exit(1);
                    break;
            }
            if (runInstr) {
                cpu->PC = cpu->registers[Rd];
            }
            break;
        case OP_jmp:
            cpu->PC += simm11 * 2;
            break;
        case OP_jr:
            cpu->PC = cpu->registers[Rd];
            break;
        case OP_call:
            STORE16(cpu, cpu->SP, cpu->PC);
            cpu->SP -= 2;
            cpu->PC += simm11 * 2;
            break;
        case OP_callr:
            STORE16(cpu, cpu->SP, cpu->PC);
            cpu->SP -= 2;
            cpu->PC = cpu->registers[Rd];
            break;
        case OP_misc:
            switch (opcode.misc.misc_op) {
                case OP_misc_flags:
                    {
                        switch (opcode.misc.arg1 >> 1) {
                            case 0: cpu->Z = (opcode.misc.arg1 & 1); break;
                            case 1: cpu->N = (opcode.misc.arg1 & 1); break;
                            case 2: cpu->I = (opcode.misc.arg1 & 1); break;
                            case 3: cpu->R = (opcode.misc.arg1 & 1); break;
                        }
                    }
                    break;
                default:
                    fprintf(stderr, "Invalid misc operation: %d\n", opcode.misc.misc_op);
                    exit(1);
                    break;
            }
            break;
            
        default:
            fprintf(stderr, "Invalid opcode: %04x\n", opcode.raw);
            exit(1);
            break;
    }
}

struct token {
    enum {
        TOKEN_IDENT,
        TOKEN_NUMBER
    } type;
    char* value;
    long int line;
    long int len;
};

int is_register(const char* reg) {
    long int len;

    if (reg == NULL) {
        return 0;
    }

    len = inline_strlen(reg);
    if (len != 2) {
        return 0;
    }

    if (reg[0] != 'r') {
        if (reg[0] == 'p' && reg[1] == 'c') {
            return 1;
        } else if (reg[0] == 's' && reg[1] == 'p') {
            return 1;
        }
        return 0;
    }
    if (reg[1] < '0' || reg[1] > '7') {
        return 0;
    }

    return 1;
}

char* drop_last(const char* str, long int len) {
    char* newStr;
    long int i;

    if (str == NULL) {
        return NULL;
    }

    newStr = malloc(len);
    if (newStr == NULL) {
        return NULL;
    }

    for (i = 0; i < len - 1; i++) {
        newStr[i] = str[i];
    }
    newStr[i] = '\0';

    return newStr;
}

union instruction* parse(char* fileData, long int* count) {
    long int line;
    union instruction* instructions;
    long int instructionCount;
    long int instructionCapacity;
    struct token* tokens;
    long int tokenCount;
    long int tokenCapacity;
    struct {
        char* name;
        char type;
        #define TYPE_IMM11 1
        #define TYPE_IMM8 2
        unsigned short where;
    }* relocs;
    long int relocCount;
    long int relocCapacity;
    struct {
        char* name;
        unsigned short where;
    }* labels;
    long int labelCount;
    long int labelCapacity;

    long int i;
    char* end;

    if (fileData == NULL) {
        printf("File data is NULL\n");
        return NULL;
    }
    if (count == NULL) {
        printf("Count is NULL\n");
        return NULL;
    }

    tokenCount = 0;
    tokenCapacity = 16;
    tokens = malloc(tokenCapacity * sizeof(struct token));
    if (tokens == NULL) {
        printf("Failed to allocate memory\n");
        return NULL;
    }

    instructionCount = 0;
    instructionCapacity = 16;
    instructions = malloc(instructionCapacity * sizeof(union instruction));
    if (instructions == NULL) {
        printf("Failed to allocate memory\n");
        return NULL;
    }

    relocCount = 0;
    relocCapacity = 16;
    relocs = malloc(relocCapacity * sizeof(*relocs));
    if (relocs == NULL) {
        printf("Failed to allocate memory\n");
        return NULL;
    }

    labelCount = 0;
    labelCapacity = 16;
    labels = malloc(labelCapacity * sizeof(*labels));
    if (labels == NULL) {
        printf("Failed to allocate memory\n");
        return NULL;
    }

    line = 1;
    while (*fileData) {
        if (*fileData == '\n') {
            line++;
            fileData++;
            continue;
        } else if (*fileData == ' ' || *fileData == '\t') {
            fileData++;
            continue;
        } else if (*fileData == ';') {
            while (*fileData && *fileData != '\n') {
                fileData++;
            }
            continue;
        }

        if (tokenCount == tokenCapacity) {
            tokenCapacity *= 2;
            tokens = realloc(tokens, tokenCapacity * sizeof(struct token));
            if (tokens == NULL) {
                printf("Failed to allocate memory\n");
                return NULL;
            }
        }
        if (*fileData == '-' || (*fileData >= '0' && *fileData <= '9')) {
            tokens[tokenCount].type = TOKEN_NUMBER;
        } else {
            tokens[tokenCount].type = TOKEN_IDENT;
        }
        
        for (i = 0; (fileData[i] != ' ' && fileData[i] != '\t' && fileData[i] != '\n' && fileData[i] != ';') && fileData[i]; i++);
        end = fileData + i;
        tokens[tokenCount].value = malloc(i + 1);
        i = 0;
        do {
            tokens[tokenCount].value[i++] = *fileData++;
        } while (fileData != end);

        tokens[tokenCount].value[i] = '\0';
        tokens[tokenCount].line = line;
        tokens[tokenCount].len = i;
        tokenCount++;
    }

    for (i = 0; i < tokenCount; i++) {
        union instruction instr;
        
        if (instructionCount == instructionCapacity) {
            instructionCapacity *= 2;
            instructions = realloc(instructions, instructionCapacity * sizeof(union instruction));
            if (instructions == NULL) {
                printf("Failed to allocate memory\n");
                return NULL;
            }
        }

        #define incr(i, tokenCount) do { (i)++; if ((i) >= (tokenCount)) { fprintf(stderr, "Unexpected end of file\n"); exit(1); } } while (0)
        #define check(f, v) do { if (!(f)(v)) { fprintf(stderr, "Expected constraint %s to be true for %s\n", #f, v); exit(1); } } while (0)

        if (tokens[i].type != TOKEN_IDENT || tokens[i].value == NULL) {
            fprintf(stderr, "Expected an identifier\n");
            exit(1);
        }

        if (tokens[i].value[tokens[i].len - 1] == ':') {
            if (labelCount == labelCapacity) {
                labelCapacity *= 2;
                labels = realloc(labels, labelCapacity * sizeof(*labels));
                if (labels == NULL) {
                    printf("Failed to allocate memory\n");
                    return NULL;
                }
            }
            labels[labelCount].name = drop_last(tokens[i].value, tokens[i].len);
            if (labels[labelCount].name == NULL) {
                printf("Failed to allocate memory\n");
                return NULL;
            }
            labels[labelCount].where = instructionCount;
            labelCount++;
            continue;
        }

        instr.raw = 0;

        if (equals(tokens[i].value, "add")) {
            instr.tri_reg.opcode = OP_add;
            
            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);
            
            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);
            
            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "sub")) {
            instr.tri_reg.opcode = OP_sub;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);
            
            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);
            
            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "cmp")) {
            instr.tri_reg.opcode = OP_sub;
            
            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);
            
            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);

            instr.tri_reg.discardRes = 1;
        } else if (equals(tokens[i].value, "mul")) {
            instr.tri_reg.opcode = OP_mul;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "div")) {
            instr.tri_reg.opcode = OP_div;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "mod")) {
            instr.tri_reg.opcode = OP_mod;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "divs")) {
            instr.tri_reg.opcode = OP_div;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);

            instr.tri_reg.isSigned = 1;
        } else if (equals(tokens[i].value, "mods")) {
            instr.tri_reg.opcode = OP_mod;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);            

            instr.tri_reg.isSigned = 1;
        } else if (equals(tokens[i].value, "and")) {
            instr.tri_reg.opcode = OP_and;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "tst")) {
            instr.tri_reg.opcode = OP_and;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);

            instr.tri_reg.discardRes = 1;
        } else if (equals(tokens[i].value, "or")) {
            instr.tri_reg.opcode = OP_or;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "xor")) {
            instr.tri_reg.opcode = OP_xor;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "not")) {
            instr.tri_reg.opcode = OP_not;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "lsl")) {
            instr.tri_reg.opcode = OP_lsl;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "lsr")) {
            instr.tri_reg.opcode = OP_lsr;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "asr")) {
            instr.tri_reg.opcode = OP_lsr;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rm = parse_register(tokens[i].value);

            instr.tri_reg.isSigned = 1;
        } else if (equals(tokens[i].value, "mov")) {
            instr.tri_reg.opcode = OP_mov;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "inc")) {
            instr.tri_reg.opcode = OP_inc;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "dec")) {
            instr.tri_reg.opcode = OP_dec;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "ldi")) {
            instr.reg_imm.opcode = OP_ldi;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.reg_imm.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            instr.reg_imm.imm8 = parse_signed(tokens[i].value);
        } else if (equals(tokens[i].value, "ldui")) {
            instr.reg_imm.opcode = OP_ldui;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.reg_imm.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            instr.reg_imm.imm8 = parse_signed(tokens[i].value);
        } else if (equals(tokens[i].value, "ld")) {
            instr.tri_reg.opcode = OP_ld;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            if (i + 1 < tokenCount && is_register(tokens[i + 1].value)) {
                incr(i, tokenCount);
                instr.tri_reg.Rm = parse_register(tokens[i].value);
                instr.tri_reg.isSigned = 1;
            }
        } else if (equals(tokens[i].value, "st")) {
            instr.tri_reg.opcode = OP_st;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            if (i + 1 < tokenCount && is_register(tokens[i + 1].value)) {
                incr(i, tokenCount);
                instr.tri_reg.Rm = parse_register(tokens[i].value);
                instr.tri_reg.isSigned = 1;
            }
        } else if (equals(tokens[i].value, "ldb")) {
            instr.tri_reg.opcode = OP_ldb;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            if (i + 1 < tokenCount && is_register(tokens[i + 1].value)) {
                incr(i, tokenCount);
                instr.tri_reg.Rm = parse_register(tokens[i].value);
                instr.tri_reg.isSigned = 1;
            }
        } else if (equals(tokens[i].value, "stb")) {
            instr.tri_reg.opcode = OP_stb;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rn = parse_register(tokens[i].value);

            if (i + 1 < tokenCount && is_register(tokens[i + 1].value)) {
                incr(i, tokenCount);
                instr.tri_reg.Rm = parse_register(tokens[i].value);
                instr.tri_reg.isSigned = 1;
            }
        } else if (equals(tokens[i].value, "push")) {
            instr.tri_reg.opcode = OP_push;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "pop")) {
            instr.tri_reg.opcode = OP_pop;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "ret")) {
            instr.tri_reg.opcode = OP_pop;

            instr.tri_reg.Rd = 7;
        } else if (equals(tokens[i].value, "jmp")) {
            instr.imm.opcode = OP_jmp;

            incr(i, tokenCount);
            if (tokens[i].type == TOKEN_NUMBER) {
                instr.imm.simm11 = parse_signed(tokens[i].value);
            } else {
                if (relocCount == relocCapacity) {
                    relocCapacity *= 2;
                    relocs = realloc(relocs, relocCapacity * sizeof(*relocs));
                    if (relocs == NULL) {
                        printf("Failed to allocate memory\n");
                        return NULL;
                    }
                }

                relocs[relocCount].name = tokens[i].value;
                relocs[relocCount].type = TYPE_IMM11;
                relocs[relocCount].where = instructionCount;
                relocCount++;
            }
        } else if (equals(tokens[i].value, "jr")) {
            instr.tri_reg.opcode = OP_jr;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);
        } else if (equals(tokens[i].value, "call")) {
            instr.imm.opcode = OP_call;

            incr(i, tokenCount);
            if (tokens[i].type == TOKEN_NUMBER) {
                instr.imm.simm11 = parse_signed(tokens[i].value);
            } else {
                if (relocCount == relocCapacity) {
                    relocCapacity *= 2;
                    relocs = realloc(relocs, relocCapacity * sizeof(*relocs));
                    if (relocs == NULL) {
                        printf("Failed to allocate memory\n");
                        return NULL;
                    }
                }

                relocs[relocCount].name = tokens[i].value;
                relocs[relocCount].type = TYPE_IMM11;
                relocs[relocCount].where = instructionCount;
                relocCount++;
            }
        } else if (equals(tokens[i].value, "callr")) {
            instr.tri_reg.opcode = OP_callr;

            incr(i, tokenCount);
            check(is_register, tokens[i].value);
            instr.tri_reg.Rd = parse_register(tokens[i].value);
        } else if (tokens[i].value[0] == 'j') {
            if (tokens[i].value[1] == 'r') {
                instr.cond_reg.opcode = OP_jrcc;

                instr.cond_reg.cond = parse_condition(tokens[i].value + 2);

                incr(i, tokenCount);
                check(is_register, tokens[i].value);
                instr.cond_reg.Rd = parse_register(tokens[i].value);
            } else {
                instr.cond_imm.opcode = OP_jcc;

                instr.cond_imm.cond = parse_condition(tokens[i].value + 1);

                incr(i, tokenCount);
                if (tokens[i].type == TOKEN_NUMBER) {
                    instr.cond_imm.simm8 = parse_signed(tokens[i].value);
                } else {
                    if (relocCount == relocCapacity) {
                        relocCapacity *= 2;
                        relocs = realloc(relocs, relocCapacity * sizeof(*relocs));
                        if (relocs == NULL) {
                            printf("Failed to allocate memory\n");
                            return NULL;
                        }
                    }

                    relocs[relocCount].name = tokens[i].value;
                    relocs[relocCount].type = TYPE_IMM8;
                    relocs[relocCount].where = instructionCount;
                    relocCount++;
                }
            }
        } else if (equals(tokens[i].value, "clrz")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 0;
        } else if (equals(tokens[i].value, "setz")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 1;
        } else if (equals(tokens[i].value, "clrn")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 2;
        } else if (equals(tokens[i].value, "setn")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 3;
        } else if (equals(tokens[i].value, "clri")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 4;
        } else if (equals(tokens[i].value, "seti")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 5;
        } else if (equals(tokens[i].value, "halt")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 6;
        } else if (equals(tokens[i].value, "nop")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 7;
        } else {
            fprintf(stderr, "Unknown instruction: %s\n", tokens[i].value);
            exit(1);
        }

        instructions[instructionCount] = instr;
        instructionCount++;
    }

    for (i = 0; i < relocCount; i++) {
        long int j;
        for (j = 0; j < labelCount; j++) {
            if (strcmp(relocs[i].name, labels[j].name) == 0) {
                unsigned short currentLocation = relocs[i].where + 1; /* when executing the instruction the PC is already incremented */
                signed short diff = labels[j].where - currentLocation;
                if (relocs[i].type == TYPE_IMM8) {
                    if (diff < -256 || diff > 255) {
                        fprintf(stderr, "Label %s is too far away from instruction at %d\n", relocs[i].name, relocs[i].where);
                        exit(1);
                    }
                    instructions[relocs[i].where].cond_imm.simm8 = diff;
                } else {
                    if (diff < -1024 || diff > 1023) {
                        fprintf(stderr, "Label %s is too far away from instruction at %d\n", relocs[i].name, relocs[i].where);
                        exit(1);
                    }
                    instructions[relocs[i].where].imm.simm11 = diff;
                }
                break;
            }
        }
        if (j == labelCount) {
            fprintf(stderr, "Undefined label: %s\n", relocs[i].name);
            exit(1);
        }
    }

    *count = instructionCount;
    return instructions;
}

int assemble(const char* f) {
    char* data;
    unsigned long int size;
    FILE* file;
    union instruction* instructions;
    long int count;
    int i;
    
    file = fopen(f, "r");
    if (!file) {
        fprintf(stderr, "Failed to open %s\n", f);
        return 1;
    }

    data = NULL;
    size = 0;

    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "Failed to seek file\n");
        return 1;
    }
    size = ftell(file);
    if (size == (unsigned long int) -1) {
        fprintf(stderr, "Failed to get file size\n");
        return 1;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to seek file\n");
        return 1;
    }

    data = malloc(size);
    if (!data) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }

    if (fread(data, 1, size, file) != size) {
        fprintf(stderr, "Failed to read file\n");
        return 1;
    }
    fclose(file);

    instructions = parse(data, &count);
    if (!instructions) {
        fprintf(stderr, "Failed to parse file\n");
        return 1;
    }

    file = fopen("program.bin", "wb");
    if (!file) {
        fprintf(stderr, "Failed to open program.bin\n");
        return 1;
    }

    for (i = 0; i < count; i++) {
        if (fwrite(&instructions[i], sizeof(union instruction), 1, file) != 1) {
            fprintf(stderr, "Failed to write to program.bin\n");
            return 1;
        }
    }
    fclose(file);

    check_free(&data);
    check_free(&instructions);
    return 0;
}

void run(struct cpu* cpu) {
#if defined(DEBUG) && DEBUG == 1
    int emptyLines;
    unsigned long int i;
    unsigned long int j;
#endif

    cpu->R = 1;
    while (cpu->R) {
        cycle(cpu);
    }

#if defined(DEBUG) && DEBUG == 1
    for (i = 0; i < 6; i++) {
        printf("R%lu: %d (0x%04x)\n", i, cpu->registers[i], cpu->registers[i]);
    }
    printf("SP: %d (0x%04x)\n", cpu->SP, cpu->SP);
    printf("PC: %d (0x%04x)\n", cpu->PC, cpu->PC);

    printf("Z: %d\n", cpu->Z);
    printf("N: %d\n", cpu->N);
    printf("I: %d\n", cpu->I);
    printf("R: %d\n", cpu->R);

    printf("        00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n");
    emptyLines = 0;
    for (i = 0; i < sizeof(cpu->memory); i += 16) {
        if (i + 16 < sizeof(cpu->memory)) {
            for (j = 0; j < 16; j++) {
                if (cpu->memory[i + j] != 0) {
                    emptyLines = 0;
                    break;
                }
                emptyLines++;
            }
            if (emptyLines != 0) {
                if (emptyLines == 16) {
                    printf("*\n");
                }
                continue;
            }
        }
        printf("0x%04lx: ", i);
        for (j = 0; j < 16; j++) {
            printf("%02hhx ", cpu->memory[i + j]);
        }
        printf("\n");
    }
#endif
}

struct cpu* load(const char* f) {
    struct cpu* cpu;
    FILE* file;
    unsigned long int size;

    cpu = malloc(sizeof(struct cpu));
    memset(&cpu->memory, 0x00, sizeof(cpu->memory));

    file = fopen(f, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open %s\n", f);
        check_free(&cpu);
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "Failed to seek file\n");
        check_free(&cpu);
        return NULL;
    }
    size = ftell(file);
    if (size == (unsigned long int) -1) {
        fprintf(stderr, "Failed to get file size\n");
        check_free(&cpu);
        return NULL;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to seek file\n");
        check_free(&cpu);
        return NULL;
    }

    if (size > sizeof(((struct cpu*) 0)->memory)) {
        fprintf(stderr, "File is too large\n");
        check_free(&cpu);
        return NULL;
    }

    if (fread(cpu->memory, 1, size, file) != size) {
        fprintf(stderr, "Failed to read file\n");
        check_free(&cpu);
        return NULL;
    }
    fclose(file);
    return cpu;
}

int disassemble(const char* f) {
    FILE* file;
    unsigned long int i;
    unsigned long int size;
    unsigned short* instructions;

    file = fopen(f, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open %s\n", f);
        return 1;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "Failed to seek file\n");
        fclose(file);
        return 1;
    }
    size = ftell(file);
    if (size == (unsigned long int) -1) {
        fprintf(stderr, "Failed to get file size\n");
        fclose(file);
        return 1;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to seek file\n");
        fclose(file);
        return 1;
    }

    if (size > sizeof(((struct cpu*) 0)->memory)) {
        fprintf(stderr, "File is too large\n");
        fclose(file);
        return 1;
    }

    instructions = malloc(size);
    if (!instructions) {
        fprintf(stderr, "Failed to allocate memory\n");
        fclose(file);
        check_free(&instructions);
        return 1;
    }

    if (fread(instructions, sizeof(unsigned short), size / sizeof(unsigned short), file) != size / sizeof(unsigned short)) {
        fprintf(stderr, "Failed to read file\n");
        fclose(file);
        check_free(&instructions);
        return 1;
    }

    i = 0;
    while (i < size / sizeof(unsigned short)) {
        union instruction instr;
        instr.raw = instructions[i];
        printf("0x%04lx: ", i * 2);
        i++;
        char* instrStr = disassemble_op(instr, i * 2);
        printf("%s\n", instrStr);
        check_free(&instrStr);
    }

    check_free(&instructions);
    return 0;
}

int main(int argc, char const *argv[]) {
    struct cpu* cpu;

    if (strcmp(argv[1], "as") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s as <program.asm>\n", argv[0]);
            return 1;
        }
        return assemble(argv[2]);
    } else if (strcmp(argv[1], "vm") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s vm <program.bin>\n", argv[0]);
            return 1;
        }
        cpu = load(argv[2]);
        if (!cpu) {
            fprintf(stderr, "Failed to load program\n");
            return 1;
        }
        run(cpu);
    } else if (strcmp(argv[1], "dis") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s dis <program.bin>\n", argv[0]);
            return 1;
        }
        return disassemble(argv[2]);
    } else {
        fprintf(stderr, "Invalid command\n");
        return 1;
    }
}
