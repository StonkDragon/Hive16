
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

#if defined(DEBUG) && DEBUG == 1
    #define FETCH8(cpu, addr) (fetch_barrier((cpu), (addr)), (cpu)->memory[(addr)] & 0xFF)
    #define STORE8(cpu, addr, value) (store_barrier((cpu), (addr), (value)), (cpu)->memory[(addr)] = (value) & 0xFF)
#else
    #define FETCH8(cpu, addr) ((cpu)->memory[(addr)] & 0xFF)
    #define STORE8(cpu, addr, value) ((cpu)->memory[(addr)] = (value) & 0xFF)
#endif
#define FETCH16(cpu, addr) (FETCH8((cpu), (addr)) | (((unsigned short) FETCH8((cpu), (addr) + 1)) << 8))
#define STORE16(cpu, addr, value) (STORE8((cpu), (addr), (value) & 0xFF), STORE8((cpu), (addr) + 1, (value) >> 8))
};

unsigned char fetch_barrier(struct cpu* cpu, unsigned short addr) {
    printf("Fetching 0x%04hx: 0x%02hhx\n", addr, cpu->memory[addr]);
    return 0;
}

unsigned char store_barrier(struct cpu* cpu, unsigned short addr, unsigned char value) {
    printf("Storing 0x%04hx: 0x%02hhx -> 0x%02hhx\n", addr, cpu->memory[addr], value);
    return 0;
}

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

#define CONCAT0(a, b) a ## b
#define CONCAT(a, b) CONCAT0(a, b)
#define const_assert(expr, msg) struct { int static_assertion_failed : !!(expr); } __attribute__((unused)) CONCAT(static_assertion_failed_at_line_, __LINE__) = { 0 }

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
#define OP_misc_int     0x01
#define OP_misc_pushf   0x02
#define OP_misc_popf    0x03

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
                case OP_misc_int:
                    return strformat("int");
                    break;
                case OP_misc_pushf:
                    return strformat("pushf");
                    break;
                case OP_misc_popf:
                    return strformat("popf");
                    break;
            }
            break;
    }
    return NULL;
}

void exec(struct cpu* cpu, union instruction opcode) {
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
    unsigned char flags;
    int runInstr;
#if defined(DEBUG) && DEBUG == 1
    char* disassembled;
#endif

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
                case OP_misc_int:
                    cpu->interrupt = 1;
                    break;
                case OP_misc_pushf:
                    flags = (cpu->Z << 3) | (cpu->N << 2) | (cpu->I << 1) | cpu->R;
                    STORE16(cpu, cpu->SP, flags);
                    cpu->SP -= 2;
                    break;
                case OP_misc_popf:
                    flags = FETCH16(cpu, cpu->SP);
                    cpu->SP += 2;
                    cpu->Z = (flags >> 3) & 1;
                    cpu->N = (flags >> 2) & 1;
                    cpu->I = (flags >> 1) & 1;
                    cpu->R = flags & 1;
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

void cycle(struct cpu* cpu) {
    union instruction opcode;
    
    /* fetch the opcode from memory */
    opcode.raw = FETCH16(cpu, cpu->PC);
    cpu->PC += 2;

    exec(cpu, opcode);
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

void abort_with(const char* message) {
    fprintf(stderr, "%s\n", message);
    abort();
}

#define array(type) struct { type* data; long int count; long int capacity; }
#define emptyArray(type) (type) {0}
#define push(arr, ...) do { if ((arr).count == (arr).capacity) { (arr).capacity = (arr).capacity == 0 ? 16 : (arr).capacity * 2; (arr).data = realloc((arr).data, (arr).capacity * sizeof(*(arr).data)); if ((arr).data == NULL) { fprintf(stderr, "Failed to allocate memory\n"); exit(1); } } (arr).data[(arr).count++] = (__VA_ARGS__); } while (0)
#define pop(arr) (arr).data[--(arr).count]
#define top(arr) (arr).data[(arr).count - 1]
#define free_array(arr) do { if ((arr).data) { free((arr).data); (arr).data = NULL; } } while (0)

struct reloc {
    char* name;
    enum type {
        TYPE_IMM11 = 1,
        TYPE_IMM8  = 2,
        TYPE_RAW   = 4,
        TYPE_LDI   = 8,
        TYPE_LDUI  = 16
    } type;
    unsigned short where;
};
struct label {
    char* name;
    unsigned short where;
};

typedef array(union instruction) instructionArray;
typedef array(struct token) tokenArray;
typedef array(struct reloc) relocArray;
typedef array(struct label) labelArray;

instructionArray parse(char* fileData) {
    long int line = 1;
    instructionArray instructions = {0};
    tokenArray tokens = {0};
    relocArray relocs = {0};
    labelArray labels = {0};
    
    struct token token = {0};
    union instruction instr = {0};
    struct reloc reloc = {0};
    struct label label = {0};

    long int i = 0;
    char* end = NULL;

    unsigned short tmp;

    if (fileData == NULL) {
        printf("File data is NULL\n");
        return emptyArray(instructionArray);
    }
    
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

        if (*fileData == '-' || (*fileData >= '0' && *fileData <= '9')) {
            token.type = TOKEN_NUMBER;
        } else {
            token.type = TOKEN_IDENT;
        }
        
        for (i = 0; (fileData[i] != ' ' && fileData[i] != '\t' && fileData[i] != '\n' && fileData[i] != ';') && fileData[i]; i++);
        end = fileData + i;
        token.value = malloc(i + 1);
        i = 0;
        do {
            token.value[i++] = *fileData++;
        } while (fileData != end);

        token.value[i] = '\0';
        token.line = line;
        token.len = i;

        push(tokens, token);
        token = (struct token) {0};
    }

    for (i = 0; i < tokens.count; i++) {
        #define incr(i, max) do { (i)++; if ((i) >= (max)) { fprintf(stderr, "Unexpected end of file\n"); exit(1); } } while (0)
        #define check(f, v) do { if (!(f)(v)) { fprintf(stderr, "Expected constraint %s to be true for %s\n", #f, v); exit(1); } } while (0)
        #define expect(expected, v) do { if (tokens.data[i].type != (expected) || tokens.data[i].value == NULL) { fprintf(stderr, "Expected a %s\n", (v)); exit(1); } } while (0)

        if (tokens.data[i].type != TOKEN_IDENT || tokens.data[i].value == NULL) {
            fprintf(stderr, "Expected an identifier\n");
            exit(1);
        }

        if (tokens.data[i].value[tokens.data[i].len - 1] == ':') {
            
            label.name = drop_last(tokens.data[i].value, tokens.data[i].len);
            if (label.name == NULL) {
                fprintf(stderr, "Failed to allocate memory\n");
                return emptyArray(instructionArray);
            }
            label.where = instructions.count;
            push(labels, label);
            label = (struct label) {0};
            continue;
        } else if (tokens.data[i].value[0] == '.') {
            if (equals(tokens.data[i].value, ".org")) {
                incr(i, tokens.count);
                expect(TOKEN_NUMBER, "number");

                tmp = parse_unsigned(tokens.data[i].value);
                if (tmp % 2 != 0) {
                    fprintf(stderr, "Address must be even\n");
                    exit(1);
                }
                tmp /= 2;

                instr.raw = 0;
                while (instructions.count < tmp) {
                    push(instructions, instr);
                }
            } else if (equals(tokens.data[i].value, ".word")) {
                incr(i, tokens.count);
                if (tokens.data[i].type == TOKEN_NUMBER) {
                    instr.raw = parse_unsigned(tokens.data[i].value);
                } else {
                    reloc.name = tokens.data[i].value;
                    reloc.type = TYPE_RAW;
                    reloc.where = instructions.count;
                    push(relocs, reloc);
                    reloc = (struct reloc) {0};
                    instr.raw = 0;
                }
                push(instructions, instr);
            } else if (equals(tokens.data[i].value, ".byte")) {
                incr(i, tokens.count);
                expect(TOKEN_NUMBER, "number");

                instr.raw = parse_unsigned(tokens.data[i].value) & 0xFF;
                push(instructions, instr);
            } else {
                fprintf(stderr, "Unknown directive: %s\n", tokens.data[i].value);
                exit(1);
            }
            instr = (union instruction) {0};
            continue;
        }

        instr.raw = 0;

        if (equals(tokens.data[i].value, "add")) {
            instr.tri_reg.opcode = OP_add;
            
            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);
            
            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);
            
            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "sub")) {
            instr.tri_reg.opcode = OP_sub;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);
            
            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);
            
            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "cmp")) {
            instr.tri_reg.opcode = OP_sub;
            
            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);
            
            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);

            instr.tri_reg.discardRes = 1;
        } else if (equals(tokens.data[i].value, "mul")) {
            instr.tri_reg.opcode = OP_mul;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "div")) {
            instr.tri_reg.opcode = OP_div;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "mod")) {
            instr.tri_reg.opcode = OP_mod;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "divs")) {
            instr.tri_reg.opcode = OP_div;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);

            instr.tri_reg.isSigned = 1;
        } else if (equals(tokens.data[i].value, "mods")) {
            instr.tri_reg.opcode = OP_mod;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);            

            instr.tri_reg.isSigned = 1;
        } else if (equals(tokens.data[i].value, "and")) {
            instr.tri_reg.opcode = OP_and;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "tst")) {
            instr.tri_reg.opcode = OP_and;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);

            instr.tri_reg.discardRes = 1;
        } else if (equals(tokens.data[i].value, "or")) {
            instr.tri_reg.opcode = OP_or;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "xor")) {
            instr.tri_reg.opcode = OP_xor;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "not")) {
            instr.tri_reg.opcode = OP_not;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "lsl")) {
            instr.tri_reg.opcode = OP_lsl;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "lsr")) {
            instr.tri_reg.opcode = OP_lsr;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "asr")) {
            instr.tri_reg.opcode = OP_lsr;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rm = parse_register(tokens.data[i].value);

            instr.tri_reg.isSigned = 1;
        } else if (equals(tokens.data[i].value, "mov")) {
            instr.tri_reg.opcode = OP_mov;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "inc")) {
            instr.tri_reg.opcode = OP_inc;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "dec")) {
            instr.tri_reg.opcode = OP_dec;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "ldi")) {
            instr.reg_imm.opcode = OP_ldi;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.reg_imm.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            if (tokens.data[i].type == TOKEN_NUMBER) {
                instr.reg_imm.imm8 = parse_signed(tokens.data[i].value);
            } else {
                reloc.name = tokens.data[i].value;
                reloc.type = TYPE_LDI;
                reloc.where = instructions.count;
                
                push(relocs, reloc);
                reloc = (struct reloc) {0};
            }
        } else if (equals(tokens.data[i].value, "ldui")) {
            instr.reg_imm.opcode = OP_ldui;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.reg_imm.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            if (tokens.data[i].type == TOKEN_NUMBER) {
                instr.reg_imm.imm8 = parse_signed(tokens.data[i].value);
            } else {
                reloc.name = tokens.data[i].value;
                reloc.type = TYPE_LDUI;
                reloc.where = instructions.count;
                
                push(relocs, reloc);
                reloc = (struct reloc) {0};
            }
        } else if (equals(tokens.data[i].value, "ld")) {
            instr.tri_reg.opcode = OP_ld;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            if (i + 1 < tokens.count && is_register(tokens.data[i + 1].value)) {
                incr(i, tokens.count);
                instr.tri_reg.Rm = parse_register(tokens.data[i].value);
                instr.tri_reg.isSigned = 1;
            }
        } else if (equals(tokens.data[i].value, "st")) {
            instr.tri_reg.opcode = OP_st;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            if (i + 1 < tokens.count && is_register(tokens.data[i + 1].value)) {
                incr(i, tokens.count);
                instr.tri_reg.Rm = parse_register(tokens.data[i].value);
                instr.tri_reg.isSigned = 1;
            }
        } else if (equals(tokens.data[i].value, "ldb")) {
            instr.tri_reg.opcode = OP_ldb;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            if (i + 1 < tokens.count && is_register(tokens.data[i + 1].value)) {
                incr(i, tokens.count);
                instr.tri_reg.Rm = parse_register(tokens.data[i].value);
                instr.tri_reg.isSigned = 1;
            }
        } else if (equals(tokens.data[i].value, "stb")) {
            instr.tri_reg.opcode = OP_stb;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rn = parse_register(tokens.data[i].value);

            if (i + 1 < tokens.count && is_register(tokens.data[i + 1].value)) {
                incr(i, tokens.count);
                instr.tri_reg.Rm = parse_register(tokens.data[i].value);
                instr.tri_reg.isSigned = 1;
            }
        } else if (equals(tokens.data[i].value, "push")) {
            instr.tri_reg.opcode = OP_push;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "pop")) {
            instr.tri_reg.opcode = OP_pop;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "ret")) {
            instr.tri_reg.opcode = OP_pop;

            instr.tri_reg.Rd = 7;
        } else if (equals(tokens.data[i].value, "jmp")) {
            instr.imm.opcode = OP_jmp;

            incr(i, tokens.count);
            if (tokens.data[i].type == TOKEN_NUMBER) {
                instr.imm.simm11 = parse_signed(tokens.data[i].value);
            } else {
                reloc.name = tokens.data[i].value;
                reloc.type = TYPE_IMM11;
                reloc.where = instructions.count;
                
                push(relocs, reloc);
                reloc = (struct reloc) {0};
            }
        } else if (equals(tokens.data[i].value, "jr")) {
            instr.tri_reg.opcode = OP_jr;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);
        } else if (equals(tokens.data[i].value, "call")) {
            instr.imm.opcode = OP_call;

            incr(i, tokens.count);
            if (tokens.data[i].type == TOKEN_NUMBER) {
                instr.imm.simm11 = parse_signed(tokens.data[i].value);
            } else {
                reloc.name = tokens.data[i].value;
                reloc.type = TYPE_IMM11;
                reloc.where = instructions.count;
                
                push(relocs, reloc);
                reloc = (struct reloc) {0};
            }
        } else if (equals(tokens.data[i].value, "callr")) {
            instr.tri_reg.opcode = OP_callr;

            incr(i, tokens.count);
            check(is_register, tokens.data[i].value);
            instr.tri_reg.Rd = parse_register(tokens.data[i].value);
        } else if (tokens.data[i].value[0] == 'j') {
            if (tokens.data[i].value[1] == 'r') {
                instr.cond_reg.opcode = OP_jrcc;

                instr.cond_reg.cond = parse_condition(tokens.data[i].value + 2);

                incr(i, tokens.count);
                check(is_register, tokens.data[i].value);
                instr.cond_reg.Rd = parse_register(tokens.data[i].value);
            } else {
                instr.cond_imm.opcode = OP_jcc;

                instr.cond_imm.cond = parse_condition(tokens.data[i].value + 1);

                incr(i, tokens.count);
                if (tokens.data[i].type == TOKEN_NUMBER) {
                    instr.cond_imm.simm8 = parse_signed(tokens.data[i].value);
                } else {
                    reloc.name = tokens.data[i].value;
                    reloc.type = TYPE_IMM8;
                    reloc.where = instructions.count;
                    
                    push(relocs, reloc);
                    reloc = (struct reloc) {0};
                }
            }
        } else if (equals(tokens.data[i].value, "clrz")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 0;
        } else if (equals(tokens.data[i].value, "setz")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 1;
        } else if (equals(tokens.data[i].value, "clrn")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 2;
        } else if (equals(tokens.data[i].value, "setn")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 3;
        } else if (equals(tokens.data[i].value, "clri")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 4;
        } else if (equals(tokens.data[i].value, "seti")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 5;
        } else if (equals(tokens.data[i].value, "halt") || equals(tokens.data[i].value, "clrr")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 6;
        } else if (equals(tokens.data[i].value, "nop") || equals(tokens.data[i].value, "setr")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_flags;
            instr.misc.arg1 = 7;
        } else if (equals(tokens.data[i].value, "int")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_int;
        } else if (equals(tokens.data[i].value, "pushf")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_pushf;
        } else if (equals(tokens.data[i].value, "popf")) {
            instr.misc.opcode = OP_misc;
            instr.misc.misc_op = OP_misc_popf;
        } else {
            fprintf(stderr, "Unknown instruction: %s\n", tokens.data[i].value);
            exit(1);
        }

        push(instructions, instr);
        instr = (union instruction) {0};
    }

    for (i = 0; i < relocs.count; i++) {
        long int j;
        for (j = 0; j < labels.count; j++) {
            if (strcmp(relocs.data[i].name, labels.data[j].name) == 0) {
                unsigned short currentLocation = relocs.data[i].where + 1; /* when executing the instruction the PC is already incremented */
                signed short diff = labels.data[j].where - currentLocation;
                switch (relocs.data[i].type) {
                    case TYPE_IMM11:
                        if (diff < -1024 || diff > 1023) {
                            fprintf(stderr, "Label %s is too far away from instruction at %d\n", relocs.data[i].name, relocs.data[i].where);
                            exit(1);
                        }
                        instructions.data[relocs.data[i].where].imm.simm11 = diff;
                        break;
                    case TYPE_IMM8:
                        if (diff < -256 || diff > 255) {
                            fprintf(stderr, "Label %s is too far away from instruction at %d\n", relocs.data[i].name, relocs.data[i].where);
                            exit(1);
                        }
                        instructions.data[relocs.data[i].where].cond_imm.simm8 = diff;
                        break;
                    case TYPE_RAW:
                        instructions.data[relocs.data[i].where].raw = labels.data[j].where * 2;
                        break;
                    case TYPE_LDI:
                        instructions.data[relocs.data[i].where].reg_imm.imm8 = (labels.data[j].where * 2) & 0xFF;
                        break;
                    case TYPE_LDUI:
                        instructions.data[relocs.data[i].where].reg_imm.imm8 = ((labels.data[j].where * 2) >> 8) & 0xFF;
                        break;
                }
                break;
            }
        }
        if (j == labels.count) {
            fprintf(stderr, "Undefined label: %s\n", relocs.data[i].name);
            exit(1);
        }
    }

    return instructions;
}

int assemble(const char* f) {
    char* data;
    unsigned long int size;
    FILE* file;
    instructionArray instructions;
    int i;
    
    file = fopen(f, "rb");
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

    instructions = parse(data);
    if (!instructions.data) {
        fprintf(stderr, "Failed to parse file\n");
        return 1;
    }

    file = fopen("program.bin", "wb");
    if (!file) {
        fprintf(stderr, "Failed to open program.bin\n");
        return 1;
    }

    for (i = 0; i < instructions.count; i++) {
        if (fwrite(&instructions.data[i], sizeof(union instruction), 1, file) != 1) {
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
    unsigned long int j;
#endif
    unsigned long int i;

    union instruction setup[] = {
        {.misc = {.opcode = OP_misc, .misc_op = OP_misc_flags, .arg1 = 0x0 | 0x4}}, /* clri */
        {.reg_imm = {.opcode = OP_ldi, .Rd = 6, .imm8 = 0xff}}, /* ldi sp 0xff */
        {.reg_imm = {.opcode = OP_ldui, .Rd = 6, .imm8 = 0xcf}}, /* ldui sp 0xcf */
        {.reg_imm = {.opcode = OP_ldi, .Rd = 7, .imm8 = 0xfc}}, /* ldi pc 0xfc */
        {.reg_imm = {.opcode = OP_ldui, .Rd = 7, .imm8 = 0xff}}, /* ldui pc 0xff */
        {.tri_reg = {.opcode = OP_ld, .Rd = 7, .Rn = 7}}, /* ld pc pc */
        {.misc = {.opcode = OP_misc, .misc_op = OP_misc_flags, .arg1 = 0x1 | 0x6}}, /* nop, important: sets run flag */
    };
    union instruction onInterrupt[] = {
        {.tri_reg = {.opcode = OP_push, .Rd = 7}}, /* push pc */
        {.misc = {.opcode = OP_misc, .misc_op = OP_misc_pushf}}, /* pushf */
        {.misc = {.opcode = OP_misc, .misc_op = OP_misc_flags, .arg1 = 0x0 | 0x4}}, /* clri */
        {.reg_imm = {.opcode = OP_ldi, .Rd = 7, .imm8 = 0xfe}}, /* ldi pc 0xfe */
        {.reg_imm = {.opcode = OP_ldui, .Rd = 7, .imm8 = 0xff}}, /* ldui pc 0xff */
        {.tri_reg = {.opcode = OP_ld, .Rd = 7, .Rn = 7}}, /* ld pc pc */
    };

    for (i = 0; !cpu->R; i++) {
        exec(cpu, setup[i]);
    }

    while (cpu->R) {
        if (cpu->I && cpu->interrupt) {
            for (i = 0; i < sizeof(onInterrupt) / sizeof(union instruction); i++) {
                exec(cpu, onInterrupt[i]);
            }
        }
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
        printf("0x%04hx %s\n", instr.raw, instrStr);
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
