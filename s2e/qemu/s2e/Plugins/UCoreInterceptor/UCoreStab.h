#ifndef _UCORE_STAB_DESCRIPTOR_H_
#define _UCORE_STAB_DESCRIPTOR_H_

/* SIZEOF UCoreStab : 12 */

#define STAB_BEGIN_ADDR_SYMBOL "__STAB_BEGIN__"
#define STAB_END_ADDR_SYMBOL "__STAB_END__"
#define STABSTR_BEGIN_ADDR_SYMBOL "__STABSTR_BEGIN__"
#define STABSTR_END_ADDR_SYMBOL "__STABSTR_END__"

#define N_GSYM      0x20    // global symbol
#define N_FNAME     0x22    // F77 function name
#define N_FUN       0x24    // procedure name
#define N_STSYM     0x26    // data segment variable
#define N_LCSYM     0x28    // bss segment variable
#define N_MAIN      0x2a    // main function name
#define N_PC        0x30    // global Pascal symbol
#define N_RSYM      0x40    // register variable
#define N_SLINE     0x44    // text segment line number
#define N_DSLINE    0x46    // data segment line number
#define N_BSLINE    0x48    // bss segment line number
#define N_SSYM      0x60    // structure/union element
#define N_SO        0x64    // main source file name
#define N_LSYM      0x80    // stack variable
#define N_BINCL     0x82    // include file beginning
#define N_SOL       0x84    // included source file name
#define N_PSYM      0xa0    // parameter variable
#define N_EINCL     0xa2    // include file end
#define N_ENTRY     0xa4    // alternate entry point
#define N_LBRAC     0xc0    // left bracket
#define N_EXCL      0xc2    // deleted include file
#define N_RBRAC     0xe0    // right bracket
#define N_BCOMM     0xe2    // begin common
#define N_ECOMM     0xe4    // end common
#define N_ECOML     0xe8    // end common (local name)
#define N_LENG      0xfe    // length of preceding entry

#include <inttypes.h>

namespace s2e{
  typedef struct _UcoreStab {
    uint32_t n_strx;
    uint8_t n_type;
    uint8_t n_other;
    uint16_t n_desc;
    uint32_t n_value; //pointer to the value
  } UCoreStab;
}
#endif
