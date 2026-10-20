#!/usr/bin/env python3
"""Reproduce nl-regex.h from a directory of the six pinned upstream inputs.

Usage: sol-nl-amalgamate.py UPSTREAM_DIRECTORY OUTPUT_HEADER
This maintenance tool does not download, compile, or run a benchmark.
"""
from pathlib import Path
import re
import sys
import hashlib
root = Path(sys.argv[1])
output = Path(sys.argv[2])
# Exact upstream inputs from the pinned musl revision.
upstream = {'tre.h': 'e734e68decc33b5ee983db12cabcbdd2589c2d16088677228087b0e5dc365cf3', 'tre-mem.c': '4721979ce365a395fd7644335c847a8a97913e87f14348641f7f199b57b93e28', 'regcomp.c': '440c5e74c6b941cc4bb3bd32ce13965dc8c2f54369c915f39dab40fb387983ea', 'regexec.c': '072e8a1092c98830b48e784fb74ce486f7c39e27207f79f1dd161e2c5d86ba77', 'regex.h': '4acf94cf0e0f14b2eb50accac93fee886fcc4f821a9b7bb5347a5d035a027ad3', 'COPYRIGHT': 'b870108ec5e7790e9f9919064f1b9421d62d5f9b0e6c230c6adf7ea2da62e97b'}
for name, digest in upstream.items():
    assert hashlib.sha256((root/name).read_bytes()).hexdigest() == digest, name

# All functions and regex types have translation-unit scope or command names.
pre='''/* nl-only length-aware BRE fallback. See docs/sol-nl.md for provenance,
 * license and the bounded-input changes. Not a shared regex helper.
 * Derived from musl b1efda5b91735e33635376ca11c9b497a1c66e39 src/regex.
 */
#ifndef BNL_REGEX_H
#define BNL_REGEX_H
#include <stddef.h>
#include <wchar.h>
#include <wctype.h>
#define regex_t bnl_regex_t
#define regmatch_t bnl_regmatch_t
#define regoff_t bnl_regoff_t
#define reg_errcode_t bnl_reg_errcode_t
#define regcomp bnl_regcomp
#define regfree bnl_regfree
#define regexec bnl_regnexec
'''
rh=(root/'regex.h').read_text()
for name in re.findall(r'^#define (REG_\w+)',rh,re.M): pre+=f'#undef {name}\n'
start=rh.index('typedef struct re_pattern_buffer')
end=rh.index('int regcomp(')
rh=rh[start:end].replace('struct re_pattern_buffer','struct bnl_pattern_buffer')
pre+='typedef ptrdiff_t bnl_regoff_t;\n'+rh+'''
static int bnl_regcomp(bnl_regex_t *, const char *, int);
static void bnl_regfree(bnl_regex_t *);
static int bnl_regnexec(const bnl_regex_t *, const char *, size_t, size_t, bnl_regmatch_t *, int);
'''
pre += '\n/*\n' + (root/'COPYRIGHT').read_text().split('Authors/contributors include:')[0] + '*/\n'
parts=[]
for file in ['tre.h','tre-mem.c','regcomp.c','regexec.c']:
 s=(root/file).read_text()
 s=re.sub(r'^#include ["<](?:regex.h|tre.h)[">]\n','',s,flags=re.M)
 s=s.replace('#define NDEBUG\n','').replace('#undef  TRE_MBSTATE', '#define TRE_MBSTATE 1')
 s=s.replace('hidden ', 'static ')
 s=s.replace('__tre_mem_', 'bnl_tre_mem_')
 # Keep C-locale bytes, including invalid UTF-8 bytes, distinct and intact.
 if file=='regexec.c':
  begin=s.index('#define GET_NEXT_WCHAR()')
  end=s.index('\n#define IS_WORD_CHAR',begin)
  s=s[:begin]+'''/* next_c == WEOF is the bounded end marker; NUL is ordinary data. */
#define GET_NEXT_WCHAR() do {                                                \\
    prev_c = next_c; pos += pos_add_next;                                    \\
    if ((size_t)pos >= length) {                                            \\
        next_c = WEOF; pos_add_next = 0;                                    \\
    } else {                                                               \\
        size_t available = length - (size_t)pos;                            \\
        if (MB_CUR_MAX == 1) {                                             \\
            next_c = (unsigned char)*str_byte; pos_add_next = 1;            \\
        } else {                                                           \\
            pos_add_next = (regoff_t)mbrtowc(&next_c, str_byte, available, &mbstate);             \\
            if (pos_add_next < 0) { \\
                next_c = TRE_CHAR_MAX + 1 + (unsigned char)*str_byte; \\
                pos_add_next = 1; memset(&mbstate, 0, sizeof mbstate); \\
            } \\
            if (pos_add_next == 0) pos_add_next = 1;                         \\
        }                                                                  \\
        str_byte += pos_add_next;                                          \\
    }                                                                      \\
  } while (0)
''' + s[end:]
  s=s.replace("next_c != L'\\0'",'next_c != (tre_char_t)WEOF')
  s=s.replace("next_c == L'\\0'",'next_c == (tre_char_t)WEOF')
  s=s.replace('if (!next_c) break;', 'if (next_c == (tre_char_t)WEOF) break;')
  s=s.replace('const void *string,', 'const void *string, size_t length,')
  s=s.replace('size_t nmatch, regmatch_t pmatch[restrict], int eflags)',
              'size_t length, size_t nmatch, regmatch_t pmatch[restrict], int eflags)')
  s=s.replace('tnfa, string, tags,', 'tnfa, string, length, tags,')
  # Backreferences must compare all bytes, never stop at embedded NUL; check
  # their remaining length before touching the bounded subject.
  a=s.index('  result = strncmp(')
  b=s.index('\n\n',a)
  s=s[:a]+'''  result = so < 0 || eo < so || (size_t)bt_len > length - (size_t)pos
              ? 1 : memcmp((const char *)string + so,
                           (const char *)string + pos, (size_t)bt_len);'''+s[b:]
  s=s.replace('str_byte += bt_len - 1;\n\t      pos += bt_len - 1;',
              'str_byte = (const char *)string + pos + bt_len;\n\t      pos += bt_len;\n\t      pos_add_next = 0;')
  a=s.index('#define CHECK_ASSERTIONS(')
  b=s.index('\n#define CHECK_CHAR_CLASSES',a)
  s=s[:a]+r'''#define CHECK_ASSERTIONS(assertions) (                                    \
    (((assertions) & ASSERT_AT_BOL) && (pos > 0 || reg_notbol)              \
      && (prev_c != L'\n' || !reg_newline))                               \
    || (((assertions) & ASSERT_AT_EOL)                                    \
      && (next_c != (tre_char_t)WEOF || reg_noteol)                        \
      && (next_c != L'\n' || !reg_newline))                               \
    || (((assertions) & ASSERT_AT_BOW)                                    \
      && (IS_WORD_CHAR(prev_c) || !IS_WORD_CHAR(next_c)))                  \
    || (((assertions) & ASSERT_AT_EOW)                                    \
      && (!IS_WORD_CHAR(prev_c) || IS_WORD_CHAR(next_c)))                  \
    || (((assertions) & ASSERT_AT_WB)                                     \
      && (IS_WORD_CHAR(prev_c) == IS_WORD_CHAR(next_c)))                   \
    || (((assertions) & ASSERT_AT_WB_NEG)                                 \
      && (IS_WORD_CHAR(prev_c) != IS_WORD_CHAR(next_c))))
'''+s[b:]
  # Exhausting one attempted match must not prevent trying later starts.
  s=s.replace("if (next_c == (tre_char_t)WEOF)\n\t\t    {",
              "if (next_c_start == (tre_char_t)WEOF)\n\t\t    {")
  s=s.replace("#define IS_WORD_CHAR(c)\t ((c) == L'_' || tre_isalnum(c))",
              "#define IS_WORD_CHAR(c) ((tre_cint_t)(c) <= TRE_CHAR_MAX && ((c) == L'_' || tre_isalnum(c)))")
  s=s.replace('  int next_c;\n', '  int next_c;\n  tre_char_t prev_c;\n  regoff_t pos_add_next;\n')
  s=s.replace('stack->item.next_c = (_next_c);',
              'stack->item.next_c = (_next_c); stack->item.prev_c = prev_c; stack->item.pos_add_next = pos_add_next;')
  s=s.replace('next_c = stack->item.next_c;',
              'next_c = stack->item.next_c; prev_c = stack->item.prev_c; pos_add_next = stack->item.pos_add_next;')
  s=s.replace('str_byte = str_byte_start;',
              'str_byte = str_byte_start; pos_add_next = str_byte - (const char *)string - pos_start;')
  s=s.replace('str_byte = (const char *)string + pos + bt_len;',
              'tre_char_t last_c = prev_c;\n\t      if (bt_len) last_c = bnl_last_char((const char *)string + so, (size_t)bt_len);\n\t      str_byte = (const char *)string + pos + bt_len;')
  s=s.replace('pos_add_next = 0;\n\t      GET_NEXT_WCHAR();',
              'pos_add_next = 0;\n\t      GET_NEXT_WCHAR();\n\t      prev_c = last_c;')
  # Empty-backreference cycle guards belong to one search path and input
  # position. A visit on a failed branch must not reject a later valid path.
  s=s.replace('int *states_seen = NULL;', 'regoff_t *states_seen = NULL;')
  s=s.replace('states_seen[i] = 0;', 'states_seen[i] = -1;')
  s=s.replace('empty_br_match && states_seen[trans_i->state_id]',
              'empty_br_match && states_seen[trans_i->state_id] == pos')
  s=s.replace('states_seen[trans_i->state_id] = empty_br_match;',
              'states_seen[trans_i->state_id] = empty_br_match ? pos : -1;')
  # Save the guard array after the tags in each stack frame, using the same
  # allocation/error handling. Restore it with the rest of the search state.
  s=s.replace('sizeof(*tags) * tnfa->num_tags);',
              'sizeof(*tags) * (tnfa->num_tags + tnfa->num_states));')
  s=s.replace('BT_STACK_MBSTATE_IN;',
              'for (i = 0; i < tnfa->num_states; i++) stack->item.tags[tnfa->num_tags + i] = states_seen[i]; BT_STACK_MBSTATE_IN;')
  s=s.replace('BT_STACK_MBSTATE_OUT;',
              'for (i = 0; i < tnfa->num_states; i++) states_seen[i] = stack->item.tags[tnfa->num_tags + i]; BT_STACK_MBSTATE_OUT;')
  s='''/* Preserve the character preceding a backreference's end for assertions. */
static wchar_t
bnl_last_char(const char *s, size_t n)
{
  if (MB_CUR_MAX == 1) return (unsigned char)s[n - 1];
  mbstate_t state = {0};
  wchar_t wc = 0;
  for (size_t off = 0; off < n;) {
    size_t width = mbrtowc(&wc, s + off, n - off, &state);
    if (width == (size_t)-1 || width == (size_t)-2) {
      wc = TRE_CHAR_MAX + 1 + (unsigned char)s[off];
      width = 1; memset(&state, 0, sizeof state);
    }
    off += width ? width : 1;
  }
  return wc;
}
''' + s
 if file=='regcomp.c':
  s=s.replace('mbtowc(', 'bnl_pattern_char(')
  a=s.index('static reg_errcode_t parse_bracket_terms(')
  b=s.index('static reg_errcode_t parse_bracket(',a)
  section=s[a:b].replace('len = bnl_pattern_char(&wc, s, -1);',
                        'len = bnl_pattern_char(&wc, s, -1);\n\t\tif (len > 0 && (tre_cint_t)wc > TRE_CHAR_MAX) wc = TRE_CHAR_MAX + 1;')
  s=s[:a]+section+s[b:]
  s='''static int
bnl_pattern_char(wchar_t *wc, const char *s, size_t n)
{
  if (MB_CUR_MAX == 1) {
    *wc = (unsigned char)*s;
    return *s ? 1 : 0;
  }
  mbstate_t state = {0};
  size_t size = mbrtowc(wc, s, n, &state);
  if (size == (size_t)-1 || size == (size_t)-2) {
    *wc = TRE_CHAR_MAX + 1 + (unsigned char)*s;
    return 1;
  }
  return (int)size;
}
''' + s
  # GNU nl's dot excludes NUL, while negated classes can include it.
  s=s.replace('tre_ast_new_literal(ctx->mem, 0, TRE_CHAR_MAX, ctx->position++)',
              'tre_ast_new_literal(ctx->mem, 1, TRE_CHAR_MAX, ctx->position++)')
  s=s.replace("tre_ast_new_literal(ctx->mem, 0, '\\n'-1, ctx->position++)",
              "tre_ast_new_literal(ctx->mem, 1, '\\n'-1, ctx->position++)")
 # Previously declared static functions inherit linkage; mark explicit too.
 s=re.sub(r'\nint\nreg(comp|exec)\(',r'\nstatic int\nreg\1(',s)
 s=s.replace('\nvoid\nregfree(', '\nstatic void\nregfree(')
 parts.append('\n/* Upstream '+file+' */\n'+s)
output.write_text('\n'.join(line.rstrip().replace('      \tgoto error_exit;', '\t      goto error_exit;') for line in (pre+''.join(parts)+'\n#endif /* BNL_REGEX_H */\n').splitlines())+'\n')
