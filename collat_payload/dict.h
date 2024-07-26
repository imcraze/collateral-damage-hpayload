#ifndef _DICT_H_
#define _DICT_H_

#include <Windows.h>

#define MAX_GADGET_SIZE 0x8

typedef struct gadget_kv_pair {
    const char* asm;
    CHAR bytes[MAX_GADGET_SIZE];
    SIZE_T size;
} gadget_kv_pair;

typedef struct gadget_t {
    const char* asm;
    UINT64 address;
} gadget_t;

typedef struct dict_entry_s {
    const char* key;
    UINT64 value;
} dict_entry_s;

typedef struct dict_s {
    int len;
    int cap;
    dict_entry_s* entry;
} dict_s, * dict_t;

UINT64 dict_find(dict_t dict, const char* key, int def);
int dict_find_index(dict_t dict, const char* key);
void dict_add(dict_t dict, const char* key, UINT64 value);
dict_t dict_new(void);
void dict_free(dict_t dict);

#endif // _DICT_H_