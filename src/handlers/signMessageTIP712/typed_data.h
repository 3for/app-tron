#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// TypeDesc masks
#define TYPE_MASK     (0xF)
#define ARRAY_MASK    (1 << 7)
#define TYPESIZE_MASK (1 << 6)
#define TYPENAME_ENUM (0xF)

typedef enum { ARRAY_DYNAMIC = 0, ARRAY_FIXED_SIZE, ARRAY_TYPES_COUNT } e_array_type;

typedef enum {
    // contract defined struct
    TYPE_CUSTOM = 0,
    // native types
    TYPE_SOL_INT,
    TYPE_SOL_UINT,
    TYPE_SOL_ADDRESS,
    TYPE_SOL_BOOL,
    TYPE_SOL_STRING,
    TYPE_SOL_BYTES_FIX,
    TYPE_SOL_BYTES_DYN,
    TYPE_SOL_TRCTOKEN,
    TYPES_COUNT
} e_type;

typedef struct {
    e_array_type type;
    uint8_t size;
} s_struct_712_field_array_level;

typedef struct struct_712_field {
    struct struct_712_field *next;
    bool type_is_array;
    bool type_has_size;
    e_type type;
    char *type_name;
    uint8_t type_size;
    uint8_t array_level_count;
    s_struct_712_field_array_level *array_levels;
    char *key_name;
} s_struct_712_field;

typedef struct struct_712 {
    struct struct_712 *next;
    char *name;
    s_struct_712_field *fields;
} s_struct_712;

const void *get_array_in_mem(const void *ptr, uint8_t *array_size);
const char *get_string_in_mem(const uint8_t *ptr, uint8_t *string_length);
bool struct_field_is_array(const void *ptr);
bool struct_field_has_typesize(const void *ptr);
e_type struct_field_type(const void *ptr);
uint8_t get_struct_field_typesize(const void *ptr);
const char *get_struct_field_custom_typename(const void *ptr, uint8_t *length);
const char *get_struct_field_typename(const void *ptr, uint8_t *length);
e_array_type struct_field_array_depth(const void *ptr, uint8_t *array_size);
const void *get_next_struct_field_array_lvl(const void *ptr);
const void *get_struct_field_array_lvls_array(const void *ptr, uint8_t *length);
const char *get_struct_field_keyname(const void *ptr, uint8_t *length);
const void *get_next_struct_field(const void *ptr);
const char *get_struct_name(const void *ptr, uint8_t *length);
const void *get_struct_fields_array(const void *ptr, uint8_t *length);
const void *get_next_struct(const void *ptr);
const void *get_structs_array(uint8_t *length);
const s_struct_712 *get_struct_list(void);
const s_struct_712 *get_structn(const char *name_ptr, uint8_t name_length);
bool set_struct_name(uint8_t length, const uint8_t *name);
bool set_struct_field(uint8_t length, const uint8_t *data);
bool typed_data_init(void);
void typed_data_deinit(void);
