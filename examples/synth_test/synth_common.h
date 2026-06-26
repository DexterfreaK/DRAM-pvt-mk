#pragma once
#include <stdint.h>

#define NUM_BACKENDS  16
#define KEY_MAXLEN     8

#define TYPE_UNKNOWN  (-1)
#define TYPE_PREPARE   0
#define TYPE_REQUEST   1
#define TYPE_ACK       2

/* Expensive functions — real bodies in synth_expensive.c,
 * stubs in synth_stubs.c / synth_rough_stubs.c */
int      classify_type(const char *payload, int len);
uint32_t hash_payload(const char *key, int maxlen, int *out_key_len);
uint16_t fold_csum(uint32_t csum);
