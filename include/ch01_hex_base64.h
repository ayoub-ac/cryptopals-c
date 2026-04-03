#ifndef CH01_HEX_BASE64_H
#define CH01_HEX_BASE64_H

#include <stddef.h>
#include <stdint.h>

// decode hex string to raw bytes, returns num bytes or -1 on error
int hex_to_bytes(const char *hex_str, uint8_t *out, size_t out_size);

// encode raw bytes to base64 string, returns length or -1 on error
int bytes_to_base64(const uint8_t *data, size_t len, char *out, size_t out_size);

// hex to base64 in one step
int hex_to_base64(const char *hex_str, char *out, size_t out_size);

// decode base64 string to raw bytes
int base64_to_bytes(const char *b64_str, uint8_t *out, size_t out_size);

// read a base64-encoded file (multiline) and decode to raw bytes
int read_base64_file(const char *filename, uint8_t *out, size_t out_size);

#endif
