#include "util.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>

#define BYTES_PER_LINE 16

void hex_dump(const void* data, size_t size, char* output) {
    const unsigned char* byte = (const unsigned char*)data;
    char* out = output;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        out += sprintf(out, "%08zx  ", i); // Print the address

        // Print the hex bytes
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                out += sprintf(out, "%02x ", byte[i + j]);
            }
            else {
                out += sprintf(out, "   ");
            }
        }

        out += sprintf(out, " ");

        // Print the ASCII representation
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                out += sprintf(out, "%c", isprint(byte[i + j]) ? byte[i + j] : '.');
            }
            else {
                out += sprintf(out, " ");
            }
        }

        out += sprintf(out, "\n");
    }
}

char* get_error_name(DWORD errorCode) {
    LPVOID messageBuffer;
    DWORD formatResult = FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&messageBuffer,
        0,
        NULL
    );

    if (formatResult) {
        return (char*)messageBuffer;
        //LocalFree(messageBuffer);
    }
    else {
        return GetLastError();
    }
}

void sock_log(SOCKET sock, char* msg) {
    send(sock, msg, strlen(msg), 0);
}

char* int64ToBinaryString(UINT64 value) {
    // For 64-bit integers
    int numBits = sizeof(value) * 8;
    char* binaryString = (char*)malloc(numBits + 1); // +1 for null terminator

    if (binaryString == NULL) {
        perror("Unable to allocate memory");
        return NULL;
    }

    binaryString[numBits] = '\0'; // Null-terminate the string

    for (int i = numBits - 1; i >= 0; i--) {
        binaryString[i] = (value & 1) ? '1' : '0';
        value >>= 1;
    }

    return binaryString;
}
