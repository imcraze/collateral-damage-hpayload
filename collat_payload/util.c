#include "util.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>

#define BYTES_PER_LINE 16

void hex_dump(const void* data, size_t size, char* output) {
    const unsigned char* byte_data = (const unsigned char*)data;
    char line[128]; // buffer for one line of output
    size_t offset = 0;

    while (size > 0) {
        int line_len = snprintf(line, sizeof(line), "%08x: ", (unsigned int)offset);
        size_t line_size = size > BYTES_PER_LINE ? BYTES_PER_LINE : size;

        for (size_t i = 0; i < BYTES_PER_LINE; i++) {
            if (i < line_size) {
                line_len += snprintf(line + line_len, sizeof(line) - line_len, "%02x ", byte_data[offset + i]);
            }
            else {
                line_len += snprintf(line + line_len, sizeof(line) - line_len, "   ");
            }
        }

        line_len += snprintf(line + line_len, sizeof(line) - line_len, " |");

        for (size_t i = 0; i < line_size; i++) {
            if (isprint(byte_data[offset + i])) {
                line_len += snprintf(line + line_len, sizeof(line) - line_len, "%c", byte_data[offset + i]);
            }
            else {
                line_len += snprintf(line + line_len, sizeof(line) - line_len, ".");
            }
        }

        snprintf(line + line_len, sizeof(line) - line_len, "|\n");
        strcat(output, line);

        size -= line_size;
        offset += line_size;
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