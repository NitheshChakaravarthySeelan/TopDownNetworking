#include "log.h"
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

// A simple log implementation
void log_message(log_level level, const char *format, ...) {
    // For this project, we'll keep logging simple and print everything to stdout.
    // A more advanced logger might write to files, handle log levels differently, etc.
    
    time_t raw_time;
    struct tm time_info;
    char time_str[20];

    time(&raw_time);
    localtime_r(&raw_time, &time_info);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &time_info);

    const char* level_str;
    switch (level) {
        case LOG_LEVEL_DEBUG: level_str = "DEBUG"; break;
        case LOG_LEVEL_INFO:  level_str = "INFO";  break;
        case LOG_LEVEL_WARN:  level_str = "WARN";  break;
        case LOG_LEVEL_ERROR: level_str = "ERROR"; break;
        default:              level_str = "LOG";   break;
    }

    printf("[%s] [%s] ", time_str, level_str);

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
    fflush(stdout); // Ensure the log message is printed immediately
}