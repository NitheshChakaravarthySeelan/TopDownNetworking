#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>

typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR
} log_level;

void log_message(log_level level, const char *format, ...);

#define log_debug(...) log_message(LOG_LEVEL_DEBUG, __VA_ARGS__)
#define log_info(...) log_message(LOG_LEVEL_INFO, __VA_ARGS__)
#define log_warn(...) log_message(LOG_LEVEL_WARN, __VA_ARGS__)
#define log_error(...) log_message(LOG_LEVEL_ERROR, __VA_ARGS__)

#endif // LOG_H
