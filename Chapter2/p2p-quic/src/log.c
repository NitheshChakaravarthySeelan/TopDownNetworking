#include "include/log.h"

/**
 * struct tm fields:

Field	Meaning	Range
tm_sec	seconds	0–60
tm_min	minutes	0–59
tm_hour	hours	0–23
tm_mday	day of month	1–31
tm_mon	month since January	0–11
tm_year	years since 1900	e.g., 125 → 2025
tm_wday	days since Sunday	0–6
tm_yday	days since Jan 1	0–365
tm_isdst	daylight saving flag	-1, 0, or 1
*/
int log_message(const char *msg) {
	time_t raw_time;
	struct tm *time_info;
	char time_str[20];

	time(&raw_time); // Passing in a Null value
	localtime_r(&raw_time, &time_info);

	// Format time
    	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &time_info);

    	// Print with timestamp
    	printf("[%s] %s\n", time_str, msg);

    	return 0;
}
