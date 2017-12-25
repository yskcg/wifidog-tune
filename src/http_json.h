#ifndef __HTTP_JSON_H
#define __HTTP_JSON_H

#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "util.h"
#include "debug.h"

char *http_get_json_data(const char *res);

#endif  
