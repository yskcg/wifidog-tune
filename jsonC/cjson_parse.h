#ifndef __JSON_PARSE__
#define __JSON_PARSE__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "./cJSON.h"

extern int ccjson_parse_get_type_len(const char *json_input, const char *field, char * type, int * len);
extern char  ccjson_parse(const char * monitor,const char *field,void * output); 

#endif

