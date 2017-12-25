#ifndef __JSON_PARSE__
#define __JSON_PARSE__
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include "json.h"
#include "json_object.h"
#include "json_object_private.h"
#include "debug.h"

extern int json_parse_get_type_len(const char *json_input,const char *field,char * type,int * len);
extern int json_parse(const char *json_input,const char *field,void * output,int * len);
#endif
