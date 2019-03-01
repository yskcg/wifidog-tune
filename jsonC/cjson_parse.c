#include "./cjson_parse.h"

int cjson_parse_get_type_len(const char *json_input,const char *field,char * type,int * len)
{
    const cJSON *name = NULL;
    int status = 0;

    cJSON *monitor_json = cJSON_Parse(json_input);
   
    if (monitor_json == NULL) {
        status = 1;
		cJSON_Delete(monitor_json);
		return status;
    }

	if (field == NULL || type == NULL ){
        status = 1;
		return status;
	}

    name = cJSON_GetObjectItemCaseSensitive(monitor_json, field);

    *type = name->type & 0xFF;

    if(len){
        if (cJSON_IsString(name) && (name->valuestring != NULL)){
            *len = strlen(name->valuestring);
        }else if  (cJSON_IsNumber(name)){
            *len = sizeof(name->valuedouble);
        }else if (cJSON_IsBool(name)){
            *len = 1;
        }
    }
   
    cJSON_Delete(monitor_json);
    return status;
}

char cjson_parse(const char * json_input,const char *field,void * output)
{
    const cJSON *name = NULL;
    int status = 0;

    cJSON *monitor_json = cJSON_Parse(json_input);
   
    if (monitor_json == NULL) {
        status = 1;
		cJSON_Delete(monitor_json);
		return status;
    }

	if (field == NULL || output == NULL ){
        status = 1;
		return status;
	}

    name = cJSON_GetObjectItemCaseSensitive(monitor_json, field);
    if (cJSON_IsString(name) && (name->valuestring != NULL)){
        strcpy((char *)output,name->valuestring);	
    }else if  (cJSON_IsNumber(name)){
		memcpy((int *)output,&(name->valueint),sizeof(name->valueint));
	}else if (cJSON_IsBool(name)){
		memcpy((char *)output,&(name->valueint),sizeof(char));
	}

    cJSON_Delete(monitor_json);
    return status;
}