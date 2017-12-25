#include "http_json.h"

char *http_get_json_data(const char *res)
{
    char *json_data = NULL;

	if(res == NULL){
		return NULL;
	}
    
	json_data = strstr(res,"\r\n\r\n");

	debug(LOG_DEBUG, "%s %d json data is :%s",__FUNCTION__,__LINE__,json_data+strlen("\r\n\r\n"));
    return json_data +strlen("\r\n\r\n");
}
