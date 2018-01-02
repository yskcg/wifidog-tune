#include "json_parse.h"

int json_parse_get_type_len(const char *json_input,const char *field,char * type,int * len)
{
	struct json_object *new_obj;
	struct json_object *o = NULL;
	static char value[256] = {'\0'};
	
	if (field == NULL){
		return -1;
	}
	
	memset(value,0,sizeof(value));
	new_obj = json_tokener_parse(json_input);
	
	if (!new_obj)
		return -1; // oops, we failed.

	if (json_object_object_get_ex(new_obj, field,&o) == FALSE){
		return -1;
	}
	

	if (type){
		*type = json_object_get_type(o);
	}

	if (len){
		if(json_object_is_type(o, json_type_string)){
			*len = json_object_get_string_len(o);
		}else if(json_object_is_type(o, json_type_int)){
			*len = sizeof(int);
		}else if(json_object_is_type(o,json_type_boolean)){
			*len = sizeof(char);
		}else if(json_object_is_type(o,json_type_array)){
			*len = json_object_array_length(o);
		}
	}

	json_object_put(new_obj);
	
	return 0;

}

int json_parse(const char *json_input,const char *field,void * output)
{
	struct json_object *new_obj;
	struct json_object *o = NULL;
	static char value[256] = {'\0'};
	
	if (field == NULL){
		return -1;
	}
	
	memset(value,0,sizeof(value));
	new_obj = json_tokener_parse(json_input);
	
	if (!new_obj)
		return 1; // oops, we failed.

	if (json_object_object_get_ex(new_obj, field,&o) == FALSE){
		return 1;
	}
	
	if(json_object_is_type(o, json_type_string)){
		if(json_object_get_string_len(o) > 0){
			memcpy(output,json_object_get_string(o),json_object_get_string_len(o));
			memcpy(output + json_object_get_string_len(o),"\0",1);	
		}
	}else if(json_object_is_type(o, json_type_int)){
		int result = json_object_get_int(o);
		memcpy(output,&result,sizeof(result));
	}else if(json_object_is_type(o,json_type_boolean)){
		char result = json_object_get_boolean(o);
		memcpy(output,&result,sizeof(char));
	}else if(json_object_is_type(o,json_type_array)){
		int i ;
		struct array_list *c_array = NULL;
		
		c_array = json_object_get_array(o);
		
		if(output){
			for(i=0;i<c_array->length;i++){
				struct json_object *val;
				val = json_object_array_get_idx(o, i);
				memcpy((output+(i*32)),val->o.c_string.str,val->o.c_string.len);
			}

		}
	}

	json_object_put(new_obj);
	
	return 0;
}
