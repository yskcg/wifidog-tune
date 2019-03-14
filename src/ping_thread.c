/* vim: set sw=4 ts=4 sts=4 et : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id$ */
/** @file ping_thread.c
    @brief Periodically checks in with the central auth server so the auth
    server knows the gateway is still up.  Note that this is NOT how the gateway
    detects that the central server is still up.
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "wifidog_config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "ping_thread.h"
#include "util.h"
#include "centralserver.h"
#include "firewall.h"
#include "gateway.h"
#include "simple_http.h"

static int version = 0;
static void sync_white_black_list(void);

/** Launches a thread that periodically checks in with the wifidog auth server to perform heartbeat function.
@param arg NULL
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_ping(void *arg)
{
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;

    while (1) {
        /* Make sure we check the servers at the very begining */
        debug(LOG_DEBUG, "Running ping()");
		ping();
		sync_white_black_list();

        /* Sleep for config.checkinterval seconds... */
        timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);

        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
    }
}

/** @internal
 * This function does the actual request.
 */
static void ping(void *eloop_ctx,void *timeout_ctx )
{
    char request[MAX_BUF];
    FILE *fh;
    int sockfd;
    unsigned long int sys_uptime = 0;
    unsigned int sys_memfree = 0;
    float sys_load = 0;
	int  code = 0;
	char t[64] = {'\0'};
	char k[64] = {'\0'};
	char ret = 0;
	char is_auth = 0;
	char *json_data = NULL;
    t_auth_serv *auth_server = NULL;
	s_config *config = config_get_config();
    auth_server = get_auth_server();
    static int authdown = 0;

    debug(LOG_DEBUG, "Entering ping()");
    memset(request, 0, sizeof(request));
	/*get the t and k value*/
	build_t_key(t,k);

    /*
     * The ping thread does not really try to see if the auth server is actually
     * working. Merely that there is a web server listening at the port. And that
     * is done by connect_auth_server() internally.
     */
    sockfd = connect_auth_server();
    if (sockfd == -1) {
        /*
         * No auth servers for me to talk to
         */
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
        }
        return;
    }

    /*
     * Populate uptime, memfree and load
     */
    if ((fh = fopen("/proc/uptime", "r"))) {
        if (fscanf(fh, "%lu", &sys_uptime) != 1)
            debug(LOG_CRIT, "Failed to read uptime");

        fclose(fh);
    }
    if ((fh = fopen("/proc/meminfo", "r"))) {
        while (!feof(fh)) {
            if (fscanf(fh, "MemFree: %u", &sys_memfree) == 0) {
                /* Not on this line */
                while (!feof(fh) && fgetc(fh) != '\n') ;
            } else {
                /* Found it */
                break;
            }
        }
        fclose(fh);
    }
    if ((fh = fopen("/proc/loadavg", "r"))) {
        if (fscanf(fh, "%f", &sys_load) != 1)
            debug(LOG_CRIT, "Failed to read loadavg");

        fclose(fh);
    }

    /*
     * Prep & send request
     */
    snprintf(request, sizeof(request) - 1,
             "GET /auth/%sgw_id=%s&sys_uptime=%lu&sys_memfree=%u&sys_load=%.2f&wifidog_uptime=%lu HTTP/1.0\r\n"
			 "T: %s\r\n"
			 "K: %s\r\n"
			 "User-Agent: MoreAuth %s\r\n"
             "Host: %s\r\n"
             "\r\n",
             auth_server->authserv_ping_script_path_fragment,config->gw_id,sys_uptime,sys_memfree,sys_load,(long unsigned int)((long unsigned int)time(NULL) - (long unsigned int)started_time),\
			 t,k,
             VERSION, auth_server->authserv_hostname);


    char *res;
#ifdef USE_CYASSL
    if (auth_server->authserv_use_ssl) {
        res = https_get(sockfd, request, auth_server->authserv_hostname);
    } else {
        res = http_get(sockfd, request);
    }
#endif
#ifndef USE_CYASSL
    res = http_get(sockfd, request);
#endif
    if (NULL == res) {
        debug(LOG_ERR, "There was a problem pinging the auth server!");
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
        }
    } else {
		json_data = http_get_json_data(res);
		json_parse(json_data,"code",(char *)&code);
		
		if (code != 0){
			free(res);
			if (!authdown) {
				authdown = fw_set_authdown();
			}
			return ;
		}

		json_parse(json_data,"result",&ret);
		debug(LOG_ERR, "%s %d ret:%d !\n",__FUNCTION__,__LINE__,ret);
		if (ret){
			json_parse(json_data,"is_auth",&is_auth);
			debug(LOG_ERR, "%s %d is_auth:%d !\n",__FUNCTION__,__LINE__,is_auth);
			if(is_auth){
				if (authdown) {
					authdown = fw_set_authup();
				}
			}else{
				if (!authdown) {
					authdown = fw_set_authdown();
				}
			}

			config->auth_status = is_auth ;
			free(res);
		}
	}

    return;
}


int is_mac(char *mac_addr)
{
	if(mac_addr == NULL){
		return 0;
	}

	if(strlen(mac_addr) <17){
		return 0;
	}else{
		return 1;
	}

}

static void apply_white_black_list(char * mac,char * key)
{
	/*Flash the iptables white black list*/
	char white_black_flag = -1; //0:white;1:black;

	if(is_mac(mac)){
		if(strcmp(key,"blacklist") ==0){
			white_black_flag = 1;
		}else if(strcmp(key,"whitelist") ==0 ){
			white_black_flag = 0;
		}

		if(white_black_flag == 0){
			iptables_fw_set_white_list((const char *) mac);
		}else if(white_black_flag == 1){
			iptables_fw_set_black_list((const char *) mac);
		}
	}
}

static void sync_white_black_list(void)
{
	char request[MAX_BUF];
    int sockfd;
	int len = 0;
	int  code = 0;
	int server_version;
	char t[64] = {'\0'};
	char k[64] = {'\0'};
	char *json_data = NULL;
    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();

    debug(LOG_DEBUG, "Entering sync white black list");
    memset(request, 0, sizeof(request));

	 /*
     * The sync_white_black function does not really try to see if the auth server is actually
     * working. Merely that there is a web server listening at the port. And that
     * is done by connect_auth_server() internally.
     */
    sockfd = connect_auth_server();
    if (sockfd == -1) {
        return;
    }

	/*
     * Prep & send request
     */
	build_t_key(t,k);
    snprintf(request, sizeof(request) - 1,
             "GET /auth/baw?gw_id=%s&v=%u HTTP/1.0\r\n"
			 "T: %s\r\n"
			 "K: %s\r\n"
             "User-Agent: MoreAuth %s\r\n"
             "Host: %s\r\n"
             "\r\n",
             config_get_config()->gw_id,
			 version,t,k,
             VERSION, auth_server->authserv_hostname);

    char *res;
#ifdef USE_CYASSL
    if (auth_server->authserv_use_ssl) {
        res = https_get(sockfd, request, auth_server->authserv_hostname);
    } else {
        res = http_get(sockfd, request);
    }
#endif
#ifndef USE_CYASSL
    res = http_get(sockfd, request);
#endif
    if (NULL == res) {
		return ;
    }else{
		json_data = http_get_json_data(res);
		json_parse(json_data,"code",(char *)&code);
		
		if (code != 0){
			free(res);
			return ;
		}

		json_parse(json_data,"version",(int *)&server_version);
		
		if( (server_version != version) && server_version != 0 ){
			char type = 0;
			int i = 0;
			
			version = server_version;
			json_parse_get_type_len(json_data,"blacklist",&type,&len);

			if(type == cJSON_Array && len >=0){
				iptables_fw_clear_black_list();
				
				if(len >0){
					char mac_list[len][32];

					memset(mac_list,0,sizeof(mac_list));
					json_parse(json_data,"blacklist",mac_list);
					
					for(i=0;i<len;i++){
						apply_white_black_list(mac_list[i],"blacklist");
					}
				}
			}
			
			len = 0;
			type =0;
			i = 0;

			json_parse_get_type_len(json_data,"whitelist",&type,&len);

			if(type == json_type_array && len >=0){
				iptables_fw_clear_white_list();
				
				if(len >0){
					char mac_list[len][32];

					memset(mac_list,0,sizeof(mac_list));
					json_parse(json_data,"whitelist",mac_list);
					
					for(i=0;i<len;i++){
						apply_white_black_list(mac_list[i],"whitelist");
					}
				}
			}
		}

		free(res);
	}
    return;
}
