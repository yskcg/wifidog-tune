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

#include "../config.h"
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

static void ping(void);
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
static void
ping(void)
{
    char request[MAX_BUF];
    FILE *fh;
    int sockfd;
    unsigned long int sys_uptime = 0;
    unsigned int sys_memfree = 0;
    float sys_load = 0;
    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();
    static int authdown = 0;

    debug(LOG_DEBUG, "Entering ping()");
    memset(request, 0, sizeof(request));

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
             "GET %s%sgw_id=%s&sys_uptime=%lu&sys_memfree=%u&sys_load=%.2f&wifidog_uptime=%lu HTTP/1.0\r\n"
             "User-Agent: WiFiDog %s\r\n"
             "Host: %s\r\n"
             "\r\n",
             auth_server->authserv_path,
             auth_server->authserv_ping_script_path_fragment,
             config_get_config()->gw_id,
             sys_uptime,
             sys_memfree,
             sys_load,
             (long unsigned int)((long unsigned int)time(NULL) - (long unsigned int)started_time),
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
    } else if (strstr(res, "Pong") == 0) {
        debug(LOG_WARNING, "Auth server did NOT say Pong!");
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
        }
        free(res);
    } else {
        debug(LOG_DEBUG, "Auth Server Says: Pong");
        if (authdown) {
            fw_set_authup();
            authdown = 0;
        }
        free(res);
    }
    return;
}


static int is_mac(char *mac_addr)
{
	unsigned char uc[6];

	if(mac_addr == NULL){
		return 0;
	}

	printf("len of mac:%d\n",mac_addr);
	if(strlen(mac_addr) <17){
		return 0;
	}else{
		return 1;
	}

}

static void apply_white_black_list(char *buf,int version)
{
	char *p_key_value = NULL;
	char *p_key_value_end = NULL;
	char *p_mac = NULL;
	char *p_mac_end = NULL;
	char *p_value = NULL;

	char string_version[64] = {'\0'};
	char key[32] = {'\0'};
	char value[640] = {'\0'};
	char mac[20] = {'\0'};
	int server_version;
	char white_black_flag = -1; //0:white;1:black;


	if (strlen(buf) <=1 || buf[0] ==10){ //排除文件换行无内容情况
		return;
	}else{
		p_key_value = strstr(buf,"=");
		p_key_value_end = strstr(buf,"\n");
		//printf("%s--%d\n",p_key_value+1,p_key_value_end-p_key_value);
		strncpy(string_version,p_key_value+1,p_key_value_end-p_key_value -1);
		server_version = atoi(string_version);
		//printf("version=%d\n",server_version);

		if(version == server_version || server_version == 0 || version == 0 ){
			return;
		}else{
			while(strlen(p_key_value_end) > 0){
				memset(key,'\0',sizeof(key));
				memset(value ,'\0',sizeof(value));
				white_black_flag = -1;
				p_key_value_end = p_key_value_end +1;
				p_key_value = strstr(p_key_value_end,"=");

				if(p_key_value == NULL){
					break;
				}

				p_key_value = p_key_value +1;
				strncpy (key, p_key_value_end, p_key_value - p_key_value_end -1);
				p_key_value_end = strstr(p_key_value,"\n");

				if(p_key_value_end == NULL){
					break;
				}
				strncpy(value,p_key_value,p_key_value_end-p_key_value);
				//printf("%s=%s value_len=%d\n",key,value,strlen(value));

				/*Flash the iptables white black list*/
				if(strcmp(key,"blacklist") ==0){
					iptables_fw_clear_black_list();
					printf("iptables -t nat -F blacklist\n");
					white_black_flag = 1;
				}else if(strcmp(key,"whitelist") ==0 ){
					iptables_fw_clear_white_list();
					printf("iptables -t nat -F whitelist\n");
					white_black_flag = 0;
				}
				/*parse the value*/
				p_value = value;
				while(strlen(p_value) >0){
					p_mac = strstr(p_value,",");

					if(p_mac == NULL){
						if(ismac(p_value)){
							printf("Add %s to %s\n",p_value,key);
							if(white_black_flag == 0){
								iptables_fw_set_white_list((const char *) p_value);
							}else if(white_black_flag == 1){
								iptables_fw_set_black_list((const char *) p_value);
							}
						}
						break;
					}else{
						memset(mac,'\0',sizeof(mac));
						p_mac = p_mac +1;
						//printf("p_mac:%s\n",p_mac);
						strncpy(mac,p_value,p_mac-p_value-1);
						p_value = p_mac;
						//printf("p_value:%s\n",p_value);
						if(ismac(p_value)){
							printf("Add %s to %s\n",mac,key);
							if(white_black_flag == 0){
								iptables_fw_set_white_list((const char *) mac);
							}else if(white_black_flag == 1){
								iptables_fw_set_black_list((const char *) mac);
							}
						}
					}

				}
			}
		}
	}
}

static void sync_white_black_list(void)
{
	char request[MAX_BUF];
    FILE *fh;
    int sockfd;
	int len = 0;
    unsigned long int sys_uptime = 0;
    unsigned int sys_memfree = 0;
    float sys_load = 0;
    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();
    static int version = 0;
	char *p_value = NULL;

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
    snprintf(request, sizeof(request) - 1,
             "GET %sbaw?gw_id=%s&v=%u HTTP/1.0\r\n"
             "User-Agent: WiFiDog %s\r\n"
             "Host: %s\r\n"
             "\r\n",
             auth_server->authserv_path,
             config_get_config()->gw_id,
			 version,
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
		p_value = strstr(res,"version=");
		
		if(p_value == NULL){
			free(res);
			return ;
		}

		debug(LOG_DEBUG, "before len:%d\nvalue:%s---",len,p_value);
		//len = p_value_end - p_value;
		//memcpy(&p_value_end[len],"\n",1);
		apply_white_black_list(p_value,version);
		free(res);
	}
    return;


}
