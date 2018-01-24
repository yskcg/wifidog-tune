/* vim: set et sw=4 sts=4 ts=4 : */
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

/**
  @file util.c
  @brief Misc utility functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2006 Benoit Grégoire <bock@step.polymtl.ca>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <net/if.h>

#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>

#include <string.h>
#include <netdb.h>

#include "common.h"
#include "safe.h"
#include "util.h"
#include "debug.h"
#include "pstring.h"

#include "config.h"

#include "simple_http.h"
#include "conf.h"
#include "centralserver.h"
#include "http_json.h"
#include "json_parse.h"

#define LOCK_GHBN() do { \
	debug(LOG_DEBUG, "Locking wd_gethostbyname()"); \
	pthread_mutex_lock(&ghbn_mutex); \
	debug(LOG_DEBUG, "wd_gethostbyname() locked"); \
} while (0)

#define UNLOCK_GHBN() do { \
	debug(LOG_DEBUG, "Unlocking wd_gethostbyname()"); \
	pthread_mutex_unlock(&ghbn_mutex); \
	debug(LOG_DEBUG, "wd_gethostbyname() unlocked"); \
} while (0)

#ifdef __ANDROID__
#define WD_SHELL_PATH "/system/bin/sh"
#else
#define WD_SHELL_PATH "/bin/sh"
#endif

/** @brief FD for icmp raw socket */
static int icmp_fd;

/** @brief Mutex to protect gethostbyname since not reentrant */
static pthread_mutex_t ghbn_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned short rand16(void);

/** Fork a child and execute a shell command, the parent
 * process waits for the child to return and returns the child's exit()
 * value.
 * @return Return code of the command
 */
int
execute(const char *cmd_line, int quiet)
{
    int pid, status, rc;

    const char *new_argv[4];
    new_argv[0] = WD_SHELL_PATH;
    new_argv[1] = "-c";
    new_argv[2] = cmd_line;
    new_argv[3] = NULL;

    pid = safe_fork();
    if (pid == 0) {             /* for the child process:         */
        /* We don't want to see any errors if quiet flag is on */
        if (quiet)
            close(2);
        if (execvp(WD_SHELL_PATH, (char *const *)new_argv) == -1) { /* execute the command  */
            debug(LOG_ERR, "execvp(): %s", strerror(errno));
        } else {
            debug(LOG_ERR, "execvp() failed");
        }
        exit(1);
    }

    /* for the parent:      */
    //debug(LOG_DEBUG, "Waiting for PID %d to exit", pid);
    rc = waitpid(pid, &status, 0);
    //debug(LOG_DEBUG, "Process PID %d exited", rc);
    
    if (-1 == rc) {
        debug(LOG_ERR, "waitpid() failed (%s)", strerror(errno));
        return 1; /* waitpid failed. */
    }

    if (WIFEXITED(status)) {
        return (WEXITSTATUS(status));
    } else {
        /* If we get here, child did not exit cleanly. Will return non-zero exit code to caller*/
        debug(LOG_DEBUG, "Child may have been killed.");
        return 1;
    }
}

struct in_addr *
wd_gethostbyname(const char *name)
{
    struct hostent *he = NULL;
    struct in_addr *addr = NULL;
    struct in_addr *in_addr_temp = NULL;

    /* XXX Calling function is reponsible for free() */

    addr = safe_malloc(sizeof(*addr));

    LOCK_GHBN();

    he = gethostbyname(name);

    if (he == NULL) {
        free(addr);
        UNLOCK_GHBN();
        return NULL;
    }

    in_addr_temp = (struct in_addr *)he->h_addr_list[0];
    addr->s_addr = in_addr_temp->s_addr;

    UNLOCK_GHBN();

    return addr;
}

char *
get_iface_ip(const char *ifname)
{
    struct ifreq if_data;
    struct in_addr in;
    char *ip_str;
    int sockd;
    u_int32_t ip;

    /* Create a socket */
    if ((sockd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        debug(LOG_ERR, "socket(): %s", strerror(errno));
        return NULL;
    }

     /* I want to get an IPv4 IP address */
    if_data.ifr_addr.sa_family = AF_INET;
    /* Get IP of internal interface */
    strncpy(if_data.ifr_name, ifname, 15);
    if_data.ifr_name[15] = '\0';

    /* Get the IP address */
    if (ioctl(sockd, SIOCGIFADDR, &if_data) < 0) {
        debug(LOG_ERR, "ioctl(): SIOCGIFADDR %s", strerror(errno));
        close(sockd);
        return NULL;
    }
    memcpy((void *)&ip, (void *)&if_data.ifr_addr.sa_data + 2, 4);
    in.s_addr = ip;

    ip_str = inet_ntoa(in);
    close(sockd);
    return safe_strdup(ip_str);
}

char *
get_iface_mac(const char *ifname)
{
    int r, s;
    struct ifreq ifr;
    char *hwaddr, mac[18];
	s_config *config = config_get_config();

    strncpy(ifr.ifr_name, ifname, 15);
    ifr.ifr_name[15] = '\0';

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == s) {
        debug(LOG_ERR, "get_iface_mac socket: %s", strerror(errno));
        return NULL;
    }

    r = ioctl(s, SIOCGIFHWADDR, &ifr);
    if (r == -1) {
        debug(LOG_ERR, "get_iface_mac ioctl(SIOCGIFHWADDR): %s %s ", strerror(errno),ifname);
        close(s);
        return NULL;
    }

	//debug(LOG_DEBUG, "%s %d size:%d device_sn:%s",__FUNCTION__,__LINE__,size,buf);

    hwaddr = ifr.ifr_hwaddr.sa_data;
    close(s);
    snprintf(config->device_base_mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             hwaddr[0] & 0xFF,
             hwaddr[1] & 0xFF, hwaddr[2] & 0xFF, hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);
	return NULL;
}

char *
get_ext_iface(void)
{
    FILE *input;
    char *device, *gw;
    int i = 1;
    int keep_detecting = 1;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;
    device = (char *)safe_malloc(16);   /* XXX Why 16? */
    gw = (char *)safe_malloc(16);
    debug(LOG_DEBUG, "get_ext_iface(): Autodectecting the external interface from routing table");
    while (keep_detecting) {
        input = fopen("/proc/net/route", "r");
        if (NULL == input) {
            debug(LOG_ERR, "Could not open /proc/net/route (%s).", strerror(errno));
            free(gw);
            free(device);
            return NULL;
        }
        while (!feof(input)) {
            /* XXX scanf(3) is unsafe, risks overrun */
            if ((fscanf(input, "%15s %*s %15s %*s %*s %*s %*s %*s %*s %*s %*s\n", device, gw) == 2)
                && strcmp(gw, "00000000") == 0) {
                free(gw);
                debug(LOG_INFO, "get_ext_iface(): Detected %s as the default interface after trying %d", device, i);
                fclose(input);
                return device;
            }
        }
        fclose(input);
        debug(LOG_ERR,
              "get_ext_iface(): Failed to detect the external interface after try %d (maybe the interface is not up yet?).  Retry limit: %d",
              i, NUM_EXT_INTERFACE_DETECT_RETRY);
        /* Sleep for EXT_INTERFACE_DETECT_RETRY_INTERVAL seconds */
        timeout.tv_sec = time(NULL) + EXT_INTERFACE_DETECT_RETRY_INTERVAL;
        timeout.tv_nsec = 0;
        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);
        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);   /* XXX need to possibly add this thread to termination_handler */
        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
        //for (i=1; i<=NUM_EXT_INTERFACE_DETECT_RETRY; i++) {
        if (NUM_EXT_INTERFACE_DETECT_RETRY != 0 && i > NUM_EXT_INTERFACE_DETECT_RETRY) {
            keep_detecting = 0;
        }
        i++;
    }
    debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after %d tries, aborting", i);
    exit(1);                    /* XXX Should this be termination handler? */
    free(device);
    free(gw);
    return NULL;
}

/** Initialize the ICMP socket
 * @return A boolean of the success
 */
int
init_icmp_socket(void)
{
    int flags, oneopt = 1, zeroopt = 0;

    debug(LOG_INFO, "Creating ICMP socket");
    if ((icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1 ||
        (flags = fcntl(icmp_fd, F_GETFL, 0)) == -1 ||
        fcntl(icmp_fd, F_SETFL, flags | O_NONBLOCK) == -1 ||
        setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) ||
        setsockopt(icmp_fd, SOL_SOCKET, SO_DONTROUTE, &zeroopt, sizeof(zeroopt)) == -1) {
        debug(LOG_ERR, "Cannot create ICMP raw socket.");
        return 0;
    }
    return 1;
}

/** Close the ICMP socket. */
void
close_icmp_socket(void)
{
    debug(LOG_INFO, "Closing ICMP socket");
    close(icmp_fd);
}

/**
 * Ping an IP.
 * @param IP/host as string, will be sent to gethostbyname
 */
void
icmp_ping(const char *host)
{
    struct sockaddr_in saddr;
    struct {
        struct ip ip;
        struct icmp icmp;
    } packet;
    unsigned int i, j;
    int opt = 2000;
    unsigned short id = rand16();

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    inet_aton(host, &saddr.sin_addr);
#if defined(HAVE_SOCKADDR_SA_LEN)
    saddr.sin_len = sizeof(struct sockaddr_in);
#endif

    memset(&packet.icmp, 0, sizeof(packet.icmp));
    packet.icmp.icmp_type = ICMP_ECHO;
    packet.icmp.icmp_id = id;

    for (j = 0, i = 0; i < sizeof(struct icmp) / 2; i++)
        j += ((unsigned short *)&packet.icmp)[i];

    while (j >> 16)
        j = (j & 0xffff) + (j >> 16);

    packet.icmp.icmp_cksum = (j == 0xffff) ? j : ~j;

    if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
        debug(LOG_ERR, "setsockopt(): %s", strerror(errno));

    if (sendto(icmp_fd, (char *)&packet.icmp, sizeof(struct icmp), 0,
               (const struct sockaddr *)&saddr, sizeof(saddr)) == -1)
        debug(LOG_ERR, "sendto(): %s", strerror(errno));

    opt = 1;
    if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
        debug(LOG_ERR, "setsockopt(): %s", strerror(errno));

    return;
}

/** Get a 16-bit unsigned random number.
 * @return unsigned short a random number
 */
static unsigned short
rand16(void)
{
    static int been_seeded = 0;

    if (!been_seeded) {
        unsigned int seed = 0;
        struct timeval now;

        /* not a very good seed but what the heck, it needs to be quickly acquired */
        gettimeofday(&now, NULL);
        seed = now.tv_sec ^ now.tv_usec ^ (getpid() << 16);

        srand(seed);
        been_seeded = 1;
    }

    /* Some rand() implementations have less randomness in low bits
     * than in high bits, so we only pay attention to the high ones.
     * But most implementations don't touch the high bit, so we
     * ignore that one. */
    return ((unsigned short)(rand() >> 15));
}

/*
 * Save pid of this wifidog in pid file
 * @param 'pf' as string, it is the pid file absolutely path
 */
void
save_pid_file(const char *pf)
{
    if (pf) {
        FILE *f = fopen(pf, "w");
        if (f) {
            fprintf(f, "%d\n", getpid());

            int ret = fclose(f);
            if (ret == EOF) /* check the return value of fclose */
                debug(LOG_ERR, "fclose() on file %s was failed (%s)", pf, strerror(errno));
        } else /* fopen return NULL, open file failed */
            debug(LOG_ERR, "fopen() on flie %s was failed (%s)", pf, strerror(errno));
    }

    return;
}

/*
 * When the device power on,get the gw_id from the server
 * API:/register
 *
*/

static unsigned char get_device_gw_id_request()
{
    char request[MAX_BUF];
    int sockfd;
	char *json_data = NULL;
    char t[64] = {'\0'};
	char k[64] = {'\0'};
	int  code = 0; 

	t_auth_serv *auth_server = NULL;

	/*get the t and k value*/
	build_t_key(t,k);
	s_config *config = config_get_config();
    auth_server = get_auth_server();
	
    debug(LOG_DEBUG, "Entering get get_device_gw_id()");
    memset(request, 0, sizeof(request));

    sockfd = connect_auth_server();
    if (sockfd == -1) {
        return 1;
    }

    /*
     * Prep & send request
     */
    snprintf(request, sizeof(request) - 1,
             "GET /auth/register?mac=%s HTTP/1.0\r\n"
			 "T: %s\r\n"
			 "K: %s\r\n"
             "User-Agent: MoreAuth %s\r\n"
             "Host: %s\r\n"
             "\r\n",
			 config->device_base_mac,t,k,
             VERSION, 
			 auth_server->authserv_hostname
			);
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
       return 1;
    } else {
		json_data = http_get_json_data(res);
		json_parse(json_data,"code",(char*)&code);
		
		if (code != 0){
			free(res);
			return 1 ;
		}else{
			/*generate the gw_id*/
			json_parse(json_data,"gw_id",config->gw_id);
			json_parse(json_data,"is_auth",&config->auth_status);
			json_parse(json_data,"type",&config->auth_type.auth_type);
			if(config->auth_type.auth_type ==1 ){
				json_parse(json_data,"fixed",&config->auth_type.auth_type);
			}else if(config->auth_type.auth_type ==2){
				json_parse(json_data,"leave",&config->auth_type.auth_type);
			}

			if(config->gw_id && strlen(config->gw_id) >0 ){
				free(res);
				return 0;
			}
		}

		free(res);
		return 1;
    }

}

unsigned char get_device_gw_id(void)
{
	while(get_device_gw_id_request()){
		debug(LOG_DEBUG, "%s %d get the gw_id error wait for five seconds and try again!!!\n",__FUNCTION__,__LINE__);
		sleep(5);
	}
	
	return 0;
}

unsigned char get_auth_info(void)
{
	 char request[MAX_BUF];
    int sockfd;
	char *json_data = NULL;
    char t[64] = {'\0'};
	char k[64] = {'\0'};
	int  code = 0;

	t_auth_serv *auth_server = NULL;

	/*get the t and k value*/
	build_t_key(t,k);
	s_config *config = config_get_config();
    auth_server = get_auth_server();

    debug(LOG_DEBUG, "Entering get get_device_gw_id()");
    memset(request, 0, sizeof(request));

    sockfd = connect_auth_server();
    if (sockfd == -1) {
        return 1;
    }

    /*
     * Prep & send request
     */
   snprintf(request, sizeof(request) - 1,
             "GET /auth/config?gw_id=%s HTTP/1.0\r\n"
			 "T: %s\r\n"
			 "K: %s\r\n"
             "User-Agent: MoreAuth %s\r\n"
             "Host: %s\r\n"
             "\r\n",
             config_get_config()->gw_id,t,k,
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
       return 1;
    } else {
		json_data = http_get_json_data(res);
		json_parse(json_data,"code",(char*)&code);

		if (code != 0){
			free(res);
			return 1 ;
		}else{
			/*get auth info*/
			json_parse(json_data,"type",&config->auth_type.auth_type);
			if(config->auth_type.auth_type ==1 ){
				json_parse(json_data,"fixed",&config->auth_type.expect_time);
			}else if(config->auth_type.auth_type ==2){
				json_parse(json_data,"leave",&config->auth_type.expect_time);
			}

			free(res);
			return 0;
		}

		free(res);
		return 1;
    }


}

/**
 * compute the value of a file
 * @param  file_path
 * @param  md5_str
 * @return 0: ok, -1: fail
 */
int Compute_file_md5(const char *file_path, char *md5_str)
{
	int i;
	int fd;
	int ret;
	unsigned char data[READ_DATA_SIZE];
	unsigned char md5_value[MD5_SIZE];
	MD5_CTX md5;

	fd = open(file_path, O_RDONLY);
	if (-1 == fd)
	{
		perror("open");
		return -1;
	}

	// init md5
	MD5Init(&md5);

	while (1)
	{
		ret = read(fd, data, READ_DATA_SIZE);
		if (-1 == ret)
		{
			perror("read");
			return -1;
		}

		MD5Update(&md5, data, ret);

		if (0 == ret || ret < READ_DATA_SIZE)
		{
			break;
		}
	}

	close(fd);

	MD5Final(&md5, md5_value);

	// convert md5 value to md5 string
	for(i = 0; i < MD5_SIZE; i++)
	{
		snprintf(md5_str + i*2, 2+1, "%02x", md5_value[i]);
	}

	return 0;
}

/**
 * compute the value of a string
 * @param  dest_str
 * @param  dest_len
 * @param  md5_str
 */
int Compute_string_md5(unsigned char *dest_str, unsigned int dest_len, char *md5_str)
{
	int i;
	unsigned char md5_value[MD5_SIZE];
	MD5_CTX md5;

	// init md5
	MD5Init(&md5);

	MD5Update(&md5, dest_str, dest_len);

	MD5Final(&md5, md5_value);

	// convert md5 value to md5 string
	for(i = 0; i < MD5_SIZE; i++)
	{
		snprintf(md5_str + i*2, 2+1, "%02x", md5_value[i]);
	}

	return 0;
}


static void wifidog_itoa(unsigned int n,unsigned char *string)
{
	int i,j,sign;
	int k = 0;
	char temp[128] = {'\0'};
	
    if((sign=n)<0)    //记录符号  
        n=-n;         //使n成为正数  
    i=0;

    do{  
        temp[i++]=n%10+'0';    //取下一个数字  
    }while((n/=10)>0);      //循环相除  
  
    if(sign<0)  
        temp[i++]='-';  
    temp[i]='\0';  
    for(j=i-1,k = 0;j>=0;j--,k++){        //生成的数字是逆序的，所以要逆序输出  
		string[k] = temp[j];
	}
}

/*
	*  t = TIMESTAMP
	*  end = t[9:]
	*  s = md5(md5(t[end:]) + t[0:end])
	*  k = s[end:]
* */
unsigned long int build_t_key(char *t,char *k)
{
	time_t time_stamp = 0;	
	time_t end = 0;
	unsigned char time_string[64] = {'\n'};
	char md5_str[MD5_STR_LEN + 1];
	unsigned char string_time[64] = {'\0'};

	time_stamp = time(NULL);
	
	/*All is string,make the time stamp conver to string*/
	wifidog_itoa(time_stamp,time_string);
	/*end = time[9:]*/
	end  = atoi((const char *)(time_string+9));
	//md5 (const char *message, long len, char *output);
	if ( end != 0 ){
		Compute_string_md5(time_string + end, strlen((const char *)(time_string+end)), md5_str);
	}else{
		Compute_string_md5(time_string , strlen((const char *)(time_string)), md5_str);
	}

	memcpy(string_time,md5_str,strlen(md5_str));
	
	if ( end != 0 ){
		memcpy(string_time+strlen(md5_str),time_string,end);
	}
	
	Compute_string_md5(string_time, strlen((const char *)string_time), md5_str);

	if ( end != 0 ){
		memcpy(k,md5_str+end,strlen((const char *)(md5_str+end)));
	}else{
		memcpy(k,md5_str,strlen((const char *)(md5_str)));
	}

	memcpy(t,time_string,strlen((const char *)(time_string)));

	return 0;
}





