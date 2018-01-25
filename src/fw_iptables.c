/* vim: set et ts=4 sts=4 sw=4 : */
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
/** @internal
  @file fw_iptables.c
  @brief Firewall iptables functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#include "safe.h"
#include "conf.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"

static int iptables_do_command(const char *format, ...);

/**
Used to supress the error output of the firewall during destruction */
static int fw_quiet = 0;

/** @internal
 * @brief Insert $ID$ with the gateway's id in a string.
 *
 * This function can replace the input string with a new one. It assumes
 * the input string is dynamically allocted and can be free()ed safely.
 *
 * This function must be called with the CONFIG_LOCK held.
 */
static void
iptables_insert_gateway_id(char **input)
{
    char *token;
    const s_config *config;
    char *buffer;
    char *tmp_intf;

    if (strstr(*input, "$ID$") == NULL)
        return;

    while ((token = strstr(*input, "$ID$")) != NULL)
        /* This string may look odd but it's standard POSIX and ISO C */
        memcpy(token, "%1$s", 4);

    config = config_get_config();
    tmp_intf = safe_strdup(config->gw_interface);
    if (strlen(tmp_intf) > CHAIN_NAME_MAX_LEN) {
        *(tmp_intf + CHAIN_NAME_MAX_LEN) = '\0';
    }
    safe_asprintf(&buffer, *input, tmp_intf);

    free(tmp_intf);
    free(*input);  /* Not an error, input from safe_asprintf */
    *input = buffer;
}

/** @internal 
 * */
static int
iptables_do_command(const char *format, ...)
{
    va_list vlist;
    char *fmt_cmd;
    char *cmd;
    int rc;

    va_start(vlist, format);
    safe_vasprintf(&fmt_cmd, format, vlist);
    va_end(vlist);

    safe_asprintf(&cmd, "iptables %s", fmt_cmd);
    free(fmt_cmd);

    iptables_insert_gateway_id(&cmd);

    debug(LOG_DEBUG, "Executing command: %s", cmd);

    rc = execute(cmd, fw_quiet);

    if (rc != 0) {
        // If quiet, do not display the error
        if (fw_quiet == 0)
            debug(LOG_ERR, "iptables command failed(%d): %s", rc, cmd);
        else if (fw_quiet == 1)
            debug(LOG_DEBUG, "iptables command failed(%d): %s", rc, cmd);
    }

    free(cmd);

    return rc;
}

void iptables_fw_set_white_list(const char * mac)
{
	if(mac == NULL){
		return ;
	}

	iptables_do_command("-t nat -A " CHAIN_WHITE_MAC_LIST " -m mac --mac-source %s -j ACCEPT", mac);
}

void iptables_fw_clear_white_list(void)
{
	 iptables_do_command("-t nat -F " CHAIN_WHITE_MAC_LIST);
}

void iptables_fw_clear_black_list(void)
{
	 iptables_do_command("-t nat -F " CHAIN_BLACK_MAC_LIST);
}

void iptables_fw_set_black_list(const char * mac)
{
	if(mac == NULL){
		return ;
	}

	iptables_do_command("-t nat -A " CHAIN_BLACK_MAC_LIST " -m mac --mac-source %s -j DNAT --to-destination 0.0.0.0", mac);
}

void
iptables_fw_clear_authservers(void)
{
    iptables_do_command("-t nat -F " CHAIN_AUTHSERVERS);
}

void
iptables_fw_set_authservers(void)
{
    const s_config *config;
    t_auth_serv *auth_server;

    config = config_get_config();

    for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
        if (auth_server->last_ip && strcmp(auth_server->last_ip, "0.0.0.0") != 0) {
            iptables_do_command("-t nat -A " CHAIN_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
        }
    }

}

/** Initialize the firewall rules
*/
int
iptables_fw_init(void)
{
    const s_config *config;
    char *ext_interface = NULL;
    int gw_port = 0;
    fw_quiet = 0;
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;

    LOCK_CONFIG();
    config = config_get_config();
    gw_port = config->gw_port;
    if (config->external_interface) {
        ext_interface = safe_strdup(config->external_interface);
    } else {
        ext_interface = get_ext_iface();
    }

    if (ext_interface == NULL) {
        UNLOCK_CONFIG();
        debug(LOG_ERR, "FATAL: no external interface");
        return 0;
    }

    /*
     *
     * Everything in the NAT table
     *
     */

    /* Create new chains */
    iptables_do_command("-t nat -N " CHAIN_OUTGOING);
    iptables_do_command("-t nat -N " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -N " CHAIN_TO_INTERNET);
	iptables_do_command("-t nat -N " CHAIN_BLACK_MAC_LIST);
	iptables_do_command("-t nat -N " CHAIN_WHITE_MAC_LIST);

    iptables_do_command("-t nat -N " CHAIN_GLOBAL);
    iptables_do_command("-t nat -N " CHAIN_UNKNOWN);
    iptables_do_command("-t nat -N " CHAIN_AUTHSERVERS);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -N " CHAIN_AUTH_IS_DOWN);

    /* Assign links and rules to these new chains */
    iptables_do_command("-t nat -A PREROUTING -i %s -j " CHAIN_OUTGOING, config->gw_interface);

    iptables_do_command("-t nat -A " CHAIN_OUTGOING " -d %s -j " CHAIN_TO_ROUTER, config->gw_address);
    iptables_do_command("-t nat -A " CHAIN_TO_ROUTER " -j ACCEPT");

	/*support for mac list black list and white list*/
	iptables_do_command("-t nat -A " CHAIN_OUTGOING " -j " CHAIN_BLACK_MAC_LIST);
	iptables_do_command("-t nat -A " CHAIN_OUTGOING " -j " CHAIN_WHITE_MAC_LIST);

    iptables_do_command("-t nat -A " CHAIN_OUTGOING " -j " CHAIN_TO_INTERNET);

    iptables_do_command("-t nat -A " CHAIN_TO_INTERNET " -j " CHAIN_UNKNOWN);

    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_GLOBAL);
    if (got_authdown_ruleset) {
        fw_set_authdown();
    }
    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -p tcp --dport 80 -j REDIRECT --to-ports %d", gw_port);

	/*add for morewifi*/
	iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j DNAT --to-destination 0.0.0.0");

    UNLOCK_CONFIG();

    free(ext_interface);
    return 1;
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog and when it starts to make
 * sure there are no rules left over
 */
int
iptables_fw_destroy(void)
{
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    fw_quiet = 1;

    /*
     *
     * Everything in the NAT table
     *
     */
    debug(LOG_DEBUG, "Destroying chains in the NAT table");
    iptables_fw_destroy_mention("nat", "PREROUTING", CHAIN_OUTGOING);
    iptables_do_command("-t nat -F " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -F " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -F " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t nat -F " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -F " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -F " CHAIN_GLOBAL);
    iptables_do_command("-t nat -F " CHAIN_UNKNOWN);
	iptables_do_command("-t nat -F " CHAIN_BLACK_MAC_LIST);
	iptables_do_command("-t nat -F " CHAIN_WHITE_MAC_LIST);
    iptables_do_command("-t nat -X " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -X " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -X " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t nat -X " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -X " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -X " CHAIN_GLOBAL);
    iptables_do_command("-t nat -X " CHAIN_UNKNOWN);
	iptables_do_command("-t nat -X " CHAIN_BLACK_MAC_LIST);
	iptables_do_command("-t nat -X " CHAIN_WHITE_MAC_LIST);

    return 1;
}

/*
 * Helper for iptables_fw_destroy
 * @param table The table to search
 * @param chain The chain in that table to search
 * @param mention A word to find and delete in rules in the given table+chain
 */
int
iptables_fw_destroy_mention(const char *table, const char *chain, const char *mention)
{
    FILE *p = NULL;
    char *command = NULL;
    char *command2 = NULL;
    char line[MAX_BUF];
    char rulenum[10];
    char *victim = safe_strdup(mention);
    int deleted = 0;

    iptables_insert_gateway_id(&victim);

    debug(LOG_DEBUG, "Attempting to destroy all mention of %s from %s.%s", victim, table, chain);

    safe_asprintf(&command, "iptables -t %s -L %s -n --line-numbers -v", table, chain);
    iptables_insert_gateway_id(&command);

    if ((p = popen(command, "r"))) {
        /* Skip first 2 lines */
        while (!feof(p) && fgetc(p) != '\n') ;
        while (!feof(p) && fgetc(p) != '\n') ;
        /* Loop over entries */
        while (fgets(line, sizeof(line), p)) {
            /* Look for victim */
            if (strstr(line, victim)) {
                /* Found victim - Get the rule number into rulenum */
                if (sscanf(line, "%9[0-9]", rulenum) == 1) {
                    /* Delete the rule: */
                    debug(LOG_DEBUG, "Deleting rule %s from %s.%s because it mentions %s", rulenum, table, chain,
                          victim);
                    safe_asprintf(&command2, "-t %s -D %s %s", table, chain, rulenum);
                    iptables_do_command(command2);
                    free(command2);
                    deleted = 1;
                    /* Do not keep looping - the captured rulenums will no longer be accurate */
                    break;
                }
            }
        }
        pclose(p);
    }

    free(command);
    free(victim);

    if (deleted) {
        /* Recurse just in case there are more in the same table+chain */
        iptables_fw_destroy_mention(table, chain, mention);
    }

    return (deleted);
}

/** Set if a specific client has access through the firewall */
int
iptables_fw_access(fw_access_t type, const char *ip, const char *mac, int tag)
{
    int rc = -1;
	int ret = -1;
	char *script;

    fw_quiet = 0;

    switch (type) {
    case FW_ACCESS_ALLOW:
	   /*make sure iptables rules no this rule*/
	   safe_asprintf(&script, "iptables -t nat -C %s -m mac --mac-source %s -j ACCEPT", CHAIN_TO_INTERNET, mac);
       iptables_insert_gateway_id(&script);
       ret = system(script);
       free(script);
  
	   if(ret != 0 ){
	       rc = iptables_do_command("-t nat -I " CHAIN_TO_INTERNET " -m mac --mac-source %s -j ACCEPT", mac);
	   }
       
       break;
    case FW_ACCESS_DENY:
        /* XXX Add looping to really clear? */
        rc = iptables_do_command("-t nat -D " CHAIN_TO_INTERNET " -m mac --mac-source %s -j ACCEPT", mac);
        break;
    default:
        rc = -1;
        break;
    }

    return rc;
}

int
iptables_fw_access_host(fw_access_t type, const char *host)
{
    int rc;

    fw_quiet = 0;

    switch (type) {
    case FW_ACCESS_ALLOW:
        rc = iptables_do_command("-t nat -A " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        break;
    case FW_ACCESS_DENY:
        rc = iptables_do_command("-t nat -D " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        break;
    default:
        rc = -1;
        break;
    }

    return rc;
}

/** Set a mark when auth server is not reachable */
int
iptables_fw_auth_unreachable(int tag)
{
	int ret = -1;
	int rc ;
	char *script;

    /*check the iptables rules exist*/
	safe_asprintf(&script, "iptables -t nat -C %s -j ACCEPT", CHAIN_OUTGOING);
    iptables_insert_gateway_id(&script);
    //ret = system(script);
	ret = execute(script, fw_quiet);
	debug(LOG_ERR, "%s %d ret:%d  %s !\n",__FUNCTION__,__LINE__,ret,script);
    free(script);

    if(ret != 0 ){
	    rc = iptables_do_command("-t nat -I " CHAIN_OUTGOING " 1 -j ACCEPT");
		return 1;
    }
	
	return 0;
}

/** Remove mark when auth server is reachable again */
int
iptables_fw_auth_reachable(void)
{
	int ret = -1;
	int rc ;
	char *script;

    /*check the iptables rules exist*/
	safe_asprintf(&script, "iptables -t nat -C %s -j ACCEPT", CHAIN_OUTGOING);
    iptables_insert_gateway_id(&script);
    //ret = system(script);
	ret = execute(script, fw_quiet);
	debug(LOG_ERR, "%s %d ret:%d  %s !\n",__FUNCTION__,__LINE__,ret,script);
    free(script);
	
    if(ret == 0 ){
	    rc = iptables_do_command("-t nat -D " CHAIN_OUTGOING " -j ACCEPT");
		return rc;
    }

	return 1;
}

