/* vim: set et sw=4 ts=4 sts=4 : */
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
/** @file gateway.h
    @brief Main loop
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _GATEWAY_H_
#define _GATEWAY_H_

#include <stdio.h>
#include <ctype.h>

#include "httpd.h"
#include "util.h"


extern time_t started_time;

/** @brief The internal web server */
extern httpd *webserver;

/** @brief actual program entry point. */
int gw_main(int, char **);

/** @brief exits cleanly and clear the firewall rules. */
void termination_handler(int s);

#endif                          /* _GATEWAY_H_ */
