# makefile for building wifidog src code
# see ../INSTALL for installation instructions
# see ../Makefile and luaconf.h for further customization

# == CHANGE THE SETTINGS BELOW TO SUIT YOUR ENVIRONMENT =======================

# Your platform. See PLATS for possible values.
PLAT= none
PKG_BUILD_DIR=$(PWD)


CFLAGS= -O2 -Wall $(MYCFLAGS)  -fPIC $(MYLDFLAGS) $(DEFS) $(DEFAULT_INCLUDES)
RM= rm -f
#-Wl,-Bdynamic -lgcc_s
ifneq (,$(findstring openwrt-linux,$(CC)))
	LIBS= $(top_dir)/bin/libhttpd.a  $(top_dir)/bin/libjson-c.a  -Wl,-Bdynamic -ldl -Wl,-Bdynamic -lpthread $(MYLIBS)
else
   LIBS= -ldl -lpthread $(MYLIBS) -static $(top_dir)/bin/libhttpd.a -static $(top_dir)/bin/libjson-c.a
endif


MYLDFLAGS = -Wall -Wextra -Wno-unused-parameter $(COROSS_TOOLS_PATH)
EXTRA_CFLAGS +=
MYLIBS=
DEFS = -DHAVE_CONFIG_H
top_builddir = ..
DEFAULT_INCLUDES = -I. -I$(top_dir) -I$(top_dir)/include
# USE_READLINE=1

CORE_O=	main.o auth.o centralserver.o client_list.o commandline.o conf.o debug.o firewall.o fw_iptables.o gateway.o \
		http.o httpd_thread.o  ping_thread.o pstring.o safe.o simple_http.o util.o  wdctl_thread.o json_parse.o http_json.o md5.o\
		wd_util.o
LIB_O=

WIFIDOG_HEADERS=auth.h centralserver.h client_list.h commandline.h common.h conf.h debug.h firewall.h fw_iptables.h json_parse.h \
				gateway.h httpd_thread.h http.h ping_thread.h pstring.h safe.h simple_http.h util.h wdctl.h wdctl_thread.h wd_util.h \
				http_json.h md5.h

WIFIDOG= wifidog
WIFIDOG_O=	$(CORE_O)

WDCTL=	wdctl
WDCTL_O=	wdctl.o
WDCTL_HEADERS=wdctl.h

ALL_O= $(CORE_O) $(LIB_O) $(WIFIDOG_O) $(WDCTL_O)
ALL_T= $(WIFIDOG) $(WDCTL)

default: $(PLAT)

all:h_install $(ALL_T) install

o:	$(ALL_O)


$(WIFIDOG): $(WIFIDOG_O)  $(WIFIDOG_HEADERS)
	$(CC) -g -o $@  $(MYLDFLAGS) $(WIFIDOG_O) $(LIBS) $(COROSS_TOOLS_PATH)

$(WDCTL): $(WDCTL_O) $(WDCTL_HEADERS)
	$(CC) -g -o $@  $(MYLDFLAGS) $(WDCTL_O) $(LIBS) $(COROSS_TOOLS_PATH) 

clean:
	$(RM) $(ALL_T) $(ALL_O)

h_install:$(WIFIDOG_HEADERS)
	@$(foreach list, $(WIFIDOG_HEADERS),`cp $(list) $(top_dir)/include`)

install:$(LIBHTTP_HEADERS) $(ALL_SO)
	@$(foreach list, $(ALL_T),`cp $(list) $(top_dir)/bin`)

depend:
	@$(CC) $(CFLAGS) -MM l*.c print.c

echo:
	@echo "PLAT = $(PLAT)"
	@echo "CC = $(CC)"
	@echo "CFLAGS = $(CFLAGS)"
	@echo "AR = $(AR)"
	@echo "RANLIB = $(RANLIB)"
	@echo "RM = $(RM)"
	@echo "MYCFLAGS = $(MYCFLAGS)"
	@echo "MYLDFLAGS = $(MYLDFLAGS)"
	@echo "MYLIBS = $(MYLIBS)"

# convenience targets for popular platforms
RFLAG=$(if $(USE_READLINE),-DLUA_USE_READLINE)
none:
	@echo "Please choose a platform:"
	@echo "   $(PLATS)"

linux:
	$(MAKE) all MYCFLAGS+="-DLUA_USE_LINUX -fPIC $(RFLAG)" 


# list targets that do not create files (but not all makes understand .PHONY)
.PHONY: all $(PLATS) default o a clean depend echo none

# DO NOT DELETE

