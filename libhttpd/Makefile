# makefile for building libhttpd
# see ../INSTALL for installation instructions


# == CHANGE THE SETTINGS BELOW TO SUIT YOUR ENVIRONMENT =======================

# Your platform. See PLATS for possible values.
PLAT= none
PKG_BUILD_DIR=$(PWD)


CFLAGS= -O2 -Wall -shared $(MYCFLAGS)  -fPIC $(MYLDFLAGS) $(DEFS) $(DEFAULT_INCLUDES)
RM= rm -f
LIBS= -lm $(MYLIBS)

MYLDFLAGS = -Wall -Wextra -Wno-unused-parameter
EXTRA_CFLAGS +=
MYLIBS=
DEFS = -DHAVE_CONFIG_H
top_builddir = ..
DEFAULT_INCLUDES = -I. -I$(top_builddir)

# == END OF USER SETTINGS. NO NEED TO CHANGE ANYTHING BELOW THIS LINE =========

LIBHTTPD_A = libhttpd.a
LIBHTTPD_SO = libhttpd.so

LIBHTTP_CORE_O=	api.o ip_acl.o protocol.o version.o
LIBHTTP_HEADERS= httpd.h httpd_priv.h 

ALL_O= $(LIBHTTP_CORE_O)
ALL_T= $(LIBHTTPD_SO) $(LIBHTTPD_A)
ALL_SO= $(LIBHTTPD_SO)
ALL_A = $(LIBHTTPD_A)


default: $(PLAT)

all:	$(ALL_T) install

o:	$(ALL_O)

a: $(ALL_A)

so:	$(LIBHTTPD_SO)

$(LIBHTTPD_A): $(LIBHTTP_CORE_O) $(LIBHTTP_HEADERS)
	$(AR) cru $@ $(LIBHTTP_CORE_O)
	$(RANLIB) $@

$(LIBHTTPD_SO): $(LIBHTTP_CORE_O) $(LIBHTTP_HEADERS)
	$(CC) -o $@ -shared $? 

install:$(LIBHTTP_HEADERS) $(ALL_SO)
	@$(foreach list, $(LIBHTTP_HEADERS),`cp $(list) $(top_builddir)/include`)
	@$(foreach list, $(ALL_T),`cp $(list) $(top_builddir)/bin`)

clean:
	$(RM) $(ALL_T) $(ALL_O) 

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
none:
	@echo "Please choose a platform:"
	@echo "   $(PLATS)"


linux:
	$(MAKE) all MYLIBS="-Wl,-E -ldl"

# DO NOT DELETE
api.o:$(LIBHTTP_HEADERS)
ip_acl.o:$(LIBHTTP_HEADERS)
protocol.o:$(LIBHTTP_HEADERS)
version.o:$(LIBHTTP_HEADERS)

# (end of Makefile)
