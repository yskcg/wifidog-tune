# makefile for building lua-cjson
# see ../INSTALL for installation instructions


# == CHANGE THE SETTINGS BELOW TO SUIT YOUR ENVIRONMENT =======================

# Your platform. See PLATS for possible values.
PLAT= none
PKG_BUILD_DIR=$(PWD)


CFLAGS= -O2 -Werror -Wwrite-strings -D_GNU_SOURCE -D_REENTRANT -shared $(MYCFLAGS)  -fPIC $(MYLDFLAGS) $(DEFS) $(DEFAULT_INCLUDES)
RM= rm -f
LIBS= -lm $(MYLIBS)

MYLDFLAGS = -Wall -Wextra -Wno-unused-parameter $(COROSS_TOOLS_PATH) 
EXTRA_CFLAGS +=
MYLIBS=
DEFS = -DHAVE_CONFIG_H
top_builddir = ..
DEFAULT_INCLUDES = -I. -I$(top_builddir) 
# == END OF USER SETTINGS. NO NEED TO CHANGE ANYTHING BELOW THIS LINE =========

PLATS= linux

LIBJSON_C_A= libjson-c.a
LIBJSON_C_SO= libjson-c.so
CORE_O=cJSON.o cjson_parse.o
LIBJSON_C_HEADERS= cJSON.h cjson_parse.h
LIB_O=

ALL_O= $(CORE_O)
ALL_T= $(LIBJSON_C_SO) $(LIBJSON_C_A)
ALL_SO= $(LIBJSON_C_SO)

default: $(PLAT)

all:	$(ALL_T) install

o:	$(ALL_O)

a:  $(ALL_A) 

so:	$(LIBJSON_C_SO)

$(LIBJSON_C_A):$(ALL_O) $(LIBJSON_C_HEADERS)
	$(AR) cru $@ $(ALL_O) 
	$(RANLIB) $@ 

$(LIBJSON_C_SO): $(ALL_O)
	$(CC) -o $@ -shared $? $(COROSS_TOOLS_PATH)

install:$(LIBJSON_C_HEADERS)
	@$(foreach list, $(LIBJSON_C_HEADERS),`cp $(list) $(top_builddir)/include`)
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
cJSON.o:$(LIBJSON_C_HEADERS)
cjson_parse.o: $(LIBJSON_C_HEADERS)
# (end of Makefile)
