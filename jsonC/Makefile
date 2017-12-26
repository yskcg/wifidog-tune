# makefile for building lua-cjson
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

PLATS= linux

LIBJSON_C_A= libjson-c.a
LIBJSON_C_SO= libjson-c.so
CORE_O=	arraylist.o debug.o json_c_version.o json_object.o json_object_iterator.o json_tokener.o json_util.o linkhash.o printbuf.o random_seed.o
LIBJSON_C_HEADERS= arraylist.h bits.h debug.h json.h json_config.h json_c_version.h json_inttypes.h json_object.h \
					json_object_iterator.h json_object_private.h json_tokener.h json_util.h linkhash.h printbuf.h random_seed.h
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
	$(CC) -o $@ -shared $?

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

arraylist.o:$(LIBJSON_C_HEADERS)
debug.o: $(LIBJSON_C_HEADERS)
json_c_version.o: $(LIBJSON_C_HEADERS)
json_object.o: $(LIBJSON_C_HEADERS)
json_object_iterator.o: $(LIBJSON_C_HEADERS)
json_tokener.o: $(LIBJSON_C_HEADERS)
json_util.o: $(LIBJSON_C_HEADERS)
linkhash.o: $(LIBJSON_C_HEADERS)
printbuf.o: $(LIBJSON_C_HEADERS)
random_seed.o: $(LIBJSON_C_HEADERS)

# (end of Makefile)
