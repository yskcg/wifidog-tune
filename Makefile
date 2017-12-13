#For zte F663N
#MY_TARGET=mips-unknown-linux-uclibc
#For zte F631
MY_TARGET=arm-linux-uclibc
export CC=$(MY_TARGET)-gcc
export AR=$(MY_TARGET)-ar
export CPP=$(MY_TARGET) -E
export LD= $(MY_TARGET)-ld
export NM= $(MY_TARGET)-nm
export OBJDUMP = $(MY_TARGET)-objdump
export RANLIB = $(MY_TARGET)-ranlib
export STRIP = $(MY_TARGET)-strip
export AR = $(MY_TARGET)-ar

top_dir = $(PWD)
export top_dir

exclude_dirs := include bin doc jsonC libpcap-1.5 scripts tcpdump-4.5
dirs := $(shell find . -maxdepth 1 -type d)

dirs := $(basename $(patsubst ./%,%,$(dirs)))

dirs := $(filter-out $(exclude_dirs),$(dirs))

dirs := $(sort $(dirs))

SUBDIRS := $(dirs)
clean_dirs := $(addprefix _clean_,$(SUBDIRS) )

.PHONY: subdirs $(SUBDIRS) clean

all:clean build_dir $(SUBDIRS) 
	
build_dir:
	[ -d bin ] || mkdir bin
	[ -d include ] || mkdir include

$(SUBDIRS):ECHO
	$(MAKE) -C $@ linux

ECHO:
	@echo $(SUBDIRS)

#clean: $(dirs)
#	rm -rf bin include
#	for clean_target in $(dirs);
#	do
#	cd $@ && $(MAKE) clean \
#	done

$(clean_dirs):
	$(MAKE) -C $(patsubst _clean_%,%,$@) clean

clean: $(clean_dirs)    
	
