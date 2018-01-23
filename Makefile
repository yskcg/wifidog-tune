#for hw hs8546
MY_TARGET=arm-linux
TARGET_NAME=HW-HS8546

#For zte F663N
#MY_TARGET=mips-unknown-linux-uclibc
#TARGET_NAME=ZTE-F663N

#For zte F631
#MY_TARGET=arm-linux-uclibc
#TARGET_NAME=ZTE-F631

#For zte 860
#MY_TARGET=mipsel-linux
#TARGET_NAME=ZTE-860

#For rj svg6000rw
#MY_TARGET=rj-svg-mipsel-linux
#TARGET_NAME=RJ-SVG6000

#For rj h810g
#MY_TARGET=rj-h810-mips-linux
#TARGET_NAME=RJ-h810g
#export COROSS_TOOLS_PATH="--sysroot=/opt/rj-h810g/mips-linux-uclibc/"

#MY_TARGET=i486-openwrt-linux
#MY_TARGET=mipsel-openwrt-linux
export CC=$(MY_TARGET)-gcc
export AR=$(MY_TARGET)-ar
export CPP=$(MY_TARGET) -E
export LD=$(MY_TARGET)-ld
export NM= $(MY_TARGET)-nm
export OBJDUMP = $(MY_TARGET)-objdump
export RANLIB = $(MY_TARGET)-ranlib
export STRIP = $(MY_TARGET)-strip
export AR = $(MY_TARGET)-ar


COMPILE_TIME = $(shell date +"%Y-%m-%d-%H-%M-%S")
ifneq (,$(TARGET_NAME))
	output_name=$(TARGET_NAME)-$(COMPILE_TIME)
else
	output_name=openwrt-$(COMPILE_TIME)
endif

top_dir = $(PWD)
export top_dir

exclude_dirs := include bin doc  upgrade libpcap-1.5 scripts tcpdump-4.5
dirs := $(shell find . -maxdepth 1 -type d)

dirs := $(basename $(patsubst ./%,%,$(dirs)))

dirs := $(filter-out $(exclude_dirs),$(dirs))

dirs := $(sort $(dirs))

SUBDIRS := $(dirs)
clean_dirs := $(addprefix _clean_,$(SUBDIRS) )

.PHONY: subdirs $(SUBDIRS) clean

all:clean prepare_build $(SUBDIRS) install
	
prepare_build:
	[ -d bin ] || mkdir bin
	[ -d include ] || mkdir include

$(SUBDIRS): $(ECHO)
	$(MAKE) -C $@ linux

ECHO:
	@echo $(SUBDIRS)

$(clean_dirs):
	$(MAKE) -C $(patsubst _clean_%,%,$@) clean

clean: $(clean_dirs)    
	rm -rf bin
	rm -rf include

install:
	@mkdir -p install
	@cp wifidog.conf install/
	@cp wifidog-msg.html install/
	@cp bin/wifidog install/
	@cp bin/wdctl install/
	@tar cvzf $(output_name).tar.gz install >/dev/null 2>&1
	cp $(output_name).tar.gz upgrade/
	@echo "build done in upgrade dir"
	@rm -rf $(output_name).tar.gz
	@rm -rf install
