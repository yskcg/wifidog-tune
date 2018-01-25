#!/bin/sh

topdir=`pwd`
product_dir=${topdir}/MoreAuth
get_product_list(){
	pushd ${product_dir} >/dev/null
	ls
	popd  >/dev/null
}

usage(){
	cat  <<EOF
Usage: $0 [<build-option>...] <product name>

build-option:
	-l		list the supported product name
	-h		usage
	
EOF
}


begin_build(){
	pushd ${topdir} >/dev/null
	make
	popd  >/dev/null
}
prepare_build(){
	pushd ${product_dir} >/dev/null

	if [ -d "${product_dir}/$1" ];then
		rm -rf ${topdir}/Makefile ${topdir}/wifidog.conf ${topdir}/wifidog-msg.html  ${topdir}/wifidog_config.h
		cp -f ${product_dir}/$1/* ${topdir}
		export WIFIDOG_VERSION=`sed -n '/ VERSION/p' ${product_dir}/$1/wifidog_config.h | awk '{print $3 }' | sed 's/"//g' | xargs echo -n `
	else
		echo "invaild product name $1"
		exit 1
	fi

	popd  >/dev/null
}

[ $# -eq 0 ] && {
	usage
	exit
}



#parse options
while [ -n "$1" ] ;do
	case "$1" in
		-l) get_product_list ;;
		-h) usage ;;
		 *) prepare_build $1 
			begin_build
		;;
	esac
	shift;
done
