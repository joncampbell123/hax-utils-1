#!/usr/bin/bash
export WATCOM=/usr/watcom

# TESTING: If Jon's custom branch of Open Watcom 1.9 is present, use it--this is vital for testing!
if [ -d "/usr/src/openwatcom-1.9/rel2/binl" ]; then
	export WATCOM=/usr/src/openwatcom-1.9/rel2
fi

export EDPATH=$WATCOM/eddat
export PATH=$WATCOM/binl:$WATCOM/binw:$PATH
export "INCLUDE=$WATCOM/h/nt;$WATCOM/h/nt/directx;$WATCOM/h/nt/ddk;$WATCOM/h"
export HPS=/
# PROJTOP: top directory of project we are building
export PROJTOP=`pwd`
# TOP: top directory of entire project. set buildall.sh or make.sh
if [ x"$TOP" == x ]; then
	echo WARNING: TOP directory not set
	sleep 1
fi
