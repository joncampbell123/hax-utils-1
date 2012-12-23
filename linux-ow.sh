#!/usr/bin/bash
export WATCOM=/usr/watcom

# TESTING: If Jon's custom branch of Open Watcom 1.9 is present, use it--this is vital for testing!
#if [ -d "/usr/src/openwatcom-1.9/rel2/binl" ]; then
#	export WATCOM=/usr/src/openwatcom-1.9/rel2
#fi

export EDPATH=$WATCOM/eddat
export PATH=$WATCOM/binl:$WATCOM/binw:$PATH
export "INCLUDE=$WATCOM/h/nt;$WATCOM/h/nt/directx;$WATCOM/h/nt/ddk;$WATCOM/h"
export HPS=/

#export WCC=$WATCOM/binl/wcc
#export WCC386=$WATCOM/binl/wcc386
#export WLINK=$WATCOM/binl/wlink

