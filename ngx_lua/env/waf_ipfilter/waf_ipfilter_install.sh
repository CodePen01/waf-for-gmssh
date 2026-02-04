#!/bin/bash
if [ ! -f /usr/sbin/ipset ] && [ ! -f /sbin/ipset ];then
    if [ -f /usr/bin/apt ];then
        apt install ipset -y
		apt install gcc -y
    else
        yum install ipset -y
		yum install gcc -y
    fi
fi

if [ ! -f /usr/sbin/iptables ] && [ ! -f /sbin/iptables ];then
    if [ -f /usr/bin/apt ];then
        apt install iptables -y
    else
        yum install iptables -y
    fi
fi

init_file=/etc/init.d/waf_ipfilter
if [ -f $init_file ];then
    $init_file stop
fi
PATH_WAF=/www/server/safewaf
PATH_WAF_BIN=$PATH_WAF/bin
run_file=$PATH_WAF_BIN/waf-ipfilter
mkdir -p $PATH_WAF_BIN
gcc ./waf_ipfilter.c -o $run_file
chmod 700 $run_file
chown root:root $run_file

\cp -f ./waf_ipfilter.sh $init_file
chmod 700 $init_file
chown root:root $init_file
$init_file start
$init_file status

if [ -f "/usr/bin/apt-get" ];then
    sudo update-rc.d waf_ipfilter defaults
else
    chkconfig --add waf_ipfilter
    chkconfig --level 2345 waf_ipfilter on
fi
