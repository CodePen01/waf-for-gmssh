#!/bin/bash
# chkconfig: 2345 55 25

### BEGIN INIT INFO
# Provides:          waf_ipfilter
# Required-Start:    $all
# Required-Stop:     $all
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: starts waf_ipfilter
# Description:       starts the waf_ipfilter
### END INIT INFO

PATH_WAF=/www/server/safewaf
PATH_WAF_BIN=$PATH_WAF/bin
run_file=$PATH_WAF_BIN/waf-ipfilter
mkdir -p $PATH_WAF_BIN
start()
{
        isStart=$(ps aux |grep -E "(waf-ipfilter)"|grep -v grep|grep -v "/etc/init.d/waf_ipfilter"|awk '{print $2}'|xargs)
        if [ "$isStart" == '' ];then
                echo -e "Starting waf-ipfilter service... \c"
                nohup $run_file &> /dev/null &
                sleep 0.1
                isStart=$(ps aux |grep -E "(waf-ipfilter)"|grep -v grep|grep -v "/etc/init.d/waf_ipfilter"|awk '{print $2}'|xargs)
                if [ "$isStart" == '' ];then
                        echo -e "\033[31mfailed\033[0m"
                        echo '------------------------------------------------------'
                        echo 'run error!'
                        echo '------------------------------------------------------'
                        echo -e "\033[31mError: waf-ipfilter service startup failed.\033[0m"
                        return;
                fi
                echo -e "\033[32mdone\033[0m"
        else
                echo "Starting  waf-ipfilter service (pid $isStart) already running"
        fi
}

stop()
{
	echo -e "Stopping waf-ipfilter service... \c";
        pids=$(ps aux |grep -E "(waf-ipfilter)"|grep -v grep|grep -v "/etc/init.d/waf_ipfilter"|awk '{print $2}'|xargs)
        arr=($pids)

        for p in ${arr[@]}
        do
                kill -9 $p
        done
        echo -e "\033[32mdone\033[0m"
}

status()
{
        isStart=$(ps aux |grep -E "(waf-ipfilter)"|grep -v grep|grep -v "/etc/init.d/waf_ipfilter"|awk '{print $2}'|xargs)
        if [ "$isStart" != '' ];then
                echo -e "\033[32mwaf-ipfilter service (pid $isStart) already running\033[0m"
        else
                echo -e "\033[31mwaf-ipfilter service not running\033[0m"
        fi
}

case "$1" in
        'start')
                start
                ;;
        'stop')
                stop
                ;;
        'restart')
                stop
                sleep 0.2
                start
                ;;
        'reload')
                stop
                sleep 0.2
                start
                ;;
        'status')
                status
                ;;
        *)
                echo "Usage: /etc/init.d/waf_ipfilter {start|stop|restart|reload|status}"
        ;;
esac
