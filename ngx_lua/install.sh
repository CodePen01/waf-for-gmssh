#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 1本地 0线上
BENDI=0
# Nginx配置路径
PATH_NGINX_BIN=/www/server/nginx/sbin/nginx
PATH_NGINX_CONF=/www/server/nginx/conf/nginx.conf
# 安装waf路径
PATH_WAF=/www/server/safewaf
PATH_WAF_LUA=$PATH_WAF/lua
PATH_WAF_ENV=$PATH_WAF/env
PATH_WAF_LOG=$PATH_WAF/log
PATH_WAF_ENV_PKG=$PATH_WAF_ENV/pkg
PATH_WAF_OPEN_CONF=$PATH_WAF_ENV/open_conf
# waf应用脚本路径
PATH_INSTALL_WAF="/.__gmssh/plugin/kele/safewaf/install"

Get_platform(){
    case $(uname -s 2>/dev/null) in
        Linux )                    echo "linux" ;;
        FreeBSD )                  echo "freebsd" ;;
        *BSD* )                    echo "bsd" ;;
        Darwin )                   echo "macosx" ;;
        CYGWIN* | MINGW* | MSYS* ) echo "mingw" ;;
        AIX )                      echo "aix" ;;
        SunOS )                    echo "solaris" ;;
        * )                        echo "linux"
    esac
}

Get_ARM() {
	if [[ $(uname -m) == "aarch64" ]]; then
		echo "当前系统是ARM64架构"
		# 检查Nginx是否为OpenResty版本
		if [[ ! -x "$PATH_NGINX_BIN" ]]; then
			echo "错误：未找到可执行的Nginx二进制文件"
			exit 1
		fi
		# 获取Nginx版本信息
		VERSION_INFO=$("$PATH_NGINX_BIN" -v 2>&1)
		# 检查是否包含"openresty"字符串
		if [[ ! "$VERSION_INFO" =~ "openresty" ]]; then
			echo '安装失败,ARM系统需要安装openresty版本的Nginx'
			exit 1
		fi
	fi
}


Install_lua515(){
    echo "安装Lua5.1.5"
    cd $PATH_WAF_ENV_PKG && tar xzf $PATH_WAF_ENV_PKG/lua-5.1.5.tar.gz
    cd $PATH_WAF_ENV_PKG/lua-5.1.5
    platform=$(Get_platform)
    make "${platform}" install
    ldconfig
}


Install_luajit(){
    if command -v luajit >/dev/null 2>&1; then
        if [ -f /usr/local/include/luajit-2.1/luajit.h ]; then
            echo "【跳过安装】检测到LuaJIT 2.1.0"
            return 1
        fi
    fi
    echo "安装LuaJIT"
    cd $PATH_WAF_ENV_PKG && unzip -o $PATH_WAF_ENV_PKG/luajit2-2.1-20230410.zip
    cd $PATH_WAF_ENV_PKG/luajit2-2.1-20230410
    make
    make install
    ln -sf /usr/local/lib/libluajit-5.1.so.2 /usr/local/lib64/libluajit-5.1.so.2
    LD_SO_CHECK=$(cat /etc/ld.so.conf|grep /usr/local/lib)
    if [ -z "${LD_SO_CHECK}" ];then
         echo "/usr/local/lib" >>/etc/ld.so.conf
    fi
    ldconfig
}


Install_cjson(){
    luajit -e "require 'cjson'" >/dev/null 2>&1
    local exec_status=$?
    if [ $exec_status -eq 0 ]; then
        echo "【跳过安装】检测到Cjson"
        return 1
    fi
    echo "安装Cjson"
    cd $PATH_WAF_ENV_PKG && tar xzf lua-cjson-2.1.0.tar.gz
    cd $PATH_WAF_ENV_PKG/lua-cjson-2.1.0
    make CFLAGS="-O3 -Wall -pedantic -DNDEBUG -I/usr/include/lua5.1 -I/usr/include -fpic"
    make install

}

Install_sqlite3(){
    luajit -e "require 'lsqlite3'" >/dev/null 2>&1
    local exec_status=$?
    if [ $exec_status -eq 0 ]; then
        echo "【跳过安装】检测到Sqlite3"
        return 1
    fi
    echo "安装Sqlite3"
    cd $PATH_WAF_ENV_PKG && unzip -o $PATH_WAF_ENV_PKG/lsqlite3_fsl09y.zip
    cd $PATH_WAF_ENV_PKG/lsqlite3_fsl09y
    gcc -O2 -fPIC -c lsqlite3.c -o lsqlite3.o -DLSQLITE_VERSION='"0.9.5"' -I/usr/include/lua5.1 -I/usr/include
    gcc -shared -o lsqlite3.so lsqlite3.o -L/usr/lib -Wl,-rpath,/usr/lib -lsqlite3
    mkdir -p /usr/local/lib/lua/5.1
    cp lsqlite3.so /usr/local/lib/lua/5.1
    chmod 755 /usr/local/lib/lua/5.1/lsqlite3.so

}


Install_safewaf(){

	Get_ARM
	#如果是ARM的系统。需要判断安装Nginx是否为openresty

    echo "开始安装";

    # 资源安装
	if [ -d $PATH_WAF_ENV ];then
		rm -rf $PATH_WAF_ENV
	fi
    mkdir -p $PATH_WAF_ENV
    \cp -a -r VERSION $PATH_WAF/VERSION
    \cp -a -r env/* $PATH_WAF_ENV
	if [ -d $PATH_WAF_LUA ];then
		rm -rf $PATH_WAF_LUA
	fi
    mkdir -p $PATH_WAF_LUA
    \cp -a -r lua/* $PATH_WAF_LUA
    mkdir -p $PATH_WAF_LUA/ext

	cd $PATH_WAF_ENV

    # ---------安装依赖-----------------------
    if [ "$BENDI" -eq 0 ]; then
        echo '正在安装依赖...'

        if command -v yum &>/dev/null; then
            # CentOS/RHEL 系统（yum）
            yum install -y gcc gcc-c++ readline-devel net-tools unzip sqlite-devel
        elif command -v apt &>/dev/null; then
            # Debian/Ubuntu 系统（apt）
            apt install -y gcc g++ libreadline-dev net-tools unzip libsqlite3-dev libncurses5-dev
        else
            echo "错误：仅支持 yum/apt 包管理器的系统！"
            exit 1
        fi

        Install_lua515
        Install_luajit
        Install_cjson
        Install_sqlite3

    fi

	echo '正在安装WAF模块...'

    mkdir -p $PATH_WAF_LUA/ext/captcha
    echo "{}" > $PATH_WAF_LUA/ext/captcha/num2.json

    mkdir -p $PATH_WAF_OPEN_CONF
    \cp -a -r $PATH_WAF_ENV/conf/safewaf.conf  $PATH_WAF_OPEN_CONF/safewaf.conf

	chmod +x $PATH_WAF_LUA/load.lua
	chmod +x $PATH_WAF_LUA/start.lua
	chmod +x $PATH_WAF_LUA/hook_body.lua
	chmod +x $PATH_WAF_LUA/hook_header.lua

	mkdir -p $PATH_WAF_LOG
    echo '' > $PATH_WAF_LOG/safewaf_debug.log
    chmod 777 $PATH_WAF_LOG/safewaf_debug.log
    mkdir -p $PATH_WAF_LUA/db/http_log

	if [ ! -f $PATH_WAF_LUA/resty/memcached.lua ];then
		#做软连
		if [ -f /www/server/nginx/lualib/resty/memcached.lua ];then
			#openrestry 兼容
			echo "openresty兼容"
			ln -s /www/server/nginx/lualib/resty  $PATH_WAF_LUA
		fi
	fi

    # ---------安装waf_ipfilter-----------------------
    if [ "$BENDI" -eq 0 ]; then
        if [ ! -f /usr/sbin/iptables ] && [ ! -f /sbin/iptables ];then
            if [ -f /usr/bin/apt ];then
                apt install iptables -y
            else
                yum install iptables -y
            fi
        fi

        cd $PATH_WAF_ENV/waf_ipfilter
        chmod +x waf_ipfilter_install.sh
        bash waf_ipfilter_install.sh
    fi
    # -----------------------------------------------
	NGINX_VER=$($PATH_NGINX_BIN -v 2>&1|grep -oE 1.[1-9][0-9])
	if [ "${NGINX_VER}" ];then
		sed -i "/lua_package_path/d" $PATH_NGINX_CONF
        rm -rf /usr/local/share/lua/5.1/ngx
        rm -rf /usr/local/share/lua/5.1/resty
        \cp -rpa /www/server/nginx/lib/lua/ngx /usr/local/share/lua/5.1/
        \cp -rpa /www/server/nginx/lib/lua/resty /usr/local/share/lua/5.1/
        \cp -rpa /www/server/nginx/lib/lua/ngx $PATH_WAF_LUA/
        \cp -rpa /www/server/nginx/lib/lua/resty $PATH_WAF_LUA/
	fi
	NGINX_VER=$($PATH_NGINX_BIN -v 2>&1|grep -oE openresty)
	if [ "${NGINX_VER}" ];then
		sed -i "/lua_package_path/d" $PATH_NGINX_CONF
        rm -rf /usr/local/share/lua/5.1/ngx
        rm -rf /usr/local/share/lua/5.1/resty
        \cp -rpa /www/server/nginx/lualib/ngx /usr/local/share/lua/5.1/
        \cp -rpa /www/server/nginx/lualib/resty /usr/local/share/lua/5.1/
        \cp -rpa /www/server/nginx/lib/lua/ngx $PATH_WAF_LUA/
        \cp -rpa /www/server/nginx/lib/lua/resty $PATH_WAF_LUA/
	fi

    # 兼容Debian
    if [ -f "/usr/lib/x86_64-linux-gnu/lua/5.1/cjson.so" ] ;then
        \cp -rpa /usr/lib/x86_64-linux-gnu/lua/5.1/cjson.so /www/server/safewaf/lua/ext/
    fi

    # 兼容ngx_resty
	if [ -f  /www/server/nginx/lib/lua/ngx ];then
		\cp -a -r /www/server/nginx/lib/lua/ngx /usr/local/share/lua/5.1/
		\cp -a -r /www/server/nginx/lib/lua/ngx $PATH_WAF_LUA/
	fi
	if [ -f  /www/server/nginx/lib/lua/resty ];then
		\cp -a -r /www/server/nginx/lib/lua/resty /usr/local/share/lua/5.1/
		\cp -a -r /www/server/nginx/lib/lua/resty $PATH_WAF_LUA/
	fi

    # 配置全局设置文件
    START_TIME=$(date +%s)
    sed -i \
        -e 's/"{{START_TIME}}"/'"${START_TIME}"'/g' \
        "${PATH_WAF_LUA}/config.json"

    # 配置文件权限
    chown www:www -R $PATH_WAF_LUA
    chmod 777 -R $PATH_WAF_LUA

    if [ -f /etc/init.d/nginx ];then
        if [ -x /etc/init.d/nginx ]; then
	        /etc/init.d/nginx restart
        else
            systemctl restart nginx
        fi
    else
        systemctl restart nginx
    fi

    # 检查当前启动的nginx进程
    PS_NGINX_BIN=""
    if command -v nginx >/dev/null 2>&1; then
        PS_NGINX_BIN=$(nginx -v 2>&1)
    else
        PS_NGINX_BIN=""
    fi
    if [ $(ps -ef | grep nginx | grep -v grep | grep "/usr/bin/nginx" | wc -l) -gt 0 ];then
        PS_NGINX_BIN="/usr/bin/nginx"
    elif [ $(ps -ef | grep nginx | grep -v grep | grep "/usr/sbin/nginx" | wc -l) -gt 0 ];then
        PS_NGINX_BIN="/usr/sbin/nginx"
    elif [ $(ps -ef | grep nginx | grep -v grep | grep "/www/server/nginx/sbin/nginx" | wc -l) -gt 0 ];then
        PS_NGINX_BIN="/www/server/nginx/sbin/nginx"
    fi

    echo "Nginx PATH: $PS_NGINX_BIN"
	echo "========【NGINX VESION】==========="
	$PS_NGINX_BIN -v
	echo "===================================="
    $PS_NGINX_BIN -v > $PATH_WAF/install_success 2>&1
    echo "安装完成"

}


update_safewaf(){

    echo "开始更新";
    # 检查当前启动的nginx进程
    PS_NGINX_BIN=""
    if command -v nginx >/dev/null 2>&1; then
        PS_NGINX_BIN=$(nginx -v 2>&1)
    else
        PS_NGINX_BIN=""
    fi
    if [ $(ps -ef | grep nginx | grep -v grep | grep "/usr/bin/nginx" | wc -l) -gt 0 ];then
        PS_NGINX_BIN="/usr/bin/nginx"
    elif [ $(ps -ef | grep nginx | grep -v grep | grep "/usr/sbin/nginx" | wc -l) -gt 0 ];then
        PS_NGINX_BIN="/usr/sbin/nginx"
    elif [ $(ps -ef | grep nginx | grep -v grep | grep "/www/server/nginx/sbin/nginx" | wc -l) -gt 0 ];then
        PS_NGINX_BIN="/www/server/nginx/sbin/nginx"
    fi

    echo "Nginx PATH: $PS_NGINX_BIN"
    $PS_NGINX_BIN -v > $PATH_WAF/install_success_new 2>&1
    if [ "$(cat $PATH_WAF/install_success_new)" != "$(cat $PATH_WAF/install_success)" ];then
        echo "nginx版本不一致"
        echo "========【NGINX OLD VESION】==========="
        cat $PATH_WAF/install_success
        echo "========【NGINX NEW VESION】==========="
        $PS_NGINX_BIN -v
        echo "======================================="
        if [ "$BENDI" -eq 0 ]; then
            # 安装依赖
            if command -v yum &>/dev/null; then
                # CentOS/RHEL 系统（yum）
                yum install -y gcc gcc-c++ readline-devel net-tools unzip sqlite-devel
            elif command -v apt &>/dev/null; then
                # Debian/Ubuntu 系统（apt）
                apt install -y gcc g++ libreadline-dev net-tools unzip libsqlite3-dev libncurses5-dev
            else
                echo "错误：仅支持 yum/apt 包管理器的系统！"
                exit 1
            fi

            Install_lua515
            Install_luajit
            Install_cjson
            Install_sqlite3
        fi

        $PS_NGINX_BIN -v > $PATH_WAF/install_success 2>&1
    fi
    rm -rf $PATH_WAF/install_success_new

    cd $PATH_INSTALL_WAF

    # 更新文件夹
    \cp -a -r lua/html/* $PATH_WAF_LUA/html/
    \cp -a -r lua/i18n/* $PATH_WAF_LUA/i18n/
    \cp -a -r lua/plugin/* $PATH_WAF_LUA/plugin/
    \cp -a -r lua/utils/* $PATH_WAF_LUA/utils/
    \cp -a -r lua/shell/* $PATH_WAF_LUA/shell/

    # 更新文件
    \cp -a -r lua/ext/ip.dat $PATH_WAF_LUA/ext/ip.dat
    \cp -a -r lua/exc/waf_nday.json $PATH_WAF_LUA/exc/waf_nday.json
    \cp -a -r lua/exc/waf_nday_en.json $PATH_WAF_LUA/exc/waf_nday_en.json
    \cp -a -r lua/exc/reg_en.json $PATH_WAF_LUA/exc/reg_en.json

    # 更新配置文件
    \cp -a -r lua/load.lua $PATH_WAF_LUA/load.lua
    \cp -a -r lua/start.lua $PATH_WAF_LUA/start.lua
    \cp -a -r lua/hook_header.lua $PATH_WAF_LUA/hook_header.lua
    \cp -a -r lua/hook_body.lua $PATH_WAF_LUA/hook_body.lua

    \cp -a -r env/ngx_lua/* $PATH_WAF_ENV/ngx_lua/

    # 兼容ngx_resty
	if [ -f  /www/server/nginx/lib/lua/ngx ];then
		\cp -a -r /www/server/nginx/lib/lua/ngx /usr/local/share/lua/5.1/
		\cp -a -r /www/server/nginx/lib/lua/ngx $PATH_WAF_LUA/
	fi
	if [ -f  /www/server/nginx/lib/lua/resty ];then
		\cp -a -r /www/server/nginx/lib/lua/resty /usr/local/share/lua/5.1/
		\cp -a -r /www/server/nginx/lib/lua/resty $PATH_WAF_LUA/
	fi

    # 配置文件权限
    chmod 777 -R $PATH_WAF_LUA

    if [ -f /etc/init.d/nginx ];then
        if [ -x /etc/init.d/nginx ]; then
	        /etc/init.d/nginx restart
        else
            systemctl restart nginx
        fi
    else
        systemctl restart nginx
    fi

    mkdir -p $PATH_WAF_ENV
    \cp -a -r VERSION $PATH_WAF/VERSION
    echo '更新完成'

}

if [ "${1}" == '' ];then
	Install_safewaf
elif [ "${1}" == 'install' ];then
	Install_safewaf
elif  [ "${1}" == 'update' ];then
	update_safewaf
fi
