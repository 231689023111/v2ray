#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

work_dir="$(
    cd "$(dirname "$0")" || exit
    pwd
)"
cd ${work_dir} || exit

#fonts color
Green="\033[32m"
Red="\033[31m"
# Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

#notification information
# Info="${Green}[信息]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"

shell_version="1.0.0"
v2ray_package_name="v2ray-${shell_version}.zip"
v2ray_bin_dir="/home/run_bin"
v2ray_conf="${v2ray_bin_dir}/config.json"
nginx_dir="/etc/nginx"
nginx_conf_dir="/etc/nginx/conf/conf.d"
nginx_conf="${nginx_conf_dir}/v2ray.conf"
nginx_openssl_src="/usr/local/src"
nginx_systemd_file="/etc/systemd/system/nginx.service"
ssl_update_file="/usr/bin/ssl_update.sh"
domain_file="${v2ray_bin_dir}/domain.info"
nginx_version="1.18.0"
openssl_version="1.1.1g"
jemalloc_version="5.2.1"

source '/etc/os-release'

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
#        $INS update
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
#        $INS update
    else
        echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断 ${Font}"
        exit 1
    fi

#    $INS -y install dbus

#    systemctl stop firewalld
#    systemctl disable firewalld
#    echo -e "${OK} ${GreenBG} firewalld 已关闭 ${Font}"

#    systemctl stop ufw
#    systemctl disable ufw
#    echo -e "${OK} ${GreenBG} ufw 已关闭 ${Font}"
}

is_root() {
    if [ 0 == $UID ]; then
        echo -e "${OK} ${GreenBG} 当前用户是root用户，进入安装流程 ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} 当前用户不是root用户，请切换到root用户后重新执行脚本 ${Font}"
        exit 1
    fi
}

judge() {
    if [[ 0 -eq $? ]]; then
        echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 失败${Font}"
        exit 1
    fi
}

dependency_install() {
    ${INS} install -y wget unzip psmisc

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install crontabs
    else
        ${INS} -y install cron
    fi

    if [[ "${ID}" == "centos" ]]; then
	    if [[ ! -f /var/spool/cron/root ]]; then
            touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
		fi
        systemctl start crond && systemctl enable crond
    else
	    if [[ ! -f /var/spool/cron/crontabs/root ]]; then
            touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
		fi
        systemctl start cron && systemctl enable cron
    fi

	if [[ "$1" == "nginx" ]]; then
	    ${INS} install -y git lsof bc curl

        if [[ "${ID}" == "centos" ]]; then
            ${INS} -y groupinstall "Development tools"
        else
            ${INS} -y install build-essential
        fi
        judge "编译工具包 安装"

        if [[ "${ID}" == "centos" ]]; then
            ${INS} -y install pcre pcre-devel zlib-devel epel-release
        else
            ${INS} -y install libpcre3 libpcre3-dev zlib1g-dev
        fi

        ${INS} -y install haveged
	    systemctl start haveged && systemctl enable haveged
	fi
}

basic_optimization() {
    # 最大文件打开数
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf

    # 关闭 Selinux
    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi
}

port_alterid_set() {
	stty erase '^H' && read -rp "请输入WS连接端口，该端口必须在所有安装机器上保持一致（default: 33133）:" wsport
	[[ -z ${wsport} ]] && wsport="33133"
	stty erase '^H' && read -rp "请输入TCP连接端口，该端口必须在所有安装机器上保持一致（default: 33134）:" tcpport
	[[ -z ${tcpport} ]] && tcpport="33134"
	stty erase '^H' && read -rp "请输入alterID，该ID必须在所有安装机器上保持一致（default:64 仅允许填数字）:" alterID
	[[ -z ${alterID} ]] && alterID="64"
	stty erase '^H' && read -rp "请输入UUID，该UUID必须在所有安装机器上保持一致（默认不修改，使用配置文件自带的UUID）:" UUID
}

port_alterid_set_nginx() {
	stty erase '^H' && read -rp "请输入nginx的WS连接端口，该端口必须在所有安装机器上保持一致（default: 443）:" wsport
	[[ -z ${wsport} ]] && wsport="443"
	stty erase '^H' && read -rp "请输入nginx的TCP连接端口，该端口必须在所有安装机器上保持一致（default: 4433）:" tcpport
	[[ -z ${tcpport} ]] && tcpport="4433"
	stty erase '^H' && read -rp "请输入alterID，该ID必须在所有安装机器上保持一致（default:64 仅允许填数字）:" alterID
	[[ -z ${alterID} ]] && alterID="64"
	stty erase '^H' && read -rp "请输入UUID，该UUID必须在所有安装机器上保持一致（默认不修改，使用配置文件自带的UUID）:" UUID
}

dynamicport_set() {
	stty erase '^H' && read -rp "请输入动态端口刷新时间，单位分钟（default: 5）:" refresh
	[[ -z ${refresh} ]] && refresh=5
	stty erase '^H' && read -rp "请输入动态端口同时监听个数（default: 2）:" concurrency
	[[ -z ${concurrency} ]] && concurrency=2
	stty erase '^H' && read -rp "请输入WS连接的动态端口范围，至少为同时监听个数的3倍（default: 33200-33205）:" dy_wsport
	[[ -z ${dy_wsport} ]] && dy_wsport="33200-33205"
	stty erase '^H' && read -rp "请输入TCP连接的动态端口范围，至少为同时监听个数的3倍（default: 33300-33305）:" dy_tcpport
	[[ -z ${dy_tcpport} ]] && dy_tcpport="33300-33305"
}

modify_alterid() {
    sed -i "/\"alterId\"/c \            \"alterId\": ${alterID}," ${v2ray_conf}
    judge "V2Ray alterid 修改"
}

modify_inbound_port() {
    sed -i "/\"port\": 33133/c \      \"port\": ${wsport}," ${v2ray_conf}
    sed -i "/\"port\": 33134/c \      \"port\": ${tcpport}," ${v2ray_conf}
	
    judge "V2Ray inbound_port 修改"
}

modify_UUID() {
    [[ -z ${UUID} ]] && return
    sed -i "/\"id\"/c \            \"id\": \"${UUID}\"," ${v2ray_conf}
    judge "V2Ray UUID 修改"
}

modify_path() {
    sed -i "/\"path\"/c \        \"path\": \"${camouflage}\"" ${v2ray_conf}
    judge "V2Ray 伪装路径 修改"
}

modify_icmp_capture_info() {
    sed -i "/\"iface\"/c \    \"iface\": \"${iface}\"," ${v2ray_conf}
	sed -i "/\"address\"/c \    \"address\": \"${ipaddr}\"," ${v2ray_conf}
	sed -i "/\"ifaceIp\"/c \    \"ifaceIp\": \"${ipaddr}\"," ${v2ray_conf}
	sed -i "/\"ifaceMask\"/c \    \"ifaceMask\": \"${ifaceMask}\"" ${v2ray_conf}
}

modify_dynamicport() {
    sed -i "/\"port\": \"33200-33205\"/c \      \"port\": \"${dy_wsport}\"," ${v2ray_conf}
	sed -i "/\"port\": \"33300-33305\"/c \      \"port\": \"${dy_tcpport}\"," ${v2ray_conf}
	sed -i "/\"refresh\"/c \        \"refresh\": ${refresh}," ${v2ray_conf}
	sed -i "/\"concurrency\"/c \        \"concurrency\": ${concurrency}" ${v2ray_conf}
}

get_netcard_info() {
    nets=`ip route | grep "default.*dev" | awk -F'dev' '{print $2}' | awk -F' ' '{print $1}'`

	for one_net in ${nets[@]}; do
		datas=`ifconfig ${one_net}`
		if [ -z "${datas}" ]; then
			continue
		fi
		iface=`echo ${one_net}`
		ipaddr=`ifconfig ${one_net} | grep -o -E 'inet addr:[0-9.]+' | awk -F':' '{print $2}'`
		if [ -z "${ipaddr}" ]; then
			ipaddr=`ifconfig ${one_net} | grep -o -E 'inet [0-9.]+' | awk -F' ' '{print $2}'`
		fi
		if [ -z "${ipaddr}" ]; then
			echo -e "${Error} ${RedBG} 获取${iface}的IP地址失败 ${Font}"
			continue
		fi
		ifaceMask=`ifconfig ${one_net} | grep -o -E 'Mask:[0-9.]+' | awk -F':' '{print $2}'`
		if [ -z "${ifaceMask}" ]; then
			ifaceMask=`ifconfig ${one_net} | grep -o -E 'Mask [0-9.]+' | awk -F' ' '{print $2}'`
		fi
		if [ -z "${ifaceMask}" ]; then
			ifaceMask=`ifconfig ${one_net} | grep -o -E 'netmask [0-9.]+' | awk -F' ' '{print $2}'`
		fi
		
		if [ -z "${ifaceMask}" ]; then
			echo -e "${Error} ${RedBG} 获取${iface}的子网掩码失败 ${Font}"
			continue
		fi
	done
	if [ -z "${iface}" ]; then
		iface="eth0"
	fi
	if [ -z "${ipaddr}" ]; then
		ipaddr="127.0.0.1"
	fi
	if [ -z "${ifaceMask}" ]; then
		ifaceMask="255.255.255.0"
	fi

	echo -e "${Green} 网卡信息:${iface} ${ipaddr} ${ifaceMask} ${Font}"
}

install_v2ray_core() {
	get_netcard_info
	
	ps_num=`ps -ef | grep v2ray | grep -v grep | wc -l`
	if [ $ps_num -gt 0 ]; then
		killall v2ray
	fi
	
	rm -rf /home/run_bin > /dev/null
	if [ ! -e "/home/run_bin" ]; then
        mkdir -p /home/run_bin
	fi
	if [ ! -d "/home/run_bin" ]; then
		rm -rf /home/run_bin
		mkdir -p /home/run_bin
	fi
	
	wget -N -O v2ray-rocker.zip https://github.com/231689023111/v2ray/raw/master/v2ray-${shell_version}.zip
	unzip -o -d /home/run_bin v2ray-rocker.zip

	mkdir -p /home/run_bin/log
	
	rm -f /etc/ld.so.conf.d/v2ray.conf >> /dev/null && ldconfig
	ldconfig -p | grep libpcap.so.1 >> /dev/null && ldconfig -p | grep libnl-3.so.200 >> /dev/null && ldconfig -p | grep libnl-genl-3.so.200 >> /dev/null
	if [ $? -eq 1 ];then
		touch /etc/ld.so.conf.d/v2ray.conf
		cat >/etc/ld.so.conf.d/v2ray.conf <<EOF
/home/run_bin/lib
EOF
        ldconfig
	else
	    rm -rf /home/run_bin/lib
    fi
	
	mkdir -p /home/run_bin/script
	touch /home/run_bin/script/monitor.sh
	cat >/home/run_bin/script/monitor.sh <<EOF
#!/bin/bash

if [ \$# -eq 0 ]; then
    echo "###################"
    echo "invalid para,usage:"
    echo "-r: run project"
    echo "-k: kill project"
    echo "###################"
fi

ps_num=\`ps -ef | grep v2ray | grep -v grep | wc -l\`
if [ \$ps_num -lt 1 -a "\$1" == "-r" ]; then
    nohup /home/run_bin/v2ray -config /home/run_bin/config.json 1>/dev/null 2>&1 &
    timenew=\`date\`
    echo "\$timenew: Run /home/v2ray"
fi

if [ \$ps_num -gt 0 -a "\$1" == "-k" ]; then
    killall v2ray
    timenew=\`date\`
    echo "\$timenew: Kill /home/v2ray"
fi
EOF

    touch /home/run_bin/cron.tab
    cat >/home/run_bin/cron.tab <<EOF
1-59/1 * * * * /home/run_bin/script/monitor.sh -r >>/home/run_bin/log/login.txt
EOF

	chmod -R 755 /home/run_bin
	chmod +x /home/run_bin/v2ray
	chmod +x /home/run_bin/v2ctl

	crontab -uroot /home/run_bin/cron.tab
	
	if [ "$1" == "ws" ]; then
        mv -f /home/run_bin/config-vps.json ${v2ray_conf}
	elif [ "$1" == "dynamicport" ]; then
	    mv -f /home/run_bin/config-vps-dynamicport.json ${v2ray_conf}
	elif [ "$1" == "nginx" ]; then
	    mv -f /home/run_bin/config-vps-ws-tls-nginx.json ${v2ray_conf}
		touch ${domain_file}
		echo ${domain} > ${domain_file}
	else
	    echo "nothing to do."
	fi

	rm -f v2ray-rocker.zip
	rm -f /home/run_bin/cron.tab
	rm -f /home/run_bin/config-vps.json
	rm -f /home/run_bin/config-vps-dynamicport.json
	rm -f /home/run_bin/config-vps-ws-tls-nginx.json
}

start_v2ray() {
    /home/run_bin/script/monitor.sh -r >>/home/run_bin/log/login.txt
}

domain_check() {
    read -rp "请输入你的域名信息(eg:www.wulabing.com):" domain
    domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    echo -e "${OK} ${GreenBG} 正在获取 公网ip 信息，请耐心等待 ${Font}"
    local_ip=$(curl -4 ip.sb)
    echo -e "域名dns解析IP：${domain_ip}"
    echo -e "本机IP: ${local_ip}"
    sleep 2
    if [[ $(echo "${local_ip}" | tr '.' '+' | bc) -eq $(echo "${domain_ip}" | tr '.' '+' | bc) ]]; then
        echo -e "${OK} ${GreenBG} 域名dns解析IP 与 本机IP 匹配 ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} 请确保域名添加了正确的 A 记录，否则将无法正常使用 V2Ray ${Font}"
        echo -e "${Error} ${RedBG} 域名dns解析IP 与 本机IP 不匹配 是否继续安装？（y/n）${Font}" && read -r install
        case $install in
        [yY][eE][sS] | [yY])
            echo -e "${GreenBG} 继续安装 ${Font}"
            sleep 2
            ;;
        *)
            echo -e "${RedBG} 安装终止 ${Font}"
            exit 2
            ;;
        esac
    fi
}

camouflage_set() {
    stty erase '^H' && read -rp "请输入WebSocket伪装路径，该路径必须在所有安装机器上保持一致（default：\"/rocker\"）:" camouflage
    [[ -z ${camouflage} ]] && camouflage="/rocker"
}

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        echo -e "${OK} ${GreenBG} $1 端口未被占用 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} 检测到 $1 端口被占用，以下为 $1 端口占用信息 ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} 5s 后将尝试自动 kill 占用进程 ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill 完成 ${Font}"
        sleep 1
    fi
}

nginx_exist_check() {
    if [[ -f "/etc/nginx/sbin/nginx" ]]; then
        echo -e "${OK} ${GreenBG} Nginx已存在，跳过编译安装过程 ${Font}"
        sleep 2
    elif [[ -d "/usr/local/nginx/" ]]; then
        echo -e "${OK} ${GreenBG} 检测到其他套件安装的Nginx，继续安装会造成冲突，请处理后安装${Font}"
        exit 1
    else
        nginx_install
    fi
}

nginx_install() {
    wget -nc --no-check-certificate http://nginx.org/download/nginx-${nginx_version}.tar.gz -P ${nginx_openssl_src}
    judge "nginx 下载"
    wget -nc --no-check-certificate https://www.openssl.org/source/openssl-${openssl_version}.tar.gz -P ${nginx_openssl_src}
    judge "openssl 下载"
    wget -nc --no-check-certificate https://github.com/jemalloc/jemalloc/releases/download/${jemalloc_version}/jemalloc-${jemalloc_version}.tar.bz2 -P ${nginx_openssl_src}
    judge "jemalloc 下载"

    cd ${nginx_openssl_src} || exit

    [[ -d nginx-"$nginx_version" ]] && rm -rf nginx-"$nginx_version"
    tar -zxvf nginx-"$nginx_version".tar.gz

    [[ -d openssl-"$openssl_version" ]] && rm -rf openssl-"$openssl_version"
    tar -zxvf openssl-"$openssl_version".tar.gz

    [[ -d jemalloc-"${jemalloc_version}" ]] && rm -rf jemalloc-"${jemalloc_version}"
    tar -xvf jemalloc-"${jemalloc_version}".tar.bz2

    [[ -d "$nginx_dir" ]] && rm -rf ${nginx_dir}

    echo -e "${OK} ${GreenBG} 即将开始编译安装 jemalloc ${Font}"
    sleep 2

    cd jemalloc-${jemalloc_version} || exit
    ./configure
    judge "编译检查"
    make && make install
    judge "jemalloc 编译安装"
    echo '/usr/local/lib' >/etc/ld.so.conf.d/local.conf
    ldconfig

    echo -e "${OK} ${GreenBG} 即将开始编译安装 Nginx, 过程稍久，请耐心等待 ${Font}"
    sleep 4

    cd ../nginx-${nginx_version} || exit

    ./configure --prefix="${nginx_dir}" \
        --with-http_ssl_module \
        --with-http_gzip_static_module \
        --with-http_stub_status_module \
        --with-pcre \
        --with-http_realip_module \
        --with-http_flv_module \
        --with-http_mp4_module \
        --with-http_secure_link_module \
        --with-http_v2_module \
        --with-cc-opt='-O3' \
        --with-ld-opt="-ljemalloc" \
        --with-openssl=../openssl-"$openssl_version"
    judge "编译检查"
    make && make install
    judge "Nginx 编译安装"

    # 修改基本配置
    sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/worker_processes  1;/worker_processes  3;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/    worker_connections  1024;/    worker_connections  8092;/' ${nginx_dir}/conf/nginx.conf
    sed -i '$i include conf.d/*.conf;' ${nginx_dir}/conf/nginx.conf

    # 删除临时文件
    rm -rf ../nginx-"${nginx_version}"
    rm -rf ../openssl-"${openssl_version}"
    rm -rf ../nginx-"${nginx_version}".tar.gz
    rm -rf ../openssl-"${openssl_version}".tar.gz

    # 添加配置文件夹，适配旧版脚本
    mkdir ${nginx_dir}/conf/conf.d
	
	cd ${work_dir} || exit
}

nginx_conf_add() {
    touch ${nginx_conf_dir}/v2ray.conf
    cat >${nginx_conf_dir}/v2ray.conf <<EOF
server {
    listen 443 ssl http2;
    ssl_certificate       /data/v2ray.crt;
    ssl_certificate_key   /data/v2ray.key;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_session_tickets off;

    ssl_protocols         TLSv1.3;
    ssl_ciphers           TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;

    index index.html index.htm;
    root  /home/wwwroot/3DCEList;
    error_page 400 = /400.html;

    server_name www.silence.com;
    location /ray
    {
        if (\$http_upgrade != "websocket") {
            return 404;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:33133;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}

server {
    listen 4433 ssl;
    ssl_certificate       /data/v2ray.crt;
    ssl_certificate_key   /data/v2ray.key;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_session_tickets off;

    ssl_protocols         TLSv1.3;
    ssl_ciphers           TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;

    index index.html index.htm;
    root  /home/wwwroot/3DCEList;
    error_page 400 = /400.html;

    server_name www.silence.com;
    location /ray
    {
        if (\$http_upgrade != "websocket") {
            return 404;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:33134;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}

server {
    listen 80;
    server_name serveraddr.com;
    return 301 https://use.shadowsocksr.win\$request_uri;
}
EOF

    modify_nginx_port
    modify_nginx_other
    judge "Nginx 配置修改"

}

modify_nginx_port() {
    sed -i "/ssl http2;$/c \    listen ${wsport} ssl http2;" ${nginx_conf}
	sed -i "/ssl;$/c \    listen ${tcpport} ssl;" ${nginx_conf}
}

modify_nginx_other() {
    sed -i "/server_name/c \    server_name ${domain};" ${nginx_conf}
    sed -i "/location/c \    location ${camouflage}" ${nginx_conf}
    #sed -i "/proxy_pass/c \\\tproxy_pass http://127.0.0.1:${PORT};" ${nginx_conf}
    sed -i "/return 301/c \    return 301 https://${domain}\$request_uri;" ${nginx_conf}
    #sed -i "27i \\\tproxy_intercept_errors on;"  ${nginx_dir}/conf/nginx.conf
}

web_camouflage() {
	#请注意 这里和LNMP脚本的默认路径冲突，千万不要在安装了LNMP的环境下使用本脚本，否则后果自负
    rm -rf /home/wwwroot
    mkdir -p /home/wwwroot
    cd /home/wwwroot || exit
    git clone https://github.com/wulabing/3DCEList.git
    judge "web 站点伪装"
	cd ${work_dir} || exit
}

ssl_judge_and_install() {
    if [[ -f "/data/v2ray.key" || -f "/data/v2ray.crt" ]]; then
        echo "/data 目录下证书文件已存在"
        echo -e "${OK} ${GreenBG} 是否删除 [Y/N]? ${Font}"
        read -r ssl_delete
        case $ssl_delete in
        [yY][eE][sS] | [yY])
            rm -rf /data/*
            echo -e "${OK} ${GreenBG} 已删除 ${Font}"
            ;;
        *) ;;

        esac
    fi

    if [[ -f "/data/v2ray.key" || -f "/data/v2ray.crt" ]]; then
        echo "证书文件已存在"
    elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
        echo "证书文件已存在"
        "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
        judge "证书应用"
    else
        ssl_install
        acme
    fi
}

ssl_install() {
    if [[ "${ID}" == "centos" ]]; then
        ${INS} install socat nc -y
    else
        ${INS} install socat netcat -y
    fi
    judge "安装 SSL 证书生成脚本依赖"

    curl https://get.acme.sh | sh
    judge "安装 SSL 证书生成脚本"
}

acme() {
    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force --test; then
        echo -e "${OK} ${GreenBG} SSL 证书测试签发成功，开始正式签发 ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        sleep 2
    else
        echo -e "${Error} ${RedBG} SSL 证书测试签发失败 ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi

    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "${OK} ${GreenBG} SSL 证书生成成功 ${Font}"
        sleep 2
        mkdir /data
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc --force; then
            echo -e "${OK} ${GreenBG} 证书配置成功 ${Font}"
            sleep 2
        fi
    else
        echo -e "${Error} ${RedBG} SSL 证书生成失败 ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi
}

nginx_systemd() {
    cat >$nginx_systemd_file <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/etc/nginx/sbin/nginx -t
ExecStart=/etc/nginx/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    judge "Nginx systemd ServerFile 添加"
    systemctl daemon-reload
}

tls_type() {
    if [[ -f "/etc/nginx/sbin/nginx" ]] && [[ -f "$nginx_conf" ]]; then
        echo "请选择支持的 TLS 版本（default:3）:"
        echo "请注意,如果你使用 Quantumult X / 路由器 / 旧版 Shadowrocket / 低于 4.18.1 版本的 V2ray core 请选择 兼容模式"
        echo "1: TLS1.1 TLS1.2 and TLS1.3（兼容模式）"
        echo "2: TLS1.2 and TLS1.3 (兼容模式)"
        echo "3: TLS1.3 only"
        read -rp "请输入：" tls_version
        [[ -z ${tls_version} ]] && tls_version=3
        if [[ $tls_version == 3 ]]; then
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.3 only ${Font}"
        elif [[ $tls_version == 1 ]]; then
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.1 TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.1 TLS1.2 and TLS1.3 ${Font}"
        else
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.2 and TLS1.3 ${Font}"
        fi
        systemctl restart nginx
        judge "Nginx 重启"
    else
        echo -e "${Error} ${RedBG} Nginx 或 配置文件不存在，请正确安装脚本后执行${Font}"
    fi
}

enable_process_systemd() {
    systemctl start nginx
    systemctl enable nginx
    judge "设置 Nginx 开机自启"
}

acme_cron_update() {
	rm -f ${ssl_update_file}
	touch ${ssl_update_file}
	chmod 755 ${ssl_update_file}
	cat >${ssl_update_file} <<EOF
#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

domain_info="${domain_file}"
domain=\$(cat \${domain_info})

systemctl stop nginx &> /dev/null
sleep 1
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /dev/null
"/root/.acme.sh"/acme.sh --installcert -d \${domain} --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
sleep 1
systemctl start nginx &> /dev/null
EOF

	if crontab -l | grep "acme.sh" >> /dev/null; then
        if [[ "${ID}" == "centos" ]]; then
            sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file} > /dev/null" /var/spool/cron/root
        else
            sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file} > /dev/null" /var/spool/cron/crontabs/root
        fi
	else
	    crontab -l | {
            cat
            echo "0 3 * * 0 bash ${ssl_update_file} > /dev/null"
        } | crontab -
	fi
    judge "cron 计划任务更新"
}

v2ray_conf_add_ws() {
    modify_alterid
	modify_inbound_port
	modify_UUID
	modify_icmp_capture_info
}

v2ray_conf_add_nginx_tls_ws() {
    modify_alterid
	modify_UUID
	modify_path
	modify_icmp_capture_info
}

install_v2ray_vmess_ws() {
	is_root
	check_system
	dependency_install
	port_alterid_set
	install_v2ray_core "ws"
	v2ray_conf_add_ws
	port_exist_check "${tcpport}"
	port_exist_check "${wsport}"
	start_v2ray
	echo -e "${GreenBG} vmess+ws模式安装成功 ${Font}"
}

install_v2ray_vmess_ws_dynamicport() {
	is_root
	check_system
	dependency_install
	port_alterid_set
	dynamicport_set
	install_v2ray_core "dynamicport"
	v2ray_conf_add_ws
	modify_dynamicport
	port_exist_check "${tcpport}"
	port_exist_check "${wsport}"
	start_v2ray
	echo -e "${GreenBG} vmess+ws+动态端口模式安装成功 ${Font}"
}

install_v2ray_nginx_ws_tls() {
	is_root
	check_system
	dependency_install "nginx"
	basic_optimization
	domain_check
	port_alterid_set_nginx
	camouflage_set
	install_v2ray_core "nginx"
	v2ray_conf_add_nginx_tls_ws
	port_exist_check 80
    port_exist_check "${tcpport}"
	port_exist_check "${wsport}"
	nginx_exist_check
	nginx_conf_add
	web_camouflage
	ssl_judge_and_install
	nginx_systemd
	tls_type
	start_v2ray
	enable_process_systemd
	acme_cron_update
	echo -e "${GreenBG} nginx+ws+tls模式安装成功 ${Font}"
}

install_bbr_bbrplus() {
    is_root
	check_system
    wget -N -O tcp.sh https://raw.githubusercontent.com/231689023111/v2ray/master/tcp.sh && chmod 755 tcp.sh && ./tcp.sh
    #rm -f tcp.sh
	echo -e "${GreenBG} bbr/bbrplus安装成功	${Font}"
}

menu() {
	echo -e "\t V2Ray 安装管理脚本 ${Red}[${shell_version}]${Font}\n"
	echo -e "—————————————— 安装向导 ——————————————"
	echo -e "${Green}1.${Font}  安装 V2Ray (vmess+ws)"
	echo -e "${Green}2.${Font}  安装 V2Ray (vmess+ws+dynamicport)"
	echo -e "${Green}3.${Font}  安装 V2Ray (nginx+ws+tls), 需要预先申请域名"
	echo -e "—————————————— 加速管理 ——————————————"
	echo -e "${Green}4.${Font}  安装 BBR/BBRPlus加速"
	echo -e "—————————————— 其他选项 ——————————————"
	echo -e "${Green}5.${Font} 退出 \n"
	
	stty erase '^H' && read -rp "请输入数字：" menu_num
	case $menu_num in
	1)
	    install_v2ray_vmess_ws
		;;
	2)
	    install_v2ray_vmess_ws_dynamicport
		;;
    3)
	    install_v2ray_nginx_ws_tls
		;;
    4)
	    install_bbr_bbrplus
		;;
    5)
	    exit 0
		;;
	*)
        echo -e "${RedBG}输入的数字不正确，退出安装...${Font}"
        ;;
    esac
}

menu
