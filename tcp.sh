#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS 6/7/8,Debian 8/9/10,ubuntu 16/18/19
#	Description: BBR+BBRplus
#	Version: 1.3.2.24
#	Author: 千影,cx9208,YLX
#   Modyfy: rocker
#	更新内容及反馈:  https://blog.ylx.me/archives/783.html
#=================================================

sh_ver="1.3.2.24"
github="github.000060000.xyz"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

installwget() {
    which wget >> /dev/null
    if [ $? -eq 1 ];then
        yum install -y wget
    fi
}

#安装BBR内核
installbbr(){
	kernel_version="4.11.8"
	bit=`uname -m`
	rm -rf bbr
	mkdir bbr && cd bbr
	
	if [[ "${release}" == "centos" ]]; then
		if [[ ${version} = "6" ]]; then
			if [[ ${bit} = "x86_64" ]]; then
				installwget
				wget -N -O kernel-headers-c6.rpm https://github.com/ylx2016/kernel/releases/download/5.5.5/kernel-headers-5.5.5-1-c6.x86_64.rpm
				wget -N -O kernel-c6.rpm https://github.com/ylx2016/kernel/releases/download/5.5.5/kernel-5.5.5-1-c6.x86_64.rpm
			
				rpm -ivh kernel-c6.rpm --force --nodeps
				rpm -ivh kernel-headers-c6.rpm --force --nodeps
			
				kernel_version="5.5.5"
			else
				echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
			fi
		
		elif [[ ${version} = "7" ]]; then
			if [[ ${bit} = "x86_64" ]]; then
			    installwget
				wget -N -O kernel-headers-c7.rpm https://github.com/ylx2016/kernel/releases/download/5.5.5/kernel-headers-5.5.5-1-c7.x86_64.rpm
				wget -N -O kernel-c7.rpm https://github.com/ylx2016/kernel/releases/download/5.5.5/kernel-5.5.5-1-c7.x86_64.rpm

				rpm -ivh kernel-c7.rpm --force --nodeps
				rpm -ivh kernel-headers-c7.rpm --force --nodeps
			
				kernel_version="5.5.5"
			else
				echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
			fi	
			
		elif [[ ${version} = "8" ]]; then
			installwget
			wget -N -O kernel-c8.rpm https://github.com/ylx2016/kernel/releases/download/5.5.5/kernel-5.5.5-1-c8.x86_64.rpm
			wget -N -O kernel-headers-c8.rpm https://github.com/ylx2016/kernel/releases/download/5.5.5/kernel-headers-5.5.5-1-c8.x86_64.rpm

			rpm -ivh kernel-c8.rpm --force --nodeps
			rpm -ivh kernel-headers-c8.rpm --force --nodeps
			
			kernel_version="5.5.5"
		else
		    echo -e "暂时不支持的系统版本centos ${version}" && exit 1
		fi
	
	elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
		if [[ "${release}" == "debian" ]]; then
			if [[ ${version} = "8" ]]; then
				if [[ ${bit} = "x86_64" ]]; then
					wget -N -O linux-image-d8.deb https://github.com/ylx2016/kernel/releases/download/5.5.5/linux-image-5.5.5_5.5.5-1-d8_amd64.deb
					wget -N -O linux-headers-d8.deb https://github.com/ylx2016/kernel/releases/download/5.5.5/linux-headers-5.5.5_5.5.5-1-d8_amd64.deb
				
					dpkg -i linux-image-d8.deb
					dpkg -i linux-headers-d8.deb
				
					kernel_version="5.5.5"
				else
					echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
				fi
		
			elif [[ ${version} = "9" ]]; then
				if [[ ${bit} = "x86_64" ]]; then
					wget -N -O linux-image-d9.deb https://github.com/ylx2016/kernel/releases/download/5.5.5/linux-image-5.5.5_5.5.5-1-d9_amd64.deb
					wget -N -O linux-headers-d9.deb https://github.com/ylx2016/kernel/releases/download/5.5.5/linux-headers-5.5.5_5.5.5-1-d9_amd64.deb
				
					dpkg -i linux-image-d9.deb
					dpkg -i linux-headers-d9.deb
				
					kernel_version="5.5.5"
				else
					echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
				fi
			elif [[ ${version} = "10" ]]; then
				if [[ ${bit} = "x86_64" ]]; then
					wget -N -O linux-image-d10.deb https://github.com/ylx2016/kernel/releases/download/5.5.5/linux-image-5.5.5_5.5.5-1-d10_amd64.deb
					wget -N -O linux-headers-d10.deb https://github.com/ylx2016/kernel/releases/download/5.5.5/linux-headers-5.5.5_5.5.5-1-d10_amd64.deb
				
					dpkg -i linux-image-d10.deb
					dpkg -i linux-headers-d10.deb
				
					kernel_version="5.5.5"
				else
					echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
				fi
			else
		        echo -e "暂时不支持的系统版本debian ${version}" && exit 1
			fi
		elif [[ "${release}" == "ubuntu" ]]; then
			if [[ ${version} = "16" ]]; then
				if [[ ${bit} = "x86_64" ]]; then
					wget -N -O linux-image-u16.deb https://github.com/ylx2016/kernel/releases/download/5.4.14/linux-image-5.4.14_5.4.14-1-u16_amd64.deb
					wget -N -O linux-headers-u16.deb https://github.com/ylx2016/kernel/releases/download/5.4.14/linux-headers-5.4.14_5.4.14-1-u16_amd64.deb
				
					dpkg -i linux-image-u16.deb
					dpkg -i linux-headers-u16.deb
				
					kernel_version="5.4.14"
				else
					echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
				fi
		
			elif [[ ${version} = "18" ]]; then
				if [[ ${bit} = "x86_64" ]]; then
					wget -N -O linux-image-u18.deb https://github.com/ylx2016/kernel/releases/download/5.4.14/linux-image-5.4.14_5.4.14-1-u18_amd64.deb
					wget -N -O linux-headers-u18.deb https://github.com/ylx2016/kernel/releases/download/5.4.14/linux-headers-5.4.14_5.4.14-1-u18_amd64.deb
				
					dpkg -i linux-image-u18.deb
					dpkg -i linux-headers-u18.deb
				
					kernel_version="5.4.14"
				else
					echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
				fi
			elif [[ ${version} = "19" || ${version} = "20" ]]; then
				if [[ ${bit} = "x86_64" ]]; then
					wget -N -O linux-image-u19.deb https://github.com/ylx2016/kernel/releases/download/5.4.14/linux-headers-5.4.14_5.4.14-1-u19_amd64.deb
					wget -N -O linux-headers-u19.deb https://github.com/ylx2016/kernel/releases/download/5.4.14/linux-image-5.4.14_5.4.14-1-u19_amd64.deb
				
					dpkg -i linux-image-u19.deb
					dpkg -i linux-headers-u19.deb
				
					kernel_version="5.4.14"
				else
					echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
				fi
			else
		        echo -e "暂时不支持的系统版本ubuntu ${version}" && exit 1
			fi				
			
		#else	
		#	wget http://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u10_amd64.deb
		#	wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/linux-headers-${kernel_version}-all.deb
		#	wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/${bit}/linux-headers-${kernel_version}.deb
		#	wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/${bit}/linux-image-${kernel_version}.deb
	
		#	dpkg -i libssl1.0.0_1.0.1t-1+deb8u10_amd64.deb
		#	dpkg -i linux-headers-${kernel_version}-all.deb
		#	dpkg -i linux-headers-${kernel_version}.deb
		#	dpkg -i linux-image-${kernel_version}.deb
		fi
	fi
	
	cd .. && rm -rf bbr	
	
	detele_kernel
	BBR_grub
	echo -e "${Tip} ${Red_font_prefix}请检查上面是否有内核信息，无内核千万别重启${Font_color_suffix}"
	echo -e "${Tip} ${Red_font_prefix}rescue不是正常内核，要排除这个${Font_color_suffix}"
	echo -e "${Tip} 重启VPS后，请重新运行脚本开启${Red_font_prefix}BBR${Font_color_suffix}"	
	stty erase '^H' && read -p "需要重启VPS后，才能开启BBR，是否现在重启 ? [Y/n] :" yn
	[ -z "${yn}" ] && yn="y"
	if [[ $yn == [Yy] ]]; then
		echo -e "${Info} VPS 重启中..."
		reboot
	fi
	#echo -e "${Tip} 内核安装完毕，请参考上面的信息检查是否安装成功及手动调整内核启动顺序"
}

#安装BBRplus内核 4.14.129
installbbrplus(){
	kernel_version="4.14.160-bbrplus"
	bit=`uname -m`
	rm -rf bbrplus
	mkdir bbrplus && cd bbrplus
	if [[ "${release}" == "centos" ]]; then
		if [[ ${version} = "6" ]]; then
			if [[ ${bit} = "x86_64" ]]; then
			    installwget
				wget -N -O kernel-headers-c6.rpm https://github.com/ylx2016/kernel/releases/download/4.14.168bbrplus/kernel-headers-4.14.168_bbrplus-1-c6.x86_64.rpm
				wget -N -O kernel-c6.rpm https://github.com/ylx2016/kernel/releases/download/4.14.168bbrplus/kernel-4.14.168_bbrplus-1-c6.x86_64.rpm
			
				rpm -ivh kernel-c6.rpm --force --nodeps
				rpm -ivh kernel-headers-c6.rpm --force --nodeps
			
				kernel_version="4.14.168_bbrplus"
			else
				echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
			fi
		
		elif [[ ${version} = "7" ]]; then
			if [[ ${bit} = "x86_64" ]]; then
			    installwget
				wget -N -O kernel-headers-c7.rpm https://github.com/cx9208/Linux-NetSpeed/raw/master/bbrplus/centos/7/kernel-headers-4.14.129-bbrplus.rpm
				wget -N -O kernel-c7.rpm https://github.com/cx9208/Linux-NetSpeed/raw/master/bbrplus/centos/7/kernel-4.14.129-bbrplus.rpm
				
				rpm -ivh kernel-c7.rpm --force --nodeps
				rpm -ivh kernel-headers-c7.rpm --force --nodeps
				
				kernel_version="4.14.129_bbrplus"
			else
				echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
			fi
			
		elif [[ ${version} = "8" ]]; then
		    if [[ ${bit} = "x86_64" ]]; then
			    installwget
			    wget -N -O kernel-headers-c8.rpm https://github.com/ylx2016/kernel/releases/download/4.14.168bbrplus/kernel-headers-4.14.168_bbrplus-1-c8.x86_64.rpm
			    wget -N -O kernel-c8.rpm https://github.com/ylx2016/kernel/releases/download/4.14.168bbrplus/kernel-4.14.168_bbrplus-1-c8.x86_64.rpm

			    rpm -ivh kernel-c8.rpm --force --nodeps
			    rpm -ivh kernel-headers-c8.rpm --force --nodeps
			
			    kernel_version="4.14.168_bbrplus"
			else
				echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
			fi
		else
		    echo -e "暂时不支持的系统版本centos ${version}" && exit 1
		fi	
		
	elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
		wget -N -O linux-headers.deb https://github.com/cx9208/Linux-NetSpeed/raw/master/bbrplus/debian-ubuntu/x64/linux-headers-4.14.129-bbrplus.deb
		wget -N -O linux-image.deb https://github.com/cx9208/Linux-NetSpeed/raw/master/bbrplus/debian-ubuntu/x64/linux-image-4.14.129-bbrplus.deb
		
		dpkg -i linux-image.deb
		dpkg -i linux-headers.deb
			
		kernel_version="4.14.129-bbrplus"
	fi
	
	cd .. && rm -rf bbrplus
	detele_kernel
	BBR_grub
	echo -e "${Tip} ${Red_font_prefix}请检查上面是否有内核信息，无内核千万别重启${Font_color_suffix}"
	echo -e "${Tip} ${Red_font_prefix}rescue不是正常内核，要排除这个${Font_color_suffix}"
	echo -e "${Tip} 重启VPS后，请重新运行脚本开启${Red_font_prefix}BBRplus${Font_color_suffix}"
	stty erase '^H' && read -p "需要重启VPS后，才能开启BBRplus，是否现在重启 ? [Y/n] :" yn
	[ -z "${yn}" ] && yn="y"
	if [[ $yn == [Yy] ]]; then
		echo -e "${Info} VPS 重启中..."
		reboot
	fi
	#echo -e "${Tip} 内核安装完毕，请参考上面的信息检查是否安装成功及手动调整内核启动顺序"
}

#安装bbrplus 新内核
installbbrplusnew(){
	kernel_version="4.14.173-bbrplus"
	bit=`uname -m`
	rm -rf bbrplusnew
	mkdir bbrplusnew && cd bbrplusnew
	if [[ "${release}" == "centos" ]]; then
		if [[ ${version} = "7" ]]; then
			if [[ ${bit} = "x86_64" ]]; then
				installwget
				wget -N -O kernel-c7.rpm https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EWu6fCx32KxEvBrWqe5pZbAB6Y13ogTMfMfPnQWzfQpmiQ?download=1
				wget -N -O kernel-headers-c7.rpm https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EZVCeWQA8rdMrNMysFO2V_0BJWB6Mlrc-IzLD_Xni4HuTQ?download=1
				
				yum install -y kernel-c7.rpm
				yum install -y kernel-headers-c7.rpm
			
				kernel_version="4.14.173_bbrplus"
			else
				echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
			fi
		fi
	elif [[ "${release}" == "debian" ]]; then
		if [[ ${version} = "10" ]]; then
			if [[ ${bit} = "x86_64" ]]; then
				wget -N -O linux-headers-d10.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/ERSKfg1XkUJImM9fWZ3N8WwB3ygLGBzAT3-2Qf37UOokcw?download=1
				wget -N -O linux-image-d10.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EeSISwYaxadNr81olVZh_usBHwvnt0J6W__-4nV-AKY9HQ?download=1
					
				dpkg -i linux-image-d10.deb
				dpkg -i linux-headers-d10.deb
				
				kernel_version="4.14.173-bbrplus"
			else
				echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
			fi		
		fi			
	fi

	cd .. && rm -rf bbrplusnew
	detele_kernel
	BBR_grub
	echo -e "${Tip} ${Red_font_prefix}请检查上面是否有内核信息，无内核千万别重启${Font_color_suffix}"
	echo -e "${Tip} ${Red_font_prefix}rescue不是正常内核，要排除这个${Font_color_suffix}"
	echo -e "${Tip} 重启VPS后，请重新运行脚本开启${Red_font_prefix}BBRplus${Font_color_suffix}"
	stty erase '^H' && read -p "需要重启VPS后，才能开启BBRplus，是否现在重启 ? [Y/n] :" yn
	[ -z "${yn}" ] && yn="y"
	if [[ $yn == [Yy] ]]; then
		echo -e "${Info} VPS 重启中..."
		reboot
	fi
	#echo -e "${Tip} 内核安装完毕，请参考上面的信息检查是否安装成功及手动调整内核启动顺序"

}

#启用BBR+fq
startbbrfq(){
	remove_all
	echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
	sysctl -p
	echo -e "${Info}BBR+FQ启动成功！"
}

#启用BBRplus
startbbrplus(){
	remove_all
	echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbrplus" >> /etc/sysctl.conf
	sysctl -p
	echo -e "${Info}BBRplus启动成功！"
}

#卸载全部加速
remove_all(){
	rm -rf bbrmod
	sed -i '/net.ipv4.tcp_retries2/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_slow_start_after_idle/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.conf
	sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/fs.file-max/d' /etc/sysctl.conf
	sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
	sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
	sed -i '/net.core.rmem_default/d' /etc/sysctl.conf
	sed -i '/net.core.wmem_default/d' /etc/sysctl.conf
	sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
	sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_tw_recycle/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_keepalive_time/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
	sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
	sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
	sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
	sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
	if [[ -e /appex/bin/lotServer.sh ]]; then
		bash <(wget --no-check-certificate -qO- https://git.io/lotServerInstall.sh) uninstall
	fi
	clear
	echo -e "${Info}:清除加速完成。"
	sleep 1s
}

#优化系统配置
optimizing_system(){
	sed -i '/net.ipv4.tcp_retries2/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_slow_start_after_idle/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
	sed -i '/fs.file-max/d' /etc/sysctl.conf
	sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
	sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
	sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
	sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
	echo "net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
fs.file-max = 1000000
fs.inotify.max_user_instances = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_orphans = 32768
# forward ipv4
net.ipv4.ip_forward = 1">>/etc/sysctl.conf
	sysctl -p
	echo "*               soft    nofile           1000000
*               hard    nofile          1000000">/etc/security/limits.conf
	echo "ulimit -SHn 1000000">>/etc/profile
	stty erase '^H' && read -p "需要重启VPS后，才能生效系统优化配置，是否现在重启 ? [Y/n] :" yn
	[ -z "${yn}" ] && yn="y"
	if [[ $yn == [Yy] ]]; then
		echo -e "${Info} VPS 重启中..."
		reboot
	fi
}

#开始菜单
start_menu(){
clear
echo && echo -e " TCP加速 一键安装管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
 更新内容及反馈:  https://blog.ylx.me/archives/783.html
 Modify by Rocker

————————————内核管理————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装 BBR原版内核 - 5.4.14/5.5.5
 ${Green_font_prefix}2.${Font_color_suffix} 安装 BBRplus版内核 - 4.14.129/4.14.168
————————————加速管理————————————
 ${Green_font_prefix}11.${Font_color_suffix} 使用BBR+FQ加速
 ${Green_font_prefix}12.${Font_color_suffix} 使用BBRplus+FQ版加速
————————————杂项管理————————————
 ${Green_font_prefix}21.${Font_color_suffix} 卸载全部加速
 ${Green_font_prefix}22.${Font_color_suffix} 系统配置优化
 ${Green_font_prefix}23.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo

	check_status
	echo -e " 当前内核为：${Font_color_suffix}${kernel_version_r}${Font_color_suffix}"
	if [[ ${kernel_status} == "noinstall" ]]; then
		echo -e " 当前状态: ${Green_font_prefix}未安装${Font_color_suffix} 加速内核 ${Red_font_prefix}请先安装内核${Font_color_suffix}"
	else
		echo -e " 当前状态: ${Green_font_prefix}已安装${Font_color_suffix} ${_font_prefix}${kernel_status}${Font_color_suffix} 加速内核 , ${Green_font_prefix}${run_status}${Font_color_suffix}"
		
	fi
	echo -e " 当前拥塞控制算法为: ${Green_font_prefix}${net_congestion_control}${Font_color_suffix} 当前队列算法为: ${Green_font_prefix}${net_qdisc}${Font_color_suffix} "
	
echo
stty erase '^H' && read -p " 请输入数字 :" num
case "$num" in
	1)
	check_sys_bbr
	;;
	2)
	check_sys_bbrplus
	;;
	11)
	startbbrfq
	;;
	12)
	startbbrplus
	;;
	21)
	remove_all
	;;
	22)
	optimizing_system
	;;
	23)
	exit 1
	;;
	*)
	clear
	echo -e "${Error}:请输入正确数字 [0-11]"
	sleep 2s
	start_menu
	;;
esac
}
#############内核管理组件#############

#删除多余内核
detele_kernel(){
    echo "是否需要删除旧版本的内核(
1、建议磁盘空间够的情况下不删除 
2、若需要的内核不是当前已安装内核中最高版本，则需要删除高版本内核)? [Y/n] :"
	stty erase '^H' && read yn
	[ -z "${yn}" ] && yn="n"
	if [[ $yn != [Yy] ]]; then
		return
	fi
	
	if [[ "${release}" == "centos" ]]; then
		rpm_total=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | wc -l`
		if [ "${rpm_total}" > "1" ]; then
			echo -e "检测到 ${rpm_total} 个其余内核，开始卸载..."
			for((integer = 1; integer <= ${rpm_total}; integer++)); do
				rpm_del=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | head -1`
				echo -e "开始卸载 ${rpm_del} 内核..."
				rpm --nodeps -e ${rpm_del}
				echo -e "卸载 ${rpm_del} 内核卸载完成，继续..."
			done
			echo --nodeps -e "内核卸载完毕，继续..."
		else
			echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
		fi
	elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
		deb_total=`dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | wc -l`
		if [ "${deb_total}" > "1" ]; then
			echo -e "检测到 ${deb_total} 个其余内核，开始卸载..."
			for((integer = 1; integer <= ${deb_total}; integer++)); do
			    deb_del=`dpkg -l | grep linux-headers | awk '{print $2}' | grep -v "${kernel_version}" | head -1`
				apt-get purge -y ${deb_del}
				deb_del=`dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | head -1`
				echo -e "开始卸载 ${deb_del} 内核..."
				apt-get purge -y ${deb_del}
				echo -e "卸载 ${deb_del} 内核卸载完成，继续..."
			done
			echo -e "内核卸载完毕，继续..."
		else
			echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
		fi
	fi
}

#更新引导
BBR_grub(){
	if [[ "${release}" == "centos" ]]; then
        if [[ ${version} = "6" ]]; then
            if [ ! -f "/boot/grub/grub.conf" ]; then
                echo -e "${Error} /boot/grub/grub.conf 找不到，请检查."
                exit 1
            fi
            sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
        elif [[ ${version} = "7" ]]; then
            if [ -f "/boot/grub2/grub.cfg" ]; then
				grub2-mkconfig  -o   /boot/grub2/grub.cfg
				grub2-set-default 0
			elif [ -f "/boot/efi/EFI/centos/grub.cfg" ]; then
				grub2-mkconfig  -o   /boot/efi/EFI/centos/grub.cfg
				grub2-set-default 0
			else
				echo -e "${Error} grub.cfg 找不到，请检查."
				exit 1
            fi
			#grub2-mkconfig  -o   /boot/grub2/grub.cfg
			#grub2-set-default 0
		
		elif [[ ${version} = "8" ]]; then
			grub2-mkconfig  -o   /boot/grub2/grub.cfg
			grubby --info=ALL|awk -F= '$1=="kernel" {print i++ " : " $2}'
        fi
    elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        /usr/sbin/update-grub
    fi
}

#############内核管理组件#############



#############系统检测组件#############

#检查系统
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	
#处理ca证书
	if [[ "${release}" == "centos" ]]; then
		yum install ca-certificates -y
		update-ca-trust force-enable
	elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
		apt-get install ca-certificates -y
		update-ca-certificates
	fi	
}

#检查Linux版本
check_version(){
	if [[ -s /etc/redhat-release ]]; then
		version=`grep -oE  "[0-9.]+" /etc/redhat-release | cut -d . -f 1`
	else
		version=`grep -oE  "[0-9.]+" /etc/issue | cut -d . -f 1`
	fi
	bit=`uname -m`
	if [[ ${bit} = "x86_64" ]]; then
		bit="x64"
	else
		bit="x32"
	fi
}

#检查安装bbr的系统要求
check_sys_bbr(){
	check_version
	if [[ "${release}" == "centos" ]]; then
		if [[ ${version} = "6" || ${version} = "7" || ${version} = "8" ]]; then
			installbbr
		else
			echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	elif [[ "${release}" == "debian" ]]; then
		if [[ ${version} = "8" || ${version} = "9" || ${version} = "10" ]]; then
			installbbr
		else
			echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	elif [[ "${release}" == "ubuntu" ]]; then
		if [[ ${version} = "16" || ${version} = "18" || ${version} = "19" || ${version} = "20" ]]; then
			installbbr
		else
			echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	else
		echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
	fi
}

check_sys_bbrplus(){
	check_version
	if [[ "${release}" == "centos" ]]; then
		if [[ ${version} = "6" || ${version} = "7" || ${version} = "8" ]]; then
			installbbrplus
		else
			echo -e "${Error} BBRplus内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	elif [[ "${release}" == "debian" ]]; then
		if [[ ${version} = "8" || ${version} = "9" || ${version} = "10" ]]; then
			installbbrplus
		else
			echo -e "${Error} BBRplus内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	elif [[ "${release}" == "ubuntu" ]]; then
		if [[ ${version} = "16" || ${version} = "18" || ${version} = "19" || ${version} = "20" ]]; then
			installbbrplus
		else
			echo -e "${Error} BBRplus内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	else
		echo -e "${Error} BBRplus内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
	fi
}

check_sys_bbrplusnew(){
	check_version
	if [[ "${release}" == "centos" ]]; then
		if [[ ${version} = "7" ]]; then
			installbbrplusnew
		else
			echo -e "${Error} BBRplusNew内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	elif [[ "${release}" == "debian" ]]; then
		if [[ ${version} = "10" ]]; then
			installbbrplusnew
		else
			echo -e "${Error} BBRplusNew内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	else
		echo -e "${Error} BBRplusNew内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
	fi
}

check_status(){
	kernel_version=`uname -r | awk -F "-" '{print $1}'`
	kernel_version_full=`uname -r`
	net_congestion_control=`cat /proc/sys/net/ipv4/tcp_congestion_control | awk '{print $1}'`
	net_qdisc=`cat /proc/sys/net/core/default_qdisc | awk '{print $1}'`
	kernel_version_r=`uname -r | awk '{print $1}'`
	if [[ ${kernel_version_full} = "4.14.168-bbrplus" || ${kernel_version_full} = "4.14.98-bbrplus" || ${kernel_version_full} = "4.14.129-bbrplus" || ${kernel_version_full} = "4.14.160-bbrplus" 
	      || ${kernel_version_full} = "4.14.166-bbrplus" || ${kernel_version_full} = "4.14.161-bbrplus" || ${kernel_version_full} = "4.14.173-bbrplus" ]]; then
		kernel_status="BBRplus"
	elif [[ `echo ${kernel_version} | awk -F'.' '{print $1}'` == "4" ]] && [[ `echo ${kernel_version} | awk -F'.' '{print $2}'` -ge 9 ]] || [[ `echo ${kernel_version} | awk -F'.' '{print $1}'` == "5" ]]; then
		kernel_status="BBR"
	elif [[ ${kernel_version} = "3.10.0" || ${kernel_version} = "3.16.0" || ${kernel_version} = "3.2.0" || ${kernel_version} = "4.4.0" || ${kernel_version} = "3.13.0"  || ${kernel_version} = "2.6.32" || ${kernel_version} = "4.9.0" || ${kernel_version} = "4.11.2" ]]; then
		kernel_status="Lotserver"
	else 
		kernel_status="noinstall"
	fi
	

	if [[ ${kernel_status} == "BBR" ]]; then
		run_status=`cat /proc/sys/net/ipv4/tcp_congestion_control | awk '{print $1}'`
		if [[ ${run_status} == "bbr" ]]; then
			run_status="BBR启动成功"
		elif [[ ${run_status} == "bbr2" ]]; then
			run_status="BBR2启动成功"	
		elif [[ ${run_status} == "tsunami" ]]; then
			run_status=`lsmod | grep "tsunami" | awk '{print $1}'`
			if [[ ${run_status} == "tcp_tsunami" ]]; then
				run_status="BBR魔改版启动成功"
			else 
				run_status="BBR魔改版启动失败"
			fi
		elif [[ ${run_status} == "nanqinlang" ]]; then
			run_status=`lsmod | grep "nanqinlang" | awk '{print $1}'`
			if [[ ${run_status} == "tcp_nanqinlang" ]]; then
				run_status="暴力BBR魔改版启动成功"
			else 
				run_status="暴力BBR魔改版启动失败"
			fi
		else 
			run_status="未安装加速模块"
		fi
		
	elif [[ ${kernel_status} == "Lotserver" ]]; then
		if [[ -e /appex/bin/lotServer.sh ]]; then
			run_status=`bash /appex/bin/lotServer.sh status | grep "LotServer" | awk  '{print $3}'`
			if [[ ${run_status} = "running!" ]]; then
				run_status="启动成功"
			else 
				run_status="启动失败"
			fi
		else 
			run_status="未安装加速模块"
		fi	
	elif [[ ${kernel_status} == "BBRplus" ]]; then
		run_status=`cat /proc/sys/net/ipv4/tcp_congestion_control | awk '{print $1}'`
		if [[ ${run_status} == "bbrplus" ]]; then
			run_status="BBRplus启动成功"
		else 
			run_status="未安装加速模块"
		fi
	fi
}

#############系统检测组件#############
check_sys
check_version
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} 本脚本不支持当前系统 ${release} !" && exit 1
start_menu