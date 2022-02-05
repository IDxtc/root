#!/usr/bin/env bash
# Detection area
# -------------------------------------------------------------
# Check the system
export LANG=en_US.UTF-8

echoContent() {
	case $1 in
	# Red
	"red")
		# shellcheck disable=SC2154
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		# sky blue
	"skyBlue")
		${echoType} "\033[1;36m${printN}$2 \033[0m"
		;;
		# green
	"green")
		${echoType} "\033[32m${printN}$2 \033[0m"
		;;
		# white
	"white")
		${echoType} "\033[37m${printN}$2 \033[0m"
		;;
	"magenta")
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		# yellow
	"yellow")
		${echoType} "\033[33m${printN}$2 \033[0m"
		;;
	esac
}
checkSystem() {
	if [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
		mkdir -p /etc/yum.repos.d

		if [[ -f "/etc/centos-release" ]]; then
			centosVersion=$(rpm -q centos-release | awk -F "[-]" '{print $3}' | awk -F "[.]" '{print $1}')

			if [[ -z "${centosVersion}" ]] && grep </etc/centos-release -q -i "release 8"; then
				centosVersion=8
			fi
		fi

		release="centos"
		installType='yum -y install'
		removeType='yum -y remove'
		upgrade="yum update -y --skip-broken"

	elif grep </etc/issue -q -i "debian" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "debian" && [[ -f "/proc/version" ]]; then
		release="debian"
		installType='apt -y install'
		upgrade="apt update"
		updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
		removeType='apt -y autoremove'

	elif grep </etc/issue -q -i "ubuntu" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "ubuntu" && [[ -f "/proc/version" ]]; then
		release="ubuntu"
		installType='apt -y install'
		upgrade="apt update"
		updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
		removeType='apt -y autoremove'
		if grep </etc/issue -q -i "16."; then
			release=
		fi
	fi

	if [[ -z ${release} ]]; then
		echoContent red "\nThis script does not support this system，Please feedback the log below to the developer\n"
		echoContent yellow "$(cat /etc/issue)"
		echoContent yellow "$(cat /proc/version)"
		exit 0
	fi
}

# Check CPU provider
checkCPUVendor() {
	if [[ -n $(which uname) ]]; then
		if [[ "$(uname)" == "Linux" ]]; then
			case "$(uname -m)" in
			'amd64' | 'x86_64')
				xrayCoreCPUVendor="Xray-linux-64"
				v2rayCoreCPUVendor="v2ray-linux-64"
				;;
			'armv8' | 'aarch64')
				xrayCoreCPUVendor="Xray-linux-arm64-v8a"
				v2rayCoreCPUVendor="v2ray-linux-arm64-v8a"
				;;
			*)
				echo "  This CPU architecture is not supported--->"
				exit 1
				;;
			esac
		fi
	else
		echoContent red "  This CPU architecture is not recognized，Default amd64、x86_64--->"
		xrayCoreCPUVendor="Xray-linux-64"
		v2rayCoreCPUVendor="v2ray-linux-64"
	fi
}

# Initialize global variables
initVar() {
	installType='yum -y install'
	removeType='yum -y remove'
	upgrade="yum -y update"
	echoType='echo -e'

	# Core supported cpu version
	xrayCoreCPUVendor=""
	v2rayCoreCPUVendor=""
	# domain name
	domain=

	# The address of the CDN node
	add=

	# Overall progress of installation
	totalProgress=1

	# 1.xray-core Install
	# 2.v2ray-core Install
	# 3.v2ray-core[xtls] Install
	coreInstallType=

	# core installation path
	# coreInstallPath=

	# v2ctl Path
	ctlPath=
	# 1.Install all
	# 2.Personalized installation
	# v2rayAgentInstallType=

	# Current Personalized Installation Methods 01234
	currentInstallProtocolType=

	# The order of the current alpn
	currentAlpn=

	# Pre-Type
	frontingType=

	# Personalized installation method of choice
	selectCustomInstallType=

	# v2ray-core、xray-core the path to the configuration file
	configPath=

	# the path to the configuration file
	currentPath=

	# the host of the configuration file
	currentHost=

	# The core type selected during installation
	selectCoreType=

	# Default core version
	v2rayCoreVersion=

	# random path
	customPath=

	# centos version
	centosVersion=

	# UUID
	currentUUID=

	localIP=

	# Integrated update certificate logic no longer uses a separate script--RenewTLS
	renewTLS=$1

	# number of attempts after tls install failed
	installTLSCount=

	# BTPanel status
	BTPanelStatus=

	# nginx configuration file path
	nginxConfigPath=/etc/nginx/conf.d/
}

# Check the installation method
readInstallType() {
	coreInstallType=
	configPath=

	# 1.Check the installation directory
	if [[ -d "/etc/v2ray-agent" ]]; then
		# Check the installation method v2ray-core
		if [[ -d "/etc/v2ray-agent/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ctl" ]]; then
			if [[ -d "/etc/v2ray-agent/v2ray/conf" && -f "/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json" ]]; then
				configPath=/etc/v2ray-agent/v2ray/conf/

				if ! grep </etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json -q xtls; then
					# without XTLS v2ray-core
					coreInstallType=2
					ctlPath=/etc/v2ray-agent/v2ray/v2ctl
				elif grep </etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json -q xtls; then
					# without XTLS v2ray-core
					ctlPath=/etc/v2ray-agent/v2ray/v2ctl
					coreInstallType=3
				fi
			fi
		fi

		if [[ -d "/etc/v2ray-agent/xray" && -f "/etc/v2ray-agent/xray/xray" ]]; then
			# Check here xray-core
			if [[ -d "/etc/v2ray-agent/xray/conf" ]] && [[ -f "/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json" || -f "/etc/v2ray-agent/xray/conf/02_trojan_TCP_inbounds.json" ]]; then
				# xray-core
				configPath=/etc/v2ray-agent/xray/conf/
				ctlPath=/etc/v2ray-agent/xray/xray
				coreInstallType=1
			fi
		fi
	fi
}

# read protocol type
readInstallProtocolType() {
	currentInstallProtocolType=

	while read -r row; do
		if echo "${row}" | grep -q 02_trojan_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'trojan'
			frontingType=02_trojan_TCP_inbounds
		fi
		if echo "${row}" | grep -q VLESS_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'0'
			frontingType=02_VLESS_TCP_inbounds
		fi
		if echo "${row}" | grep -q VLESS_WS_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'1'
		fi
		if echo "${row}" | grep -q trojan_gRPC_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'2'
		fi
		if echo "${row}" | grep -q VMess_WS_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'3'
		fi
		if echo "${row}" | grep -q 04_trojan_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'4'
		fi
		if echo "${row}" | grep -q VLESS_gRPC_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'5'
		fi
		if echo "${row}" | grep -q VMess_gRPC_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'6'
		fi
	done < <(find ${configPath} -name "*inbounds.json" | awk -F "[.]" '{print $1}')
}

# Check if pagoda is installed
checkBTPanel() {
	if pgrep -f "BT-Panel"; then
		nginxConfigPath=/www/server/panel/vhost/nginx/
		BTPanelStatus=true
	fi
}
# The order in which the current alpn is read
readInstallAlpn() {
	if [[ -n ${currentInstallProtocolType} ]]; then
		local alpn
		alpn=$(jq -r .inbounds[0].streamSettings.xtlsSettings.alpn[0] ${configPath}${frontingType}.json)
		if [[ -n ${alpn} ]]; then
			currentAlpn=${alpn}
		fi
	fi
}

# Check firewall
allowPort() {
	# If the firewall is enabled, add the corresponding open port
	if systemctl status netfilter-persistent 2>/dev/null | grep -q "active (exited)"; then
		local updateFirewalldStatus=
		if ! iptables -L | grep -q "http(mack-a)"; then
			updateFirewalldStatus=true
			iptables -I INPUT -p tcp --dport 80 -m comment --comment "allow http(mack-a)" -j ACCEPT
		fi

		if ! iptables -L | grep -q "https(mack-a)"; then
			updateFirewalldStatus=true
			iptables -I INPUT -p tcp --dport 443 -m comment --comment "allow https(mack-a)" -j ACCEPT
		fi

		if echo "${updateFirewalldStatus}" | grep -q "true"; then
			netfilter-persistent save
		fi
	elif systemctl status ufw 2>/dev/null | grep -q "active (exited)"; then
		if ! ufw status | grep -q 443; then
			sudo ufw allow https
			checkUFWAllowPort 443
		fi

		if ! ufw status | grep -q 80; then
			sudo ufw allow 80
			checkUFWAllowPort 80
		fi
	elif systemctl status firewalld 2>/dev/null | grep -q "active (running)"; then
		local updateFirewalldStatus=
		if ! firewall-cmd --list-ports --permanent | grep -qw "80/tcp"; then
			updateFirewalldStatus=true
			firewall-cmd --zone=public --add-port=80/tcp --permanent
			checkFirewalldAllowPort 80
		fi

		if ! firewall-cmd --list-ports --permanent | grep -qw "443/tcp"; then
			updateFirewalldStatus=true
			firewall-cmd --zone=public --add-port=443/tcp --permanent
			checkFirewalldAllowPort 443
		fi
		if echo "${updateFirewalldStatus}" | grep -q "true"; then
			firewall-cmd --reload
		fi
	fi
}

# Check the occupancy of ports 80 and 443
checkPortUsedStatus() {
	if lsof -i tcp:80 | grep -q LISTEN; then
		echoContent red "\n ---> 80端口被占用，请手动关闭后安装\n"
		lsof -i tcp:80 | grep LISTEN
		exit 0
	fi

	if lsof -i tcp:443 | grep -q LISTEN; then
		echoContent red "\n ---> 443端口被占用，请手动关闭后安装\n"
		lsof -i tcp:80 | grep LISTEN
		exit 0
	fi
}

# Output ufw port open status
checkUFWAllowPort() {
	if ufw status | grep -q "$1"; then
		echoContent green " ---> $1端口开放成功"
	else
		echoContent red " ---> $1端口开放失败"
		exit 0
	fi
}

# Output ufw port open status
checkFirewalldAllowPort() {
	if firewall-cmd --list-ports --permanent | grep -q "$1"; then
		echoContent green " ---> $1端口开放成功"
	else
		echoContent red " ---> $1端口开放失败"
		exit 0
	fi
}
# Check the file directory and path
readConfigHostPathUUID() {
	currentPath=
	currentUUID=
	currentHost=
	currentPort=
	currentAdd=
	# read path
	if [[ -n "${configPath}" ]]; then
		local fallback
		fallback=$(jq -r -c '.inbounds[0].settings.fallbacks[]|select(.path)' ${configPath}${frontingType}.json | head -1)

		local path
		path=$(echo "${fallback}" | jq -r .path | awk -F "[/]" '{print $2}')

		if [[ $(echo "${fallback}" | jq -r .dest) == 31297 ]]; then
			currentPath=$(echo "${path}" | awk -F "[w][s]" '{print $1}')
		elif [[ $(echo "${fallback}" | jq -r .dest) == 31298 ]]; then
			currentPath=$(echo "${path}" | awk -F "[t][c][p]" '{print $1}')
		elif [[ $(echo "${fallback}" | jq -r .dest) == 31299 ]]; then
			currentPath=$(echo "${path}" | awk -F "[v][w][s]" '{print $1}')
		fi
	fi

	if [[ "${coreInstallType}" == "1" ]]; then
		currentHost=$(jq -r .inbounds[0].streamSettings.xtlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
		currentAdd=$(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json)
		if [[ "${currentAdd}" == "null" ]]; then
			currentAdd=${currentHost}
		fi
		currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)

	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
		if [[ "${coreInstallType}" == "3" ]]; then
			currentHost=$(jq -r .inbounds[0].streamSettings.xtlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		else
			currentHost=$(jq -r .inbounds[0].streamSettings.tlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		fi
		currentAdd=$(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json)

		if [[ "${currentAdd}" == "null" ]]; then
			currentAdd=${currentHost}
		fi
		currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
		currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)
	fi
}

# Status display
showInstallStatus() {
	if [[ -n "${coreInstallType}" ]]; then
		if [[ "${coreInstallType}" == 1 ]]; then
			if [[ -n $(pgrep -f xray/xray) ]]; then
				echoContent yellow "\n Status：Xray-core[running]"
			else
				echoContent yellow "\n Status：Xray-core[not running]"
			fi

		elif [[ "${coreInstallType}" == 2 || "${coreInstallType}" == 3 ]]; then
			if [[ -n $(pgrep -f v2ray/v2ray) ]]; then
				echoContent yellow "\n Status：v2ray-core[running]"
			else
				echoContent yellow "\n Status：v2ray-core[not running]"
			fi
		fi
		# read protocol type
		readInstallProtocolType

		if [[ -n ${currentInstallProtocolType} ]]; then
			echoContent yellow "：\c"
		fi
		if echo ${currentInstallProtocolType} | grep -q 0; then
			if [[ "${coreInstallType}" == 2 ]]; then
				echoContent yellow "VLESS+TCP[TLS] \c"
			else
				echoContent yellow "VLESS+TCP[TLS/XTLS] \c"
			fi
		fi

		if echo ${currentInstallProtocolType} | grep -q trojan; then
			if [[ "${coreInstallType}" == 1 ]]; then
				echoContent yellow "Trojan+TCP[TLS/XTLS] \c"
			fi
		fi

		if echo ${currentInstallProtocolType} | grep -q 1; then
			echoContent yellow "VLESS+WS[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then
			echoContent yellow "Trojan+gRPC[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then
			echoContent yellow "VMess+WS[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then
			echoContent yellow "Trojan+TCP[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			echoContent yellow "VLESS+gRPC[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 6; then
			echoContent yellow "VMess+gRPC[TLS] \c"
		fi
	fi
}

# Clean up old residue
cleanUp() {
	if [[ "$1" == "v2rayClean" ]]; then
		rm -rf "$(find /etc/v2ray-agent/v2ray/* | grep -E '(config_full.json|conf)')"
		handleV2Ray stop >/dev/null
		rm -f /etc/systemd/system/v2ray.service
	elif [[ "$1" == "xrayClean" ]]; then
		rm -rf "$(find /etc/v2ray-agent/xray/* | grep -E '(config_full.json|conf)')"
		handleXray stop >/dev/null
		rm -f /etc/systemd/system/xray.service

	elif [[ "$1" == "v2rayDel" ]]; then
		rm -rf /etc/v2ray-agent/v2ray/*

	elif [[ "$1" == "xrayDel" ]]; then
		rm -rf /etc/v2ray-agent/xray/*
	fi
}

initVar "$1"
checkSystem
checkCPUVendor
readInstallType
readInstallProtocolType
readConfigHostPathUUID
readInstallAlpn
checkBTPanel

# -------------------------------------------------------------

# 初始化安装目录
mkdirTools() {
	mkdir -p /etc/v2ray-agent/tls
	mkdir -p /etc/v2ray-agent/subscribe
	mkdir -p /etc/v2ray-agent/subscribe_tmp
	mkdir -p /etc/v2ray-agent/v2ray/conf
	mkdir -p /etc/v2ray-agent/xray/conf
	mkdir -p /etc/v2ray-agent/trojan
	mkdir -p /etc/systemd/system/
	mkdir -p /tmp/v2ray-agent-tls/
}

# Initialize the installation directory
installTools() {
	echo 'installation tool'
	echoContent skyBlue "\n progress  $1/${totalProgress} : installation tool"
	# Fix ubuntu individual system problems
	if [[ "${release}" == "ubuntu" ]]; then
		dpkg --configure -a
	fi

	if [[ -n $(pgrep -f "apt") ]]; then
		pgrep -f apt | xargs kill -9
	fi

	echoContent green " ———> Check and install updates [The new machine will be very slow, if there is no response for a long time, please stop it manually and execute it again]"

	${upgrade} >/etc/v2ray-agent/install.log 2>&1
	if grep <"/etc/v2ray-agent/install.log" -q "changed"; then
		${updateReleaseInfoChange} >/dev/null 2>&1
	fi

	if [[ "${release}" == "centos" ]]; then
		rm -rf /var/run/yum.pid
		${installType} epel-release >/dev/null 2>&1
	fi

	#	[[ -z `find /usr/bin /usr/sbin |grep -v grep|grep -w curl` ]]

	if ! find /usr/bin /usr/sbin | grep -q -w wget; then
		echoContent green " ———> Install wget"
		${installType} wget >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w curl; then
		echoContent green " ———> Install curl"
		${installType} curl >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w unzip; then
		echoContent green " ———> Install unzip"
		${installType} unzip >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w socat; then
		echoContent green " ———> Install socat"
		${installType} socat >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w tar; then
		echoContent green " ———> Install tar"
		${installType} tar >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w cron; then
		echoContent green " ———> Install crontabs"
		if [[ "${release}" == "ubuntu" ]] || [[ "${release}" == "debian" ]]; then
			${installType} cron >/dev/null 2>&1
		else
			${installType} crontabs >/dev/null 2>&1
		fi
	fi
	if ! find /usr/bin /usr/sbin | grep -q -w jq; then
		echoContent green " ———> Install jq"
		${installType} jq >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w binutils; then
		echoContent green " ———> Install binutils"
		${installType} binutils >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w ping6; then
		echoContent green " ———> Install ping6"
		${installType} inetutils-ping >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w qrencode; then
		echoContent green " ———> Install qrencode"
		${installType} qrencode >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w sudo; then
		echoContent green " ———> Install sudo"
		${installType} sudo >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w lsb-release; then
		echoContent green " ———> Install lsb-release"
		${installType} lsb-release >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w lsof; then
		echoContent green " ———> Install lsof"
		${installType} lsof >/dev/null 2>&1
	fi

	# Detect nginx version，and provide the option to uninstall

	if ! find /usr/bin /usr/sbin | grep -q -w nginx; then
		echoContent green " ———> Install nginx"
		installNginxTools
	else
		nginxVersion=$(nginx -v 2>&1)
		nginxVersion=$(echo "${nginxVersion}" | awk -F "[n][g][i][n][x][/]" '{print $2}' | awk -F "[.]" '{print $2}')
		if [[ ${nginxVersion} -lt 14 ]]; then
			read -r -p "Read that the current Nginx version does not support gRPC，will cause the installation to fail，Whether to uninstall and reinstall Nginx ？[y/n]:" unInstallNginxStatus
			if [[ "${unInstallNginxStatus}" == "y" ]]; then
				${removeType} nginx >/dev/null 2>&1
				echoContent yellow " ———> nginx uninstallation completed"
				echoContent green " ———> Install nginx"
				installNginxTools >/dev/null 2>&1
			else
				exit 0
			fi
		fi
	fi
	if ! find /usr/bin /usr/sbin | grep -q -w semanage; then
		echoContent green " ———> Install semanage"
		${installType} bash-completion >/dev/null 2>&1

		if [[ "${centosVersion}" == "7" ]]; then
			policyCoreUtils="policycoreutils-python.x86_64"
		elif [[ "${centosVersion}" == "8" ]]; then
			policyCoreUtils="policycoreutils-python-utils-2.9-9.el8.noarch"
		fi

		if [[ -n "${policyCoreUtils}" ]]; then
			${installType} ${policyCoreUtils} >/dev/null 2>&1
		fi
		if [[ -n $(which semanage) ]]; then
			semanage port -a -t http_port_t -p tcp 31300

		fi
	fi

	if [[ ! -d "$HOME/.acme.sh" ]] || [[ -d "$HOME/.acme.sh" && -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
		echoContent green " ———> Install acme.sh"
		curl -s https://get.acme.sh | sh -s >/etc/v2ray-agent/tls/acme.log 2>&1
		if [[ ! -d "$HOME/.acme.sh" ]] || [[ -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
			echoContent red "  acme installation failed--->"
			tail -n 100 /etc/v2ray-agent/tls/acme.log
			echoContent yellow "Troubleshooting："
			echoContent red "  1.Failed to get Github file，Please wait for Github to recover and try，Recovery progress can be viewed [https://www.githubstatus.com/]"
			echoContent red "  2.acme.sh script bug，viewable[https://github.com/acmesh-official/acme.sh] issues"
			exit 0
		fi
	fi
}

# Install Nginx
installNginxTools() {

	if [[ "${release}" == "debian" ]]; then
		sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
		echo "deb http://nginx.org/packages/mainline/debian $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
		echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
		curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
		# gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
		sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "ubuntu" ]]; then
		sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
		echo "deb http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
		echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
		curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
		# gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
		sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "centos" ]]; then
		${installType} yum-utils >/dev/null 2>&1
		cat <<EOF >/etc/yum.repos.d/nginx.repo
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true

[nginx-mainline]
name=nginx mainline repo
baseurl=http://nginx.org/packages/mainline/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=0
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
		sudo yum-config-manager --enable nginx-mainline >/dev/null 2>&1
	fi
	${installType} nginx >/dev/null 2>&1
	systemctl daemon-reload
	systemctl enable nginx
}

# Install warp
installWarp() {
	${installType} gnupg2 -y >/dev/null 2>&1
	if [[ "${release}" == "debian" ]]; then
		curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1
		echo "deb http://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "ubuntu" ]]; then
		curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1
		echo "deb http://pkg.cloudflareclient.com/ focal main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "centos" ]]; then
		${installType} yum-utils >/dev/null 2>&1
		sudo rpm -ivh "http://pkg.cloudflareclient.com/cloudflare-release-el${centosVersion}.rpm" >/dev/null 2>&1
	fi

	echoContent green " ———> Install WARP"
	${installType} cloudflare-warp >/dev/null 2>&1
	if [[ -z $(which warp-cli) ]]; then
		echoContent red " ———> Failed to install WARP"
		exit 0
	fi
	systemctl enable warp-svc
	warp-cli --accept-tos register
	warp-cli --accept-tos set-mode proxy
	warp-cli --accept-tos set-proxy-port 31303
	warp-cli --accept-tos connect
	warp-cli --accept-tos enable-always-on


	#	if [[]];then
	#	fi
	# todo curl --socks5 127.0.0.1:31303 https://www.cloudflare.com/cdn-cgi/trace
	# systemctl daemon-reload
	# systemctl enable cloudflare-warp
}
# Initialize Nginx application certificate configuration
initTLSNginxConfig() {
	handleNginx stop
	echoContent skyBlue "\n progress  $1/${totalProgress} : Initialize Nginx application certificate configuration"
	if [[ -n "${currentHost}" ]]; then
		echo
		read -r -p "Read to last installation record，Whether to use the domain name from the last installation ？[y/n]:" historyDomainStatus
		if [[ "${historyDomainStatus}" == "y" ]]; then
			domain=${currentHost}
			echoContent yellow "\n ———> domain name：${domain}"
		else
			echo
			echoContent yellow "Please enter the domain name to be configured
			Example：www.v2ray-agent.com ———>"
			read -r -p "域名:" domain
		fi
	else
		echo
		echoContent yellow "Please enter the domain name to configure example：www.v2ray-agent.com --->"
		read -r -p "domain name:" domain
	fi

	if [[ -z ${domain} ]]; then
		echoContent red "  Domain name cannot be empty--->"
		initTLSNginxConfig 3
	else
		# 修改配置
		touch ${nginxConfigPath}alone.conf
		cat <<EOF >${nginxConfigPath}alone.conf
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    root /usr/share/nginx/html;
    location ~ /.well-known {
    	allow all;
    }
    location /test {
    	return 200 'fjkvymb6len';
    }
	location /ip {
		proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header REMOTE-HOST \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		default_type text/plain;
		return 200 \$proxy_add_x_forwarded_for;
	}
}
EOF
		# start nginx
		handleNginx start
		checkIP
	fi
}

# Modify nginx redirect configuration
updateRedirectNginxConf() {

	if [[ ${BTPanelStatus} == "true" ]]; then

		cat <<EOF >${nginxConfigPath}alone.conf
        server {
        		listen 127.0.0.1:31300;
        		server_name _;
        		return 403;
        }
EOF

	else
		cat <<EOF >${nginxConfigPath}alone.conf
        server {
        	listen 80;
        	listen [::]:80;
        	server_name ${domain};
        	# shellcheck disable=SC2154
        	return 301 https://${domain}\${request_uri};
        }
        server {
        		listen 127.0.0.1:31300;
        		server_name _;
        		return 403;
        }
EOF
	fi

	if echo "${selectCustomInstallType}" | grep -q 2 && echo "${selectCustomInstallType}" | grep -q 5 && echo "${selectCustomInstallType}" | grep -q 6|| [[ -z "${selectCustomInstallType}" ]]; then

		cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }

    location /${currentPath}grpc {
		client_max_body_size 0;
#		keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}

	location /${currentPath}trojangrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31304;
	}

	location /${currentPath}VMgrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31305;
	}
}
EOF
	elif echo "${selectCustomInstallType}" | grep -q 5 || [[ -z "${selectCustomInstallType}" ]]; then
		cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location /${currentPath}grpc {
		client_max_body_size 0;
#		keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}
}
EOF

	elif echo "${selectCustomInstallType}" | grep -q 2 || [[ -z "${selectCustomInstallType}" ]]; then

		cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location /${currentPath}trojangrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31304;
	}
}
EOF

	elif echo "${selectCustomInstallType}" | grep -q 6 || [[ -z "${selectCustomInstallType}" ]]; then

		cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location /${currentPath}VMgrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31305;
	}
}
EOF
	else

		cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location / {
	}
}
EOF
	fi

	cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31300;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
		add_header Content-Type text/plain;
		alias /etc/v2ray-agent/subscribe/;
	}
	location / {
		add_header Strict-Transport-Security "max-age=15552000; preload" always;
	}
}
EOF

}

# checkip
checkIP() {
	echoContent skyBlue "\n ———> Check the domain name ip"
	localIP=$(curl -s -m 2 "${domain}/ip")
	handleNginx stop
	if [[ -z ${localIP} ]] || ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q '\.' && ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q ':'; then
		echoContent red "\n ———> The ip of the current domain name was not detected"
		echoContent yellow " ———> Please check that the domain name is spelled correctly"
		echoContent yellow " ———> Please check if the domain name dns resolution is correct"
		echoContent yellow " ———> If the parsing is correct，Please wait for dns to take effect，Expected to take effect within three minutes"
		echoContent yellow " ———> If the above settings are correct，Please try again after reinstalling a clean system"
		if [[ -n ${localIP} ]]; then
			echoContent yellow " ———> Detect return value exceptions，It is recommended to re-execute the script after manually uninstalling nginx"
		fi
		echoContent red " ———> Please check if firewall rules open 443、80\n"
		read -r -p "Whether to modify firewall rules through script to open 443、80？[y/n]:" allPortFirewallStatus
		if [[ ${allPortFirewallStatus} == "y" ]]; then
			allowPort
			handleNginx start
			checkIP
		else
			exit 0
		fi
	else
		if echo "${localIP}" | awk -F "[,]" '{print $2}' | grep -q "." || echo "${localIP}" | awk -F "[,]" '{print $2}' | grep -q ":"; then
			echoContent red "\n ———> multiple ip detected，Please confirm whether to close the cloud of cloudflare"
			echoContent yellow " ———> After closing the cloud, wait three minutes and try again"
			echoContent yellow " ———> The detected ip is as follows：[${localIP}]"
			exit 0
		fi
		echoContent green " ———> The current domain name ip is：[${localIP}]"
	fi

}
# Install TLS
installTLS() {
	echoContent skyBlue "\n progress  $1/${totalProgress} : Request a TLS certificate\n"
	local tlsDomain=${domain}
	# install tls
	if [[ -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" && -f "/etc/v2ray-agent/tls/${tlsDomain}.key" && -n $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]] || [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]]; then
		echoContent green " ———> Certificate detected"
		# checkTLStatus
		renewalTLS

		if [[ -z $(find /etc/v2ray-agent/tls/ -name "${tlsDomain}.crt") ]] || [[ -z $(find /etc/v2ray-agent/tls/ -name "${tlsDomain}.key") ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
			sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
		else
			echoContent yellow " ———> If not expired or custom certificate, please select[n]\n"
			read -r -p "Whether to reinstall？[y/n]:" reInstallStatus
			if [[ "${reInstallStatus}" == "y" ]]; then
				rm -rf /etc/v2ray-agent/tls/*
				installTLS "$1"
			fi
		fi

	elif [[ -d "$HOME/.acme.sh" ]] && [[ ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" || ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" ]]; then
		echoContent green " ———> Install TLS certificate"
		if echo "${localIP}" | grep -q ":"; then
			sudo "$HOME/.acme.sh/acme.sh" --issue -d "${tlsDomain}" --standalone -k ec-256 --server letsencrypt --listen-v6 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
		else
			sudo "$HOME/.acme.sh/acme.sh" --issue -d "${tlsDomain}" --standalone -k ec-256 --server letsencrypt | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
		fi

		if [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]]; then
			sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
		fi
		if [[ ! -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" || ! -f "/etc/v2ray-agent/tls/${tlsDomain}.key" ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.key") || -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
			tail -n 10 /etc/v2ray-agent/tls/acme.log
			if [[ ${installTLSCount} == "1" ]]; then
				echoContent red " ———> TLS installation failed，Please check the acme log"
				exit 0
			fi
			echoContent red " ———> TLS installation failed，Checking 80、Is port 443 open?"
			allowPort
			echoContent yellow " ———> Retry installing the TLS certificate"
			installTLSCount=1
			installTLS "$1"
		fi
		echoContent green " ———> TLS generation succeeded"
	else
		echoContent yellow " ———> not installed acme.sh"
		exit 0
	fi
}
# Configure Camouflage Blog
initNginxConfig() {
	echoContent skyBlue "\n progress  $1/${totalProgress} : Configure Nginx"

	cat <<EOF >${nginxConfigPath}alone.conf
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    root /usr/share/nginx/html;
    location ~ /.well-known {allow all;}
    location /test {return 200 'fjkvymb6len';}
}
EOF
}

# custom/random path
randomPathFunction() {
	echoContent skyBlue "\n progress  $1/${totalProgress} : Generate random paths"

	if [[ -n "${currentPath}" ]]; then
		echo
		read -r -p "Read to last installation record，Whether to use the path of the last installation ？[y/n]:" historyPathStatus
		echo
	fi

	if [[ "${historyPathStatus}" == "y" ]]; then
		customPath=${currentPath}
		echoContent green " ———> Use successfully\n"
	else
		echoContent yellow "Please enter a custom path[example: alone]，no slashes required，[Enter]random path"
		read -r -p 'path:' customPath

		if [[ -z "${customPath}" ]]; then
			customPath=$(head -n 50 /dev/urandom | sed 's/[^a-z]//g' | strings -n 4 | tr '[:upper:]' '[:lower:]' | head -1)
			currentPath=${customPath:0:4}
			customPath=${currentPath}
		else
			currentPath=${customPath}
		fi

	fi
	echoContent yellow "\n path：${currentPath}"
	echoContent skyBlue "\n————————————————————————————"
}
# Nginx Camouflage Blog
nginxBlog() {
	echoContent skyBlue "\n progress $1/${totalProgress} : Add fake site"
	if [[ -d "/usr/share/nginx/html" && -f "/usr/share/nginx/html/check" ]]; then
		echo
		read -r -p "Install masquerading site detected，Does it need to be reinstalled[y/n]：" nginxBlogInstallStatus
		if [[ "${nginxBlogInstallStatus}" == "y" ]]; then
			rm -rf /usr/share/nginx/html
			randomNum=$((RANDOM % 6 + 1))
			wget -q -P /usr/share/nginx https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip >/dev/null
			unzip -o /usr/share/nginx/html${randomNum}.zip -d /usr/share/nginx/html >/dev/null
			rm -f /usr/share/nginx/html${randomNum}.zip*
			echoContent green " ———> Add fake site successfully"
		fi
	else
		randomNum=$((RANDOM % 6 + 1))
		rm -rf /usr/share/nginx/html
		wget -q -P /usr/share/nginx https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip >/dev/null
		unzip -o /usr/share/nginx/html${randomNum}.zip -d /usr/share/nginx/html >/dev/null
		rm -f /usr/share/nginx/html${randomNum}.zip*
		echoContent green " ———> Add fake site successfully"
	fi

}
# Operate Nginx
handleNginx() {

	if [[ -z $(pgrep -f "nginx") ]] && [[ "$1" == "start" ]]; then
		systemctl start nginx
		sleep 0.5

		if [[ -z $(pgrep -f nginx) ]]; then
			echoContent red " ———> Nginx failed to start"
			echoContent red " ———> Please try manually after installing nginx，execute the script again"
			exit 0
		fi
	elif [[ -n $(pgrep -f "nginx") ]] && [[ "$1" == "stop" ]]; then
		systemctl stop nginx
		sleep 0.5
		if [[ -n $(pgrep -f "nginx") ]]; then
			pgrep -f "nginx" | xargs kill -9
		fi
	fi
}

# Scheduled task to update tls certificate
installCronTLS() {
	echoContent skyBlue "\n progress $1/${totalProgress} : Add regular maintenance certificate"
	crontab -l >/etc/v2ray-agent/backup_crontab.cron
	local historyCrontab
	historyCrontab=$(sed '/v2ray-agent/d;/acme.sh/d' /etc/v2ray-agent/backup_crontab.cron)
	echo "${historyCrontab}" >/etc/v2ray-agent/backup_crontab.cron
	echo "30 1 * * * /bin/bash /etc/v2ray-agent/install.sh RenewTLS >> /etc/v2ray-agent/crontab_tls.log 2>&1" >>/etc/v2ray-agent/backup_crontab.cron
	crontab /etc/v2ray-agent/backup_crontab.cron
	echoContent green "\n ---> Add the scheduled maintenance certificate successfully"
}

# Update certificate
renewalTLS() {
	if [[ -n $1 ]]; then
		echoContent skyBlue "\n progress  $1/1 : Update certificate"
	fi
	local domain=${currentHost}
	if [[ -z "${currentHost}" && -n "${tlsDomain}" ]]; then
		domain=${tlsDomain}
	fi

	if [[ -d "$HOME/.acme.sh/${domain}_ecc" ]] && [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" ]] && [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
		modifyTime=$(stat "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')

		modifyTime=$(date +%s -d "${modifyTime}")
		currentTime=$(date +%s)
		((stampDiff = currentTime - modifyTime))
		((days = stampDiff / 86400))
		((remainingDays = 90 - days))

		tlsStatus=${remainingDays}
		if [[ ${remainingDays} -le 0 ]]; then
			tlsStatus="expired"
		fi

		echoContent skyBlue " ———> Certificate Check Date:$(date "+%F %H:%M:%S")"
		echoContent skyBlue " ---> Certificate Generation Date:$(date -d @"${modifyTime}" +"%F %H:%M:%S")"
		echoContent skyBlue " ———> Certificate generation days:${days}"
		echoContent skyBlue " ---> Certificate days remaining:"${tlsStatus}
		echoContent skyBlue " ———> Automatic renewal on the last day before the certificate expires，If the update fails, please update manually"

		if [[ ${remainingDays} -le 1 ]]; then
			echoContent yellow " ———> Regenerate the certificate"
			handleNginx stop
			sudo "$HOME/.acme.sh/acme.sh" --cron --home "$HOME/.acme.sh"
			sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${domain}" --fullchainpath /etc/v2ray-agent/tls/"${domain}.crt" --keypath /etc/v2ray-agent/tls/"${domain}.key" --ecc
			reloadCore
			handleNginx start
		else
			echoContent green " ———> Certificate is valid"
		fi
	else
		echoContent red " ———> Not Installed"
	fi
}
# Check the status of the TLS certificate
checkTLStatus() {

	if [[ -d "$HOME/.acme.sh/${currentHost}_ecc" ]] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.key" ]] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer" ]]; then
		modifyTime=$(stat "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer" | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')

		modifyTime=$(date +%s -d "${modifyTime}")
		currentTime=$(date +%s)
		((stampDiff = currentTime - modifyTime))
		((days = stampDiff / 86400))
		((remainingDays = 90 - days))

		tlsStatus=${remainingDays}
		if [[ ${remainingDays} -le 0 ]]; then
			tlsStatus="expired"
		fi

		echoContent skyBlue " ———> Certificate Generation Date:$(date -d "@${modifyTime}" +"%F %H:%M:%S")"
		echoContent skyBlue " ———> Certificate generation days:${days}"
		echoContent skyBlue " ———> Certificate days remaining:${tlsStatus}"
	fi
}

# Install V2Ray, specify the version
installV2Ray() {
	readInstallType
	echoContent skyBlue "\n progress  $1/${totalProgress} : install V2Ray"

	if [[ "${coreInstallType}" != "2" && "${coreInstallType}" != "3" ]]; then
		if [[ "${selectCoreType}" == "2" ]]; then

			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | head -1)
		else
			version=${v2rayCoreVersion}
		fi

		echoContent green " ---> v2ray-core Version:${version}"
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip" -d /etc/v2ray-agent/v2ray >/dev/null
		rm -rf "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip"
	else
		if [[ "${selectCoreType}" == "3" ]]; then
			echoContent green " ———> Lock the v2ray-core version to v4.32.1"
			rm -f /etc/v2ray-agent/v2ray/v2ray
			rm -f /etc/v2ray-agent/v2ray/v2ctl
			installV2Ray "$1"
		else
			echoContent green " ———> v2ray-core Version:$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"
			read -r -p "Whether to update, upgrade？[y/n]:" reInstallV2RayStatus
			if [[ "${reInstallV2RayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				installV2Ray "$1"
			fi
		fi
	fi
}

# Install xray
installXray() {
	readInstallType
	echoContent skyBlue "\n progress  $1/${totalProgress} : Install Xray"

	if [[ "${coreInstallType}" != "1" ]]; then

		version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[].tag_name | head -1)

		echoContent green " ———> Xray-core version:${version}"
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" -d /etc/v2ray-agent/xray >/dev/null
		rm -rf "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip"
		chmod 655 /etc/v2ray-agent/xray/xray
	else
		echoContent green " ———> Xray-core version:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"
		read -r -p "whether to update、upgrade？[y/n]:" reInstallXrayStatus
		if [[ "${reInstallXrayStatus}" == "y" ]]; then
			rm -f /etc/v2ray-agent/xray/xray
			installXray "$1"
		fi
	fi
}

# v2ray Version management
v2rayVersionManageMenu() {
	echoContent skyBlue "\n progress  $1/${totalProgress} : V2Ray version management"
	if [[ ! -d "/etc/v2ray-agent/v2ray/" ]]; then
		echoContent red " ———> No installation directory detected，Please execute the script to install the content"
		menu
		exit 0
	fi
	echoContent red "\n——————————————————————————————————————————————————————————————"
	echoContent yellow "1.upgrade"
	echoContent yellow "2.go back"
	echoContent yellow "3.close v2ray-core"
	echoContent yellow "4.open v2ray-core"
	echoContent yellow "5.restart v2ray-core"
	echoContent red "——————————————————————————————————————————————————————————————"
	read -r -p "please choose:" selectV2RayType
	if [[ "${selectV2RayType}" == "1" ]]; then
		updateV2Ray
	elif [[ "${selectV2RayType}" == "2" ]]; then
		echoContent yellow "\n1.Only the last five versions can be rolled back"
		echoContent yellow "2.There is no guarantee that it will work normally after the rollback"
		echoContent yellow "3.If the rolled back version does not support the current config, it will fail to connect, proceed with caution"
		echoContent skyBlue "------------------------Version-------------------------------"
		curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | head -5 | awk '{print ""NR""":"$0}'

		echoContent skyBlue "——————————————————————————————————————————————————————————————"
		read -r -p "Please enter the version you want to roll back：" selectV2rayVersionType
		version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | head -5 | awk '{print ""NR""":"$0}' | grep "${selectV2rayVersionType}:" | awk -F "[:]" '{print $2}')
		if [[ -n "${version}" ]]; then
			updateV2Ray "${version}"
		else
			echoContent red "\n ———> Incorrect input, please try again"
			v2rayVersionManageMenu 1
		fi
	elif [[ "${selectXrayType}" == "3" ]]; then
		handleV2Ray stop
	elif [[ "${selectXrayType}" == "4" ]]; then
		handleV2Ray start
	elif [[ "${selectXrayType}" == "5" ]]; then
		reloadCore
	fi
}

# xray version management
xrayVersionManageMenu() {
	echoContent skyBlue "\n progress  $1/${totalProgress} : Xray version management"
	if [[ ! -d "/etc/v2ray-agent/xray/" ]]; then
		echoContent red " ———> No installation directory detected, please execute script to install content"
		menu
		exit 0
	fi
	echoContent red "\n——————————————————————————————————————————————————————————————"
	echoContent yellow "1.upgrade"
	echoContent yellow "2.go back"
	echoContent yellow "3.close Xray-core"
	echoContent yellow "4.open Xray-core"
	echoContent yellow "5.restart Xray-core"
	echoContent red "——————————————————————————————————————————————————————————————"
	read -r -p "please choose:" selectXrayType
	if [[ "${selectXrayType}" == "1" ]]; then
		updateXray
	elif [[ "${selectXrayType}" == "2" ]]; then
		echoContent yellow "\n1.Due to frequent updates of Xray-core, only the latest two versions can be rolled back"
		echoContent yellow "2.There is no guarantee that it will work normally after the rollback"
		echoContent yellow "3.If the rolled back version does not support the current config, it will fail to connect, proceed with caution"
		echoContent skyBlue "------------------------Version-------------------------------"
		curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[].tag_name | head -2 | awk '{print ""NR""":"$0}'
		echoContent skyBlue "——————————————————————————————————————————————————————————————"
		read -r -p "Please enter the version you want to roll back：" selectXrayVersionType
		version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[].tag_name | head -2 | awk '{print ""NR""":"$0}' | grep "${selectXrayVersionType}:" | awk -F "[:]" '{print $2}')
		if [[ -n "${version}" ]]; then
			updateXray "${version}"
		else
			echoContent red "\n ———> Incorrect input, please try again"
			xrayVersionManageMenu 1
		fi
	elif [[ "${selectXrayType}" == "3" ]]; then
		handleXray stop
	elif [[ "${selectXrayType}" == "4" ]]; then
		handleXray start
	elif [[ "${selectXrayType}" == "5" ]]; then
		reloadCore
	fi

}
# Update V2Ray
updateV2Ray() {
	readInstallType
	if [[ -z "${coreInstallType}" ]]; then

		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[0]|select (.prerelease==false)|.tag_name')
		fi
		# Use locked version
		if [[ -n "${v2rayCoreVersion}" ]]; then
			version=${v2rayCoreVersion}
		fi
		echoContent green " ———> v2ray-core Version:${version}"

		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
		else
			wget -c -P "/etc/v2ray-agent/v2ray/ https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip" -d /etc/v2ray-agent/v2ray >/dev/null
		rm -rf "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip"
		handleV2Ray stop
		handleV2Ray start
	else
		echoContent green " ———> Current v2ray-core version:$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"

		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[0]|select (.prerelease==false)|.tag_name')
		fi

		if [[ -n "${v2rayCoreVersion}" ]]; then
			version=${v2rayCoreVersion}
		fi
		if [[ -n "$1" ]]; then
			read -r -p "The fallback version is${version}，Whether to continue？[y/n]:" rollbackV2RayStatus
			if [[ "${rollbackV2RayStatus}" == "y" ]]; then
				if [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
					echoContent green " ———> Current v2ray-core version:$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"
				elif [[ "${coreInstallType}" == "1" ]]; then
					echoContent green " ———> Current Xray-core version:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"
				fi

				handleV2Ray stop
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray "${version}"
			else
				echoContent green " ---> About the fallback version"
			fi
		elif [[ "${version}" == "v$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)" ]]; then
			read -r -p "The current version is the same as the latest version, do you want to reinstall it？[y/n]:" reInstallV2RayStatus
			if [[ "${reInstallV2RayStatus}" == "y" ]]; then
				handleV2Ray stop
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray
			else
				echoContent green " ———> give up reinstall"
			fi
		else
			read -r -p "The latest version is：${version}，whether to update？[y/n]：" installV2RayStatus
			if [[ "${installV2RayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray
			else
				echoContent green " ———> give up update"
			fi

		fi
	fi
}

# Update Xray
updateXray() {
	readInstallType
	if [[ -z "${coreInstallType}" ]]; then
		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[0].tag_name)
		fi

		echoContent green " ———> Xray-core Version:${version}"

		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" -d /etc/v2ray-agent/xray >/dev/null
		rm -rf "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip"
		chmod 655 /etc/v2ray-agent/xray/xray
		handleXray stop
		handleXray start
	else
		echoContent green " ———> Current Xray-core version:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"

		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[0].tag_name)
		fi

		if [[ -n "$1" ]]; then
			read -r -p "The fallback version is${version}，Whether to continue？[y/n]:" rollbackXrayStatus
			if [[ "${rollbackXrayStatus}" == "y" ]]; then
				echoContent green " ———> Current Xray-core version:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"

				handleXray stop
				rm -f /etc/v2ray-agent/xray/xray
				updateXray "${version}"
			else
				echoContent green " ———> Abandon the fallback version"
			fi
		elif [[ "${version}" == "v$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)" ]]; then
			read -r -p "The current version is the same as the latest version, do you want to reinstall it？[y/n]:" reInstallXrayStatus
			if [[ "${reInstallXrayStatus}" == "y" ]]; then
				handleXray stop
				rm -f /etc/v2ray-agent/xray/xray
				rm -f /etc/v2ray-agent/xray/xray
				updateXray
			else
				echoContent green " ———> give up reinstall"
			fi
		else
			read -r -p "The latest version is：${version}，whether to update？[y/n]：" installXrayStatus
			if [[ "${installXrayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/xray/xray
				updateXray
			else
				echoContent green " ———> give up update"
			fi

		fi
	fi
}

# Verify that the entire service is available
checkGFWStatue() {
	readInstallType
	echoContent skyBlue "\n progress $1/${totalProgress} : Verify service startup status"
	if [[ "${coreInstallType}" == "1" ]] && [[ -n $(pgrep -f xray/xray) ]]; then
		echoContent green " ———> Service started successfully"
	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]] && [[ -n $(pgrep -f v2ray/v2ray) ]]; then
		echoContent green " ———> Service started successfully"
	else
		echoContent red " ———> The service failed to start, please check whether there is a log print on the terminal"
		exit 0
	fi

}

# V2Ray starts automatically
installV2RayService() {
	echoContent skyBlue "\n progress  $1/${totalProgress} : Configuring V2Ray to start automatically at boot"
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
		rm -rf /etc/systemd/system/v2ray.service
		touch /etc/systemd/system/v2ray.service
		execStart='/etc/v2ray-agent/v2ray/v2ray -confdir /etc/v2ray-agent/v2ray/conf'
		cat <<EOF >/etc/systemd/system/v2ray.service
[Unit]
Description=V2Ray - A unified platform for anti-censorship
Documentation=https://v2ray.com https://guide.v2fly.org
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=${execStart}
Restart=on-failure
RestartPreventExitStatus=23


[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable v2ray.service
		echoContent green " ———> Configure V2Ray to start successfully after booting"
	fi
}

# Xray starts automatically
installXrayService() {
	echoContent skyBlue "\n progress  $1/${totalProgress} : Configure Xray to start automatically at boot"
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
		rm -rf /etc/systemd/system/xray.service
		touch /etc/systemd/system/xray.service
		execStart='/etc/v2ray-agent/xray/xray run -confdir /etc/v2ray-agent/xray/conf'
		cat <<EOF >/etc/systemd/system/xray.service
[Unit]
Description=Xray - A unified platform for anti-censorship
# Documentation=https://v2ray.com https://guide.v2fly.org
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=${execStart}
Restart=on-failure
RestartPreventExitStatus=23


[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable xray.service
		echoContent green " ———> Configure Xray to start successfully after booting"
	fi
}

# Operate V2Ray
handleV2Ray() {
	# shellcheck disable=SC2010
	if find /bin /usr/bin | grep -q systemctl && ls /etc/systemd/system/ | grep -q v2ray.service; then
		if [[ -z $(pgrep -f "v2ray/v2ray") ]] && [[ "$1" == "start" ]]; then
			systemctl start v2ray.service
		elif [[ -n $(pgrep -f "v2ray/v2ray") ]] && [[ "$1" == "stop" ]]; then
			systemctl stop v2ray.service
		fi
	fi
	sleep 0.8

	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "v2ray/v2ray") ]]; then
			echoContent green " ———> V2Ray started successfully"
		else
			echoContent red "V2Ray failed to start"
			echoContent red "Please do it manually【/etc/v2ray-agent/v2ray/v2ray -confdir /etc/v2ray-agent/v2ray/conf】，View the error log"
			exit 0
		fi
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "v2ray/v2ray") ]]; then
			echoContent green " ———> V2Ray closed successfully"
		else
			echoContent red "V2Ray failed to close"
			echoContent red "Please do it manually【ps -ef|grep -v grep|grep v2ray|awk '{print \$2}'|xargs kill -9】"
			exit 0
		fi
	fi
}
# operate xray
handleXray() {
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]] && [[ -n $(find /etc/systemd/system/ -name "xray.service") ]]; then
		if [[ -z $(pgrep -f "xray/xray") ]] && [[ "$1" == "start" ]]; then
			systemctl start xray.service
		elif [[ -n $(pgrep -f "xray/xray") ]] && [[ "$1" == "stop" ]]; then
			systemctl stop xray.service
		fi
	fi

	sleep 0.8

	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "xray/xray") ]]; then
			echoContent green " ———> Xray started successfully"
		else
			echoContent red "xray failed to start"
			echoContent red "Please do it manually【/etc/v2ray-agent/xray/xray -confdir /etc/v2ray-agent/xray/conf】，View the error log"
			exit 0
		fi
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "xray/xray") ]]; then
			echoContent green " ———> Xray closed successfully"
		else
			echoContent red "xray close failed"
			echoContent red "Please do it manually【ps -ef|grep -v grep|grep xray|awk '{print \$2}'|xargs kill -9】"
			exit 0
		fi
	fi
}

# Initialize the V2Ray configuration file
initV2RayConfig() {
	echoContent skyBlue "\n progress $2/${totalProgress} : Initialize V2Ray configuration"
	echo

	read -r -p "Customize UUID ？[y/n]:" customUUIDStatus
	echo
	if [[ "${customUUIDStatus}" == "y" ]]; then
		read -r -p "Customize UUID:" currentCustomUUID
		if [[ -n "${currentCustomUUID}" ]]; then
			uuid=${currentCustomUUID}
		fi
	fi

	if [[ -n "${currentUUID}" && -z "${uuid}" ]]; then
		read -r -p "Read to last installation record，Whether to use the UUID from the last install ？[y/n]:" historyUUIDStatus
		if [[ "${historyUUIDStatus}" == "y" ]]; then
			uuid=${currentUUID}
		else
			uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
		fi
	elif [[ -z "${uuid}" ]]; then
		uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
	fi

	if [[ -z "${uuid}" ]]; then
		echoContent red "\n ———> uuid read error, regenerate"
		uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
	fi

	rm -rf /etc/v2ray-agent/v2ray/conf/*
	rm -rf /etc/v2ray-agent/v2ray/config_full.json

	# log
	cat <<EOF >/etc/v2ray-agent/v2ray/conf/00_log.json
{
  "log": {
    "error": "/etc/v2ray-agent/v2ray/error.log",
    "loglevel": "warning"
  }
}
EOF
	# outbounds
	if [[ -n "${pingIPv6}" ]]; then
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/10_ipv6_outbounds.json
{
    "outbounds": [
        {
          "protocol": "freedom",
          "settings": {},
          "tag": "direct"
        }
    ]
}
EOF

	else
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF
	fi

	# dns
	cat <<EOF >/etc/v2ray-agent/v2ray/conf/11_dns.json
{
    "dns": {
        "servers": [
          "localhost"
        ]
  }
}
EOF

	# VLESS_TCP_TLS
	# fall back on nginx
	local fallbacksList='{"dest":31300,"xver":0},{"alpn":"h2","dest":31302,"xver":0}'

	# trojan
	if echo "${selectCustomInstallType}" | grep -q 4 || [[ "$1" == "all" ]]; then
		fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":0}'
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/04_trojan_TCP_inbounds.json
{
"inbounds":[
	{
	  "port": 31296,
	  "listen": "127.0.0.1",
	  "protocol": "trojan",
	  "tag":"trojanTCP",
	  "settings": {
		"clients": [
		  {
			"password": "${uuid}",
			"email": "${domain}"
		  }
		],
		"fallbacks":[
			{"dest":"31300"}
		]
	  },
	  "streamSettings": {
		"network": "tcp",
		"security": "none",
		"tcpSettings": {
			"acceptProxyProtocol": true
		}
	  }
	}
	]
}
EOF
	fi

	# VLESS_WS_TLS
	if echo "${selectCustomInstallType}" | grep -q 1 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'ws","dest":31297,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/03_VLESS_WS_inbounds.json
{
"inbounds":[
    {
  "port": 31297,
  "listen": "127.0.0.1",
  "protocol": "vless",
  "tag":"VLESSWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "email": "${domain}"
      }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}ws"
    }
  }
}
]
}
EOF
	fi

	# trojan_grpc
	if echo "${selectCustomInstallType}" | grep -q 2 || [[ "$1" == "all" ]]; then
		if ! echo "${selectCustomInstallType}" | grep -q 5 && [[ -n ${selectCustomInstallType} ]]; then
			fallbacksList=${fallbacksList//31302/31304}
		fi

		cat <<EOF >/etc/v2ray-agent/v2ray/conf/04_trojan_gRPC_inbounds.json
{
    "inbounds": [
        {
            "port": 31304,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "tag": "trojangRPCTCP",
            "settings": {
                "clients": [
                    {
                        "password": "${uuid}",
                        "email": "${domain}"
                    }
                ],
                "fallbacks": [
                    {
                        "dest": "31300"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${customPath}trojangrpc"
                }
            }
        }
    ]
}
EOF
	fi

	# VMess_WS
	if echo "${selectCustomInstallType}" | grep -q 3 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'vws","dest":31299,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/05_VMess_WS_inbounds.json
{
"inbounds":[
{
  "listen": "127.0.0.1",
  "port": 31299,
  "protocol": "vmess",
  "tag":"VMessWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "alterId": 0,
        "add": "${add}",
        "email": "${domain}"
      }
    ]
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}vws"
    }
  }
}
]
}
EOF
	fi

	# VMess_grpc
	if echo "${selectCustomInstallType}" | grep -q 6 || [[ "$1" == "all" ]]; then
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/07_VMess_gRPC_inbounds.json
{
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": 31305,
            "protocol": "vmess",
            "tag": "VMessgRPC",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "alterId": 0,
                        "add": "${add}",
                        "email": "${domain}"
                    }
                ],
                "disableInsecureEncryption": true
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${customPath}VMgrpc"
                }
            }
        }
    ]
}
EOF
	fi

	if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]]; then
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/06_VLESS_gRPC_inbounds.json
{
    "inbounds":[
    {
        "port": 31301,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "tag":"VLESSGRPC",
        "settings": {
            "clients": [
                {
                    "id": "${uuid}",
                    "add": "${add}",
                    "email": "${domain}"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "${customPath}grpc"
                "multiMode": "true"
            }
        }
    }
]
}
EOF
	fi

	# VLESS_TCP
	cat <<EOF >/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json
{
"inbounds":[
{
  "port": 443,
  "protocol": "vless",
  "tag":"VLESSTCP",
  "settings": {
    "clients": [
     {
        "id": "${uuid}",
        "add":"${add}",
        "email": "${domain}"
      }
    ],
    "decryption": "none",
    "fallbacks": [
        ${fallbacksList}
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "minVersion": "1.2",
      "alpn": [
        "http/1.1",
        "h2"
      ],
      "certificates": [
        {
          "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
          "keyFile": "/etc/v2ray-agent/tls/${domain}.key",
          "ocspStapling": 3600,
          "usage":"encipherment"
        }
      ]
    }
  }
}
]
}
EOF

}

# Initialize the Xray Trojan XTLS configuration file
initXrayFrontingConfig() {
	if [[ -z "${configPath}" ]]; then
		echoContent red " ———> Not installed, please use script to install"
		menu
		exit 0
	fi
	if [[ "${coreInstallType}" != "1" ]]; then
		echoContent red " ———> Available types not installed"
	fi
	local xtlsType=
	if echo ${currentInstallProtocolType} | grep -q trojan; then
		xtlsType=VLESS
	else
		xtlsType=Trojan

	fi

	echoContent skyBlue "\n function 1/${totalProgress} : Front switch to${xtlsType}"
	echoContent red "\n——————————————————————————————————————————————————————————————"
	echoContent yellow "# Precautions\n"
	echoContent yellow "will replace the prefix with${xtlsType}"
	echoContent yellow "If the prefix is Trojan, when viewing the account, there will be two nodes of the Trojan protocol, one of which is unavailable xtls"
	echoContent yellow "Execute again to switch to the previous preamble\n"

	echoContent yellow "1.switch to${xtlsType}"
	echoContent red "——————————————————————————————————————————————————————————————"
	read -r -p "please choose:" selectType
	if [[ "${selectType}" == "1" ]]; then

		if [[ "${xtlsType}" == "Trojan" ]]; then

			local VLESSConfig
			VLESSConfig=$(cat ${configPath}${frontingType}.json)
			VLESSConfig=${VLESSConfig//"id"/"password"}
			VLESSConfig=${VLESSConfig//VLESSTCP/TrojanTCPXTLS}
			VLESSConfig=${VLESSConfig//VLESS/Trojan}
			VLESSConfig=${VLESSConfig//"vless"/"trojan"}
			VLESSConfig=${VLESSConfig//"id"/"password"}

			echo "${VLESSConfig}" | jq . >${configPath}02_trojan_TCP_inbounds.json
			rm ${configPath}${frontingType}.json
		elif [[ "${xtlsType}" == "VLESS" ]]; then

			local VLESSConfig
			VLESSConfig=$(cat ${configPath}02_trojan_TCP_inbounds.json)
			VLESSConfig=${VLESSConfig//"password"/"id"}
			VLESSConfig=${VLESSConfig//TrojanTCPXTLS/VLESSTCP}
			VLESSConfig=${VLESSConfig//Trojan/VLESS}
			VLESSConfig=${VLESSConfig//"trojan"/"vless"}
			VLESSConfig=${VLESSConfig//"password"/"id"}

			echo "${VLESSConfig}" | jq . >${configPath}02_VLESS_TCP_inbounds.json
			rm ${configPath}02_trojan_TCP_inbounds.json
		fi
		reloadCore
	fi

	exit 0
}

# Initialize the Xray configuration file
initXrayConfig() {
	echoContent skyBlue "\n progress $2/${totalProgress} : Initialize Xray configuration"
	echo
	local uuid=
	if [[ -n "${currentUUID}" ]]; then
		read -r -p "Read to last installation record，Whether to use the last installation UUID ？[y/n]:" historyUUIDStatus
		if [[ "${historyUUIDStatus}" == "y" ]]; then
			uuid=${currentUUID}
			echoContent green "\n ———> Use successfully"
		else
			uuid=$(/etc/v2ray-agent/xray/xray uuid)
		fi
	fi

	if [[ -z "${uuid}" ]]; then
		echoContent yellow "Please enter a custom UUID[legal]，[Enter]random UUID"
		read -r -p 'UUID:' customUUID

		if [[ -n ${customUUID} ]]; then
			uuid=${customUUID}
		else
			uuid=$(/etc/v2ray-agent/xray/xray uuid)
		fi

	fi

	if [[ -z "${uuid}" ]]; then
		echoContent red "\n ———> uuid read error，regenerate"
		uuid=$(/etc/v2ray-agent/xray/xray uuid)
	fi

	echoContent yellow "\n ${uuid}"

	rm -rf /etc/v2ray-agent/xray/conf/*

	# log
	cat <<EOF >/etc/v2ray-agent/xray/conf/00_log.json
{
  "log": {
    "error": "/etc/v2ray-agent/xray/error.log",
    "loglevel": "warning"
  }
}
EOF

	# outbounds
	if [[ -n "${pingIPv6}" ]]; then
		cat <<EOF >/etc/v2ray-agent/xray/conf/10_ipv6_outbounds.json
{
    "outbounds": [
        {
          "protocol": "freedom",
          "settings": {},
          "tag": "direct"
        }
    ]
}
EOF

	else
		cat <<EOF >/etc/v2ray-agent/xray/conf/10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF
	fi

	# dns
	cat <<EOF >/etc/v2ray-agent/xray/conf/11_dns.json
{
    "dns": {
        "servers": [
          "localhost"
        ]
  }
}
EOF

	# VLESS_TCP_TLS/XTLS
	# fall back on nginx
	local fallbacksList='{"dest":31300,"xver":0},{"alpn":"h2","dest":31302,"xver":0}'

	# trojan
	if echo "${selectCustomInstallType}" | grep -q 4 || [[ "$1" == "all" ]]; then
		fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":0}'
		cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_TCP_inbounds.json
{
"inbounds":[
	{
	  "port": 31296,
	  "listen": "127.0.0.1",
	  "protocol": "trojan",
	  "tag":"trojanTCP",
	  "settings": {
		"clients": [
		  {
			"password": "${uuid}",
			"email": "${domain}"
		  }
		],
		"fallbacks":[
			{"dest":"31300"}
		]
	  },
	  "streamSettings": {
		"network": "tcp",
		"security": "none",
		"tcpSettings": {
			"acceptProxyProtocol": true
		}
	  }
	}
	]
}
EOF
	fi

	# VLESS_WS_TLS
	if echo "${selectCustomInstallType}" | grep -q 1 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'ws","dest":31297,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/xray/conf/03_VLESS_WS_inbounds.json
{
"inbounds":[
    {
  "port": 31297,
  "listen": "127.0.0.1",
  "protocol": "vless",
  "tag":"VLESSWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "email": "${domain}"
      }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}ws"
    }
  }
}
]
}
EOF
	fi

	# trojan_grpc
	if echo "${selectCustomInstallType}" | grep -q 2 || [[ "$1" == "all" ]]; then
		if ! echo "${selectCustomInstallType}" | grep -q 5 && [[ -n ${selectCustomInstallType} ]]; then
			fallbacksList=${fallbacksList//31302/31304}
		fi

		cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_gRPC_inbounds.json
{
    "inbounds": [
        {
            "port": 31304,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "tag": "trojangRPCTCP",
            "settings": {
                "clients": [
                    {
                        "password": "${uuid}",
                        "email": "${domain}"
                    }
                ],
                "fallbacks": [
                    {
                        "dest": "31300"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${customPath}trojangrpc"
                }
            }
        }
    ]
}
EOF
	fi

	# VMess_WS
	if echo "${selectCustomInstallType}" | grep -q 3 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'vws","dest":31299,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/xray/conf/05_VMess_WS_inbounds.json
{
"inbounds":[
{
  "listen": "127.0.0.1",
  "port": 31299,
  "protocol": "vmess",
  "tag":"VMessWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "alterId": 0,
        "add": "${add}",
        "email": "${domain}"
      }
    ]
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}vws"
    }
  }
}
]
}
EOF
	fi

	if echo "${selectCustomInstallType}" | grep -q 6 || [[ "$1" == "all" ]]; then
		cat <<EOF >/etc/v2ray-agent/xray/conf/07_VMess_gRPC_inbounds.json
{
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": 31305,
            "protocol": "vmess",
            "tag": "VMessgRPC",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "alterId": 0,
                        "add": "${add}",
                        "email": "${domain}"
                    }
                ],
                "disableInsecureEncryption": true
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${customPath}VMgrpc"
                }
            }
        }
    ]
}
EOF
	fi

	if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]]; then
		cat <<EOF >/etc/v2ray-agent/xray/conf/06_VLESS_gRPC_inbounds.json
{
    "inbounds":[
    {
        "port": 31301,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "tag":"VLESSGRPC",
        "settings": {
            "clients": [
                {
                    "id": "${uuid}",
                    "add": "${add}",
                    "email": "${domain}"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "${customPath}grpc"
                "multiMode": "true"
            }
        }
    }
]
}
EOF
	fi

	# VLESS_TCP
	cat <<EOF >/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json
{
"inbounds":[
{
  "port": 443,
  "protocol": "vless",
  "tag":"VLESSTCP",
  "settings": {
    "clients": [
     {
        "id": "${uuid}",
        "add":"${add}",
        "flow":"xtls-rprx-direct",
        "email": "${domain}"
      }
    ],
    "decryption": "none",
    "fallbacks": [
        ${fallbacksList}
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "xtls",
    "xtlsSettings": {
      "minVersion": "1.2",
      "alpn": [
        "http/1.1",
        "h2"
      ],
      "certificates": [
        {
          "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
          "keyFile": "/etc/v2ray-agent/tls/${domain}.key",
          "ocspStapling": 3600,
          "usage":"encipherment"
        }
      ]
    }
  }
}
]
}
EOF
}

# Initialize Trojan-Go configuration
initTrojanGoConfig() {

	echoContent skyBlue "\n progress $1/${totalProgress} : Initialize Trojan configuration"
	cat <<EOF >/etc/v2ray-agent/trojan/config_full.json
{
    "run_type": "server",
    "local_addr": "127.0.0.1",
    "local_port": 31296,
    "remote_addr": "127.0.0.1",
    "remote_port": 31300,
    "disable_http_check":true,
    "log_level":3,
    "log_file":"/etc/v2ray-agent/trojan/trojan.log",
    "password": [
        "${uuid}"
    ],
    "dns":[
        "localhost"
    ],
    "transport_plugin":{
        "enabled":true,
        "type":"plaintext"
    },
    "websocket": {
        "enabled": true,
        "path": "/${customPath}tws",
        "host": "${domain}",
        "add":"${add}"
    },
    "router": {
        "enabled": false
    }
}
EOF
}

# Custom CDN IP
customCDNIP() {
	echoContent skyBlue "\n progress $1/${totalProgress} : Add cloudflare custom CNAME"
	echoContent red "\n——————————————————————————————————————————————————————————————"
	echoContent yellow "# Precautions"
	echoContent yellow "\nTutorial address:"
	echoContent skyBlue "https://github.com/mack-a/v2ray-agent/blob/master/documents/optimize_V2Ray.md"
	echoContent red "\nIf you don't understand Cloudflare optimization，please do not use"
	echoContent yellow "\n 1.CNAME:104.16.123.96"
	echoContent yellow " 2.CNAME:www.cloudflare.com"
	echoContent yellow " 3.CNAME:www.digitalocean.com"
	echoContent skyBlue "————————————————————————————"
	read -r -p "please choose[Carriage return is not used]:" selectCloudflareType
	case ${selectCloudflareType} in
	1)
		add="104.16.123.96"
		;;
	2)
		add="www.cloudflare.com"
		;;
	3)
		add="www.digitalocean.com"
		;;
	*)
		add="${domain}"
		echoContent yellow "\n ———> Do not use"
		;;
	esac
}
# Universal
defaultBase64Code() {
	local type=$1
	local email=$2
	local id=$3
	local hostPort=$4
	local host=
	local port=
	if echo "${hostPort}" | grep -q ":"; then
		host=$(echo "${hostPort}" | awk -F "[:]" '{print $1}')
		port=$(echo "${hostPort}" | awk -F "[:]" '{print $2}')
	else
		host=${hostPort}
		port=443
	fi

	local path=$5
	local add=$6

	local subAccount
	subAccount=${currentHost}_$(echo "${id}_currentHost" | md5sum | awk '{print $1}')

	if [[ "${type}" == "vlesstcp" ]]; then

		if [[ "${coreInstallType}" == "1" ]] && echo "${currentInstallProtocolType}" | grep -q 0; then
			echoContent yellow " ———> General format(VLESS+TCP+TLS/xtls-rprx-direct)"
			echoContent green "    vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}\n"

			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}
EOF

			echoContent skyBlue "—————————————————————————————————————————————————————————————————————————————————"

			echoContent yellow " ———> General format(VLESS+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email/direct/splice}\n"

			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email/direct/splice}
EOF

		elif [[ "${coreInstallType}" == 2 || "${coreInstallType}" == "3" ]]; then
			echoContent yellow " ———> General format(VLESS+TCP+TLS)"
			echoContent green "    vless://${id}@${host}:${port}?security=tls&encryption=none&host=${host}&headerType=none&type=tcp#${email}\n"

			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${host}:${port}?security=tls&encryption=none&host=${host}&headerType=none&type=tcp#${email}
EOF
		fi

	elif [[ "${type}" == "trojanTCPXTLS" ]]; then
		echoContent yellow " ———> General format(Trojan+TCP+TLS/xtls-rprx-direct)"
		echoContent green "    trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}
EOF

		echoContent skyBlue "—————————————————————————————————————————————————————————————————————————————————"

		echoContent yellow " ———> General format(Trojan+TCP+TLS/xtls-rprx-splice)"
		echoContent green "    trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email/direct/splice}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email/direct/splice}
EOF

	elif [[ "${type}" == "vmessws" ]]; then
		qrCodeBase64Default=$(echo -n "{\"port\":${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${host}\",\"type\":\"none\",\"path\":\"/${path}\",\"net\":\"ws\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${host}\",\"sni\":\"${host}\"}" | base64 -w 0)
		qrCodeBase64Default="${qrCodeBase64Default// /}"

		echoContent yellow " ———> General format(VMess+WS+TLS)Link"
		echoContent green "    vmess://${qrCodeBase64Default}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vmess://${qrCodeBase64Default}
EOF

	elif [[ "${type}" == "vmesstcp" ]]; then

		echoContent red "path:${path}"
		qrCodeBase64Default=$(echo -n "{\"add\":\"${add}\",\"aid\":0,\"host\":\"${host}\",\"id\":\"${id}\",\"net\":\"tcp\",\"path\":\"${path}\",\"port\":${port},\"ps\":\"${email}\",\"scy\":\"none\",\"sni\":\"${host}\",\"tls\":\"tls\",\"v\":2,\"type\":\"http\",\"allowInsecure\":0,\"peer\":\"${host}\",\"obfs\":\"http\",\"obfsParam\":\"${host}\"}" | base64)
		qrCodeBase64Default="${qrCodeBase64Default// /}"

		echoContent yellow " ———> General format(VMess+TCP+TLS)Link"
		echoContent green "    vmess://${qrCodeBase64Default}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vmess://${qrCodeBase64Default}
EOF

	elif [[ "${type}" == "vmessws" ]]; then
		qrCodeBase64Default=$(echo -n "{\"port\":${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"",\"type\":\"none\",\"path\":\"${path}\",\"net\":\"grpc\",\"add\":\"${add}\",\"allowInsecure\":0,\"sni\":\"${host}\"}" | base64 -w 0)
		qrCodeBase64Default="${qrCodeBase64Default// /}"

		echoContent yellow " ---> Universal vmess(VMess+WS+TLS)Link"
		echoContent green "    vmess://${qrCodeBase64Default}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vmess://${qrCodeBase64Default}
EOF

	elif [[ "${type}" == "vlessgrpc" ]]; then

		echoContent yellow " ---> General format(VLESS+gRPC+TLS)"
		echoContent green "    vless://${id}@${add}:${port}?mode=multi&encryption=none&security=tls&type=grpc&host=${host}&path=${path}&serviceName=${path}&alpn=h2&sni=${host}#${email}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${add}:${port}?mode=multi&encryption=none&security=tls&type=grpc&host=${host}&path=${path}&serviceName=${path}&alpn=h2&sni=${host}#${email}
EOF

	elif [[ "${type}" == "vlessws" ]]; then

		echoContent yellow " ———> General format(VLESS+WS+TLS)"
		echoContent green "    vless://${id}@${add}:${port}?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2f${path}#${email}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${add}:${port}?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2f${path}#${email}
EOF

	elif [[ "${type}" == "trojan" ]]; then
		# URLEncode
		echoContent yellow " ———> Trojan(TLS)"
		echoContent green "    trojan://${id}@${host}:${port}?peer=${host}&sni=${host}&alpn=http1.1#${email}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?peer=${host}&sni=${host}&alpn=http1.1#${email}
EOF

	elif [[ "${type}" == "trojangrpc" ]]; then
		# URLEncode

		echoContent yellow " ———> Trojan gRPC(TLS)"
		echoContent green "    trojan://${id}@${host}:${port}?encryption=none&peer=${host}&security=tls&type=grpc&sni=${host}&alpn=h2&path=${path}&serviceName=${path}#${email}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?encryption=none&peer=${host}&security=tls&type=grpc&sni=${host}&alpn=h2&path=${path}&serviceName=${path}#${email}
EOF

	fi

}

# account
showAccounts() {
	readInstallType
	readInstallProtocolType
	readConfigHostPathUUID
	echoContent skyBlue "\n schedule $1/${totalProgress} : account"
	local show
	# VLESS TCP
	if [[ -n "${configPath}" ]]; then
		show=1
		if echo "${currentInstallProtocolType}" | grep -q trojan; then
			echoContent skyBlue "———————————— Trojan TCP TLS/XTLS-direct/XTLS-splice ———————————— \n"
			jq .inbounds[0].settings.clients ${configPath}02_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> account number：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .password)"
				echo
				defaultBase64Code trojanTCPXTLS "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .password)" "${currentHost}:${currentPort}" "${currentHost}"
			done

		else
			echoContent skyBlue "———————————— VLESS TCP TLS/XTLS-direct/XTLS-splice ————————————\n"
			jq .inbounds[0].settings.clients ${configPath}02_VLESS_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> account number：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .id)"
				echo
				defaultBase64Code vlesstcp "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)" "${currentHost}:${currentPort}" "${currentHost}"
			done
		fi

		# VLESS WS
		if echo ${currentInstallProtocolType} | grep -q 1; then
			echoContent skyBlue "\n————————————————————————————VLESS WS ————————————————————————————\n"

			jq .inbounds[0].settings.clients ${configPath}03_VLESS_WS_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> account number：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .id)"
				echo
				local path="${currentPath}ws"
				#				if [[ ${coreInstallType} == "1" ]]; then
				#					echoContent yellow "Xray's 0-RTT path will be behind, which is not compatible with v2ray-centric clients, please delete it manually and use\n"
				#					path="${currentPath}ws"
				#				fi
				defaultBase64Code vlessws "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)" "${currentHost}:${currentPort}" "${path}" "${currentAdd}"
			done
		fi

		# VLESS grpc
		if echo ${currentInstallProtocolType} | grep -q 5; then
			echoContent skyBlue "\n———————————————————————————— VLESS gRPC ————————————————————————————\n"
			local serviceName
			serviceName=$(jq -r .inbounds[0].streamSettings.grpcSettings.serviceName ${configPath}06_VLESS_gRPC_inbounds.json)
			jq .inbounds[0].settings.clients ${configPath}06_VLESS_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> account number：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .id)"
				echo
				defaultBase64Code vlessgrpc "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)" "${currentHost}:${currentPort}" "${serviceName}" "${currentAdd}"
			done
		fi

		# VMess WS
		if echo ${currentInstallProtocolType} | grep -q 3; then
			echoContent skyBlue "\n———————————————————————————— VMess WS ————————————————————————————\n"
			local path="${currentPath}vws"
			if [[ ${coreInstallType} == "1" ]]; then
				path="${currentPath}vws"
			fi
			jq .inbounds[0].settings.clients ${configPath}05_VMess_WS_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> account number：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .id)"
				echo
				defaultBase64Code vmessws "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)" "${currentHost}:${currentPort}" "${path}" "${currentAdd}"
			done
		fi

		# VMess gRPC
		if echo ${currentInstallProtocolType} | grep -q 6; then
			echoContent skyBlue "\n———————————————————————————— VMess gRPC ————————————————————————————\n"
			local path="${currentPath}VMgrpc"
			if [[ ${coreInstallType} == "1" ]]; then
				path="${currentPath}VMgrpc"
			fi
			jq .inbounds[0].settings.clients ${configPath}07_VMess_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> account number：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .id)"
				echo
				defaultBase64Code vmessgrpc "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)" "${currentHost}:${currentPort}" "${path}" "${currentAdd}"
			done
		fi
	fi

	# trojan tcp
	if echo ${currentInstallProtocolType} | grep -q 4; then
		echoContent skyBlue "\n———————————————————————————— Trojan GFW ————————————————————————————\n"
		jq .inbounds[0].settings.clients ${configPath}04_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
			echoContent skyBlue "\n ---> account number：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .password)"
			echo
			defaultBase64Code trojan trojan "$(echo "${user}" | jq -r .password)" "${currentHost}"
		done
	fi

	if echo ${currentInstallProtocolType} | grep -q 2; then
		echoContent skyBlue "\n————————————————————————————  Trojan gRPC  ————————————————————————————\n"
		local serviceName=
		serviceName=$(jq -r .inbounds[0].streamSettings.grpcSettings.serviceName ${configPath}04_trojan_gRPC_inbounds.json)
		jq .inbounds[0].settings.clients ${configPath}04_trojan_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
			echoContent skyBlue "\n ---> account number：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .password)"
			echo
			defaultBase64Code trojangrpc "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .password)" "${currentHost}:${currentPort}" "${serviceName}" "${currentAdd}"
		done
	fi

	if [[ -z ${show} ]]; then
		echoContent red " ---> Not Installed"
	fi
}

# Update camouflage station
updateNginxBlog() {
	echoContent skyBlue "\n schedule $1/${totalProgress} : Replace the camouflage site"
	echoContent red "—————————————————————————————————————————————————————————————"
	echoContent yellow "# To customize, manually copy the template file to /usr/share/nginx/html \n"
	echoContent yellow "1.Beginner's guide"
	echoContent yellow "2.Game website"
	echoContent yellow "3.personal blog01"
	echoContent yellow "4.Businesses"
	echoContent yellow "5.Unlock the encrypted music file template[https://github.com/ix64/unlock-music]"
	echoContent yellow "6.mikutap[https://github.com/HFIProgramming/mikutap]"
	echoContent yellow "7.Enterprise station 02"
	echoContent yellow "8.Personal blog 02"
	echoContent yellow "9.404 Automatic jump Baidu"
	echoContent red "—————————————————————————————————————————————————————————————"
	read -r -p "please choose：" selectInstallNginxBlogType

	if [[ "${selectInstallNginxBlogType}" =~ ^[1-9]$ ]]; then
		#		rm -rf /usr/share/nginx/html
		rm -rf /usr/share/nginx/*
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /usr/share/nginx "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${selectInstallNginxBlogType}.zip" >/dev/null
		else
			wget -c -P /usr/share/nginx "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${selectInstallNginxBlogType}.zip" >/dev/null
		fi

		unzip -o "/usr/share/nginx/html${selectInstallNginxBlogType}.zip" -d /usr/share/nginx/html >/dev/null
		rm -f "/usr/share/nginx/html${selectInstallNginxBlogType}.zip*"
		echoContent green " ---> The replacement of the fake station succeeded"
	else
		echoContent red " ---> Incorrect selection, please reselect"
		updateNginxBlog
	fi
}

# Add new port
addCorePort() {
	echoContent skyBlue "\n Function 1/${totalProgress} : Add a new port"
	echoContent red "\n—————————————————————————————————————————————————————————————"
	echoContent yellow "# Precautions\n"
	echoContent yellow "Support quantity added"
	echoContent yellow "Does not affect the use of port 443"
	echoContent yellow "When viewing accounts, only accounts with default port 443 will be displayed."
	echoContent yellow "Special characters are not allowed, pay attention to the format of comma"
	echoContent yellow "Entry example: 2053, 2083, 2087\n"

	echoContent yellow "1.Add ports"
	echoContent yellow "2.Delete ports"
	echoContent red "—————————————————————————————————————————————————————————————"
	read -r -p "please choose:" selectNewPortType
	if [[ "${selectNewPortType}" == "1" ]]; then
		read -r -p "Please enter the port number：" newPort
		if [[ -n "${newPort}" ]]; then

			while read -r port; do
				cat <<EOF >"${configPath}02_dokodemodoor_inbounds_${port}.json"
{
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${port},
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 443,
        "network": "tcp",
        "followRedirect": false
      },
      "tag": "dokodemo-door-newPort-${port}"
    }
  ]
}
EOF
			done < <(echo "${newPort}" | tr ',' '\n')

			echoContent green " ---> Added successfully"
			reloadCore
		fi
	elif [[ "${selectNewPortType}" == "2" ]]; then

		find ${configPath} -name "*dokodemodoor*" | awk -F "[c][o][n][f][/]" '{print ""NR""":"$2}'
		read -r -p "Please enter the port number to delete：" portIndex
		local dokoConfig
		dokoConfig=$(find ${configPath} -name "*dokodemodoor*" | awk -F "[c][o][n][f][/]" '{print ""NR""":"$2}' | grep "${portIndex}:")
		if [[ -n "${dokoConfig}" ]]; then
			rm "${configPath}/$(echo "${dokoConfig}" | awk -F "[:]" '{print $2}')"
			reloadCore
		else
			echoContent yellow "\n ---> The number was entered incorrectly, please select again"
			addCorePort
		fi
	fi
}

# uninstall script
unInstall() {
	read -r -p "Are you sure you want to uninstall the installation content? [y/n]:" unInstallStatus
	if [[ "${unInstallStatus}" != "y" ]]; then
		echoContent green " ---> give up uninstall"
		menu
		exit 0
	fi

	handleNginx stop
	if [[ -z $(pgrep -f "nginx") ]]; then
		echoContent green " ---> Stop Nginx successfully"
	fi

	handleV2Ray stop
	#	handleTrojanGo stop

	if [[ -f "/root/.acme.sh/acme.sh.env" ]] && grep -q 'acme.sh.env' </root/.bashrc; then
		sed -i 's/. "\/root\/.acme.sh\/acme.sh.env"//g' "$(grep '. "/root/.acme.sh/acme.sh.env"' -rl /root/.bashrc)"
	fi
	rm -rf /root/.acme.sh
	echoContent green " ---> delete acme.sh done"
	rm -rf /etc/systemd/system/v2ray.service
	echoContent green " ---> Deletion of V2Ray is completed after booting"

	rm -rf /tmp/v2ray-agent-tls/*
	if [[ -d "/etc/v2ray-agent/tls" ]] && [[ -n $(find /etc/v2ray-agent/tls/ -name "*.key") ]] && [[ -n $(find /etc/v2ray-agent/tls/ -name "*.crt") ]]; then
		mv /etc/v2ray-agent/tls /tmp/v2ray-agent-tls
		if [[ -n $(find /tmp/v2ray-agent-tls -name '*.key') ]]; then
			echoContent yellow " ---> The backup certificate is successful, please keep it. [/tmp/v2ray-agent-tls]"
		fi
	fi

	rm -rf /etc/v2ray-agent
	rm -rf ${nginxConfigPath}alone.conf
	rm -rf /usr/bin/vasma
	rm -rf /usr/sbin/vasma
	echoContent green " ---> Uninstall shortcut complete"
	echoContent green " ---> Uninstall v2ray-agent script complete"
}

# Modify V2Ray CDN node
updateV2RayCDN() {

	# todo Refactor this method
	echoContent skyBlue "\n progress $1/${totalProgress} : Modify CDN node"

	if [[ -n "${currentAdd}" ]]; then
		echoContent red "—————————————————————————————————————————————————————————————"
		echoContent yellow "1.CNAME www.digitalocean.com"
		echoContent yellow "2.CNAME www.cloudflare.com"
		echoContent yellow "3.CNAME hostmonit.com"
		echoContent yellow "4.Manual entry"
		echoContent red "—————————————————————————————————————————————————————————————"
		read -r -p "please choose:" selectCDNType
		case ${selectCDNType} in
		1)
			setDomain="www.digitalocean.com"
			;;
		2)
			setDomain="www.cloudflare.com"
			;;
		3)
			setDomain="hostmonit.com"
			;;
		4)
			read -r -p "Please enter the IP or domain name you want to customize the CDN:" setDomain
			;;
		esac

		if [[ -n ${setDomain} ]]; then
			if [[ -n "${currentAdd}" ]]; then
				sed -i "s/\"${currentAdd}\"/\"${setDomain}\"/g" "$(grep "${currentAdd}" -rl ${configPath}${frontingType}.json)"
			fi
			if [[ $(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json) == "${setDomain}" ]]; then
				echoContent green " ---> CDN modified successfully"
				reloadCore
			else
				echoContent red " ---> Failed to modify CDN"
			fi
		fi
	else
		echoContent red " ---> Available types not installed"
	fi
}

# manageUser 
manageUser() {
	echoContent skyBlue "\n progress $1/${totalProgress} : Multi-user management"
	echoContent skyBlue "—————————————————————————————————————————————————————————————"
	echoContent yellow "1.Add user"
	echoContent yellow "2.delete users"
	echoContent skyBlue "—————————————————————————————————————————————————————————————"
	read -r -p "please choose:" manageUserType
	if [[ "${manageUserType}" == "1" ]]; then
		addUser
	elif [[ "${manageUserType}" == "2" ]]; then
		removeUser
	else
		echoContent red " ---> wrong selection"
	fi
}

# custom uuid
customUUID() {
	read -r -p "Whether to customize UUID ？[y/n]:" customUUIDStatus
	echo
	if [[ "${customUUIDStatus}" == "y" ]]; then
		read -r -p "Please enter a valid UUID:" currentCustomUUID
		echo
		if [[ -z "${currentCustomUUID}" ]]; then
			echoContent red " ---> UUID cannot be null"
		else
			jq -r -c '.inbounds[0].settings.clients[].id' ${configPath}${frontingType}.json | while read -r line; do
				if [[ "${line}" == "${currentCustomUUID}" ]]; then
					echo >/tmp/v2ray-agent
				fi
			done
			if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
				echoContent red " ---> UUID is not repeatable"
				rm /tmp/v2ray-agent
				exit 0
			fi
		fi
	fi
}

# custom email
customUserEmail() {
	read -r -p "Whether to customize email ？[y/n]:" customEmailStatus
	echo
	if [[ "${customEmailStatus}" == "y" ]]; then
		read -r -p "Please enter a valid email:" currentCustomEmail
		echo
		if [[ -z "${currentCustomEmail}" ]]; then
			echoContent red " ---> email cannot be empty"
		else
			jq -r -c '.inbounds[0].settings.clients[].email' ${configPath}${frontingType}.json | while read -r line; do
				if [[ "${line}" == "${currentCustomEmail}" ]]; then
					echo >/tmp/v2ray-agent
				fi
			done
			if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
				echoContent red " ---> email is not repeatable"
				rm /tmp/v2ray-agent
				exit 0
			fi
		fi
	fi
}

# Add user
addUser() {

	echoContent yellow "After adding a new user, you will need to recheck the subscription"
	read -r -p "Please enter the number of users to add：" userNum
	echo
	if [[ -z ${userNum} || ${userNum} -le 0 ]]; then
		echoContent red " ---> wrong input，please enter again"
		exit 0
	fi

	# Generate user
	if [[ "${userNum}" == "1" ]]; then
		customUUID
		customUserEmail
	fi

	while [[ ${userNum} -gt 0 ]]; do
		local users=
		((userNum--)) || true
		if [[ -n "${currentCustomUUID}" ]]; then
			uuid=${currentCustomUUID}
		else
			uuid=$(${ctlPath} uuid)
		fi

		if [[ -n "${currentCustomEmail}" ]]; then
			email=${currentCustomEmail}
		else
			email=${currentHost}_${uuid}
		fi

		#	compatible v2ray-core
		users="{\"id\":\"${uuid}\",\"flow\":\"xtls-rprx-direct\",\"email\":\"${email}\",\"alterId\":0}"

		if [[ "${coreInstallType}" == "2" ]]; then
			users="{\"id\":\"${uuid}\",\"email\":\"${email}\",\"alterId\":0}"
		fi

		if echo ${currentInstallProtocolType} | grep -q 0; then
			local vlessUsers="${users//\,\"alterId\":0/}"

			local vlessTcpResult
			vlessTcpResult=$(jq -r ".inbounds[0].settings.clients += [${vlessUsers}]" ${configPath}${frontingType}.json)
			echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
		fi

		if echo ${currentInstallProtocolType} | grep -q trojan; then
			local trojanXTLSUsers="${users//\,\"alterId\":0/}"
			trojanXTLSUsers=${trojanXTLSUsers//"id"/"password"}

			local trojanXTLSResult
			trojanXTLSResult=$(jq -r ".inbounds[0].settings.clients += [${trojanXTLSUsers}]" ${configPath}${frontingType}.json)
			echo "${trojanXTLSResult}" | jq . >${configPath}${frontingType}.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 1; then
			local vlessUsers="${users//\,\"alterId\":0/}"
			vlessUsers="${vlessUsers//\"flow\":\"xtls-rprx-direct\"\,/}"
			local vlessWsResult
			vlessWsResult=$(jq -r ".inbounds[0].settings.clients += [${vlessUsers}]" ${configPath}03_VLESS_WS_inbounds.json)
			echo "${vlessWsResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then
			local trojangRPCUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			trojangRPCUsers="${trojangRPCUsers//\,\"alterId\":0/}"
			trojangRPCUsers=${trojangRPCUsers//"id"/"password"}

			local trojangRPCResult
			trojangRPCResult=$(jq -r ".inbounds[0].settings.clients += [${trojangRPCUsers}]" ${configPath}04_trojan_gRPC_inbounds.json)
			echo "${trojangRPCResult}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then
			local vmessUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"

			local vmessWsResult
			vmessWsResult=$(jq -r ".inbounds[0].settings.clients += [${vmessUsers}]" ${configPath}05_VMess_WS_inbounds.json)
			echo "${vmessWsResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			local vlessGRPCUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			vlessGRPCUsers="${vlessGRPCUsers//\,\"alterId\":0/}"

			local vlessGRPCResult
			vlessGRPCResult=$(jq -r ".inbounds[0].settings.clients += [${vlessGRPCUsers}]" ${configPath}06_VLESS_gRPC_inbounds.json)
			echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 6; then
			local vmessGRPCUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			vmessGRPCUsers="${vmessGRPCUsers//\,\"alterId\":0/}"

			local vmessGRPCResult
			vmessGRPCResult=$(jq -r ".inbounds[0].settings.clients += [${vmessGRPCUsers}]" ${configPath}07_VMess_gRPC_inbounds.json)
			echo "${vmessGRPCResult}" | jq . >${configPath}07_VMess_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then
			local trojanUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			trojanUsers="${trojanUsers//id/password}"
			trojanUsers="${trojanUsers//\,\"alterId\":0/}"

			local trojanTCPResult
			trojanTCPResult=$(jq -r ".inbounds[0].settings.clients += [${trojanUsers}]" ${configPath}04_trojan_TCP_inbounds.json)
			echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
		fi
	done

	reloadCore
	echoContent green " ---> add complete"
	manageAccount 1
}

# remove user
removeUser() {

	if echo ${currentInstallProtocolType} | grep -q 0 || echo ${currentInstallProtocolType} | grep -q trojan; then
		jq -r -c .inbounds[0].settings.clients[].email ${configPath}${frontingType}.json | awk '{print NR""":"$0}'
		read -r -p "Please select the user ID to delete[Only single delete is supported]:" delUserIndex
		if [[ $(jq -r '.inbounds[0].settings.clients|length' ${configPath}${frontingType}.json) -lt ${delUserIndex} ]]; then
			echoContent red " ---> wrong selection"
		else
			delUserIndex=$((delUserIndex - 1))
			local vlessTcpResult
			vlessTcpResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}${frontingType}.json)
			echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
		fi
	fi
	if [[ -n "${delUserIndex}" ]]; then
		if echo ${currentInstallProtocolType} | grep -q 1; then
			local vlessWSResult
			vlessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}03_VLESS_WS_inbounds.json)
			echo "${vlessWSResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then
			local trojangRPCUsers
			trojangRPCUsers=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_gRPC_inbounds.json)
			echo "${trojangRPCUsers}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then
			local vmessWSResult
			vmessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}05_VMess_WS_inbounds.json)
			echo "${vmessWSResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			local vlessGRPCResult
			vlessGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}06_VLESS_gRPC_inbounds.json)
			echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 6; then
			local vmessGRPCResult
			vmessGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}07_VMess_gRPC_inbounds.json)
			echo "${vmessGRPCResult}" | jq . >${configPath}07_VMess_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then
			local trojanTCPResult
			trojanTCPResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_TCP_inbounds.json)
			echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
		fi

		reloadCore
	fi
	manageAccount 1
}
# update script
updateV2RayAgent() {
	echoContent skyBlue "\n progress  $1/${totalProgress} : Update v2ray-agent script"
	rm -rf /etc/v2ray-agent/install.sh
	if wget --help | grep -q show-progress; then
		wget -c -q --show-progress -P /etc/v2ray-agent/ -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"
	else
		wget -c -q -P /etc/v2ray-agent/ -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"
	fi

	sudo chmod 700 /etc/v2ray-agent/install.sh
	local version
	version=$(grep 'current version：v' "/etc/v2ray-agent/install.sh" | awk -F "[v]" '{print $2}' | tail -n +2 | head -n 1 | awk -F "[\"]" '{print $1}')

	echoContent green "\n ---> update completed"
	echoContent yellow " ---> Please manually execute [vasma] to open the script"
	echoContent green " ---> current version:${version}\n"
	echoContent yellow "If the update is unsuccessful, please manually execute the following command\n"
	echoContent skyBlue "wget -P /root -N --no-check-certificate https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh && chmod 700 /root/install.sh && /root/install.sh"
	echo
	exit 0
}

# firewall
handleFirewall() {
	if systemctl status ufw 2>/dev/null | grep -q "active (exited)" && [[ "$1" == "stop" ]]; then
		systemctl stop ufw >/dev/null 2>&1
		systemctl disable ufw >/dev/null 2>&1
		echoContent green " ---> ufw closed successfully"

	fi

	if systemctl status firewalld 2>/dev/null | grep -q "active (running)" && [[ "$1" == "stop" ]]; then
		systemctl stop firewalld >/dev/null 2>&1
		systemctl disable firewalld >/dev/null 2>&1
		echoContent green " ---> firewalld shut down successfully"
	fi
}

# Install BBR
bbrInstall() {
	echoContent red "\n—————————————————————————————————————————————————————————————"
	echoContent green "BBR、DD script for[ylx2016]mature works，address[https://github.com/ylx2016/Linux-NetSpeed]，please know"
	echoContent yellow "1.install script【推荐原版BBR+FQ】"
	echoContent yellow "2.fallback home directory"
	echoContent red "—————————————————————————————————————————————————————————————"
	read -r -p "please choose:" installBBRStatus
	if [[ "${installBBRStatus}" == "1" ]]; then
		wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
	else
		menu
	fi
}

# View, check logs
checkLog() {
	if [[ -z ${configPath} ]]; then
		echoContent red " ---> No installation directory detected, please execute script to install content"
	fi
	local logStatus=false
	if grep -q "access" ${configPath}00_log.json; then
		logStatus=true
	fi

	echoContent skyBlue "\n progress $1/${totalProgress} : View logs"
	echoContent red "\n—————————————————————————————————————————————————————————————"
	echoContent yellow "# It is recommended to turn on access log only when debugging\n"

	if [[ "${logStatus}" == "false" ]]; then
		echoContent yellow "1.Open access log"
	else
		echoContent yellow "1.close access log"
	fi

	echoContent yellow "2.Monitor access logs"
	echoContent yellow "3.Monitor error log"
	echoContent yellow "4.View the certificate timing task log"
	echoContent yellow "5.View the certificate installation log"
	echoContent yellow "6.clear log"
	echoContent red "—————————————————————————————————————————————————————————————"

	read -r -p "please choose:" selectAccessLogType
	local configPathLog=${configPath//conf\//}

	case ${selectAccessLogType} in
	1)
		if [[ "${logStatus}" == "false" ]]; then
			cat <<EOF >${configPath}00_log.json
{
  "log": {
  	"access":"${configPathLog}access.log",
    "error": "${configPathLog}error.log",
    "loglevel": "debug"
  }
}
EOF
		elif [[ "${logStatus}" == "true" ]]; then
			cat <<EOF >${configPath}00_log.json
{
  "log": {
    "error": "${configPathLog}error.log",
    "loglevel": "warning"
  }
}
EOF
		fi
		reloadCore
		checkLog 1
		;;
	2)
		tail -f ${configPathLog}access.log
		;;
	3)
		tail -f ${configPathLog}error.log
		;;
	4)
		tail -n 100 /etc/v2ray-agent/crontab_tls.log
		;;
	5)
		tail -n 100 /etc/v2ray-agent/tls/acme.log
		;;
	6)
		echo >${configPathLog}access.log
		echo >${configPathLog}error.log
		;;
	esac
}

# Script shortcut
aliasInstall() {

	if [[ -f "$HOME/install.sh" ]] && [[ -d "/etc/v2ray-agent" ]] && grep <"$HOME/install.sh" -q "作者：mack-a"; then
		mv "$HOME/install.sh" /etc/v2ray-agent/install.sh
		local vasmaType=
		if [[ -d "/usr/bin/" ]]; then
			if [[ ! -f "/usr/bin/vasma" ]]; then
				ln -s /etc/v2ray-agent/install.sh /usr/bin/vasma
				chmod 700 /usr/bin/vasma
				vasmaType=true
			fi

			rm -rf "$HOME/install.sh"
		elif [[ -d "/usr/sbin" ]]; then
			if [[ ! -f "/usr/sbin/vasma" ]]; then
				ln -s /etc/v2ray-agent/install.sh /usr/sbin/vasma
				chmod 700 /usr/sbin/vasma
				vasmaType=true
			fi
			rm -rf "$HOME/install.sh"
		fi
		if [[ "${vasmaType}" == "true" ]]; then
			echoContent green "The shortcut was created successfully, you can execute [vasma] to reopen the script"
		fi
	fi
}

# check ipv6、ipv4
checkIPv6() {
	# pingIPv6=$(ping6 -c 1 www.google.com | sed '2{s/[^(]*(//;s/).*//;q;}' | tail -n +2)
	pingIPv6=$(ping6 -c 1 www.google.com | sed -n '1p' | sed 's/.*(//g;s/).*//g')

	if [[ -z "${pingIPv6}" ]]; then
		echoContent red " ---> does not support ipv6"
		exit 0
	fi
}

# ipv6 Diversion
ipv6Routing() {
	if [[ -z "${configPath}" ]]; then
		echoContent red " ---> Not installed, please use script to install"
		menu
		exit 0
	fi

	checkIPv6
	echoContent skyBlue "\n progress 1/${totalProgress} : IPv6 offload"
	echoContent red "\n—————————————————————————————————————————————————————————————"
	echoContent yellow "1.Add domain name"
	echoContent yellow "2.Offload IPv6 offload"
	echoContent red "=============================================================="
	read -r -p "please choose:" ipv6Status
	if [[ "${ipv6Status}" == "1" ]]; then
		echoContent red "—————————————————————————————————————————————————————————————"
		echoContent yellow "# Precautions\n"
		echoContent yellow "1.Rules only support a list of predefined domains[https://github.com/v2fly/domain-list-community]"
		echoContent yellow "2.Detailed documentation[https://www.v2fly.org/config/routing.html]"
		echoContent yellow "3.If the kernel fails to start, please check the domain name and add the domain name again"
		echoContent yellow "4.Special characters are not allowed, pay attention to the format of comma"
		echoContent yellow "5.Every time you add it, it will be added again, and the last domain name will not be retained"
		echoContent yellow "6.Entry example:google,youtube,facebook\n"
		read -r -p "Please enter the domain name according to the example above:" domainList

		if [[ -f "${configPath}09_routing.json" ]]; then

			unInstallRouting IPv6-out

			routing=$(jq -r ".routing.rules += [{\"type\":\"field\",\"domain\":[\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"IPv6-out\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >${configPath}09_routing.json

		else
			cat <<EOF >"${configPath}09_routing.json"
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "domain": [
            	"geosite:${domainList//,/\",\"geosite:}"
            ],
            "outboundTag": "IPv6-out"
          }
        ]
  }
}
EOF
		fi

		unInstallOutbounds IPv6-out

		outbounds=$(jq -r '.outbounds += [{"protocol":"freedom","settings":{"domainStrategy":"UseIPv6"},"tag":"IPv6-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

		echoContent green " ---> Added successfully"

	elif [[ "${ipv6Status}" == "2" ]]; then

		unInstallRouting IPv6-out

		unInstallOutbounds IPv6-out

		echoContent green " ---> IPv6 offloading succeeded"
	else
		echoContent red " ---> wrong selection"
		exit 0
	fi

	reloadCore
}

# bt download management
btTools() {
	if [[ -z "${configPath}" ]]; then
		echoContent red " ---> Not installed, please use script to install"
		menu
		exit 0
	fi

	echoContent skyBlue "\n progress 1/${totalProgress} : bt download management"
	echoContent red "\n—————————————————————————————————————————————————————————————"

	if [[ -f ${configPath}09_routing.json ]] && grep -q bittorrent <${configPath}09_routing.json; then
		echoContent yellow "Current Status: Disabled"
	else
		echoContent yellow "Current state: not disabled"
	fi

	echoContent yellow "1.disabled"
	echoContent yellow "2.Open"
	echoContent red "—————————————————————————————————————————————————————————————"
	read -r -p "please choose:" btStatus
	if [[ "${btStatus}" == "1" ]]; then

		if [[ -f "${configPath}09_routing.json" ]]; then

			unInstallRouting blackhole-out

			routing=$(jq -r '.routing.rules += [{"type":"field","outboundTag":"blackhole-out","protocol":["bittorrent"]}]' ${configPath}09_routing.json)

			echo "${routing}" | jq . >${configPath}09_routing.json

		else
			cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "outboundTag": "blackhole-out",
            "protocol": [ "bittorrent" ]
          }
        ]
  }
}
EOF
		fi

		installSniffing

		unInstallOutbounds blackhole-out

		outbounds=$(jq -r '.outbounds += [{"protocol":"blackhole","tag":"blackhole-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

		echoContent green " ---> BT download disabled successfully"

	elif [[ "${btStatus}" == "2" ]]; then

		unInstallSniffing

		unInstallRouting blackhole-out outboundTag bittorrent

		#		unInstallOutbounds blackhole-out

		echoContent green " ---> BT download opened successfully"
	else
		echoContent red " ---> wrong selection"
		exit 0
	fi

	reloadCore
}

# Domain blacklist
blacklist() {
	if [[ -z "${configPath}" ]]; then
		echoContent red " ---> Not installed, please use script to install"
		menu
		exit 0
	fi

	echoContent skyBlue "\n progress  $1/${totalProgress} : Domain blacklist"
	echoContent red "\n—————————————————————————————————————————————————————————————"
	echoContent yellow "1.Add domain name"
	echoContent yellow "2.remove blacklist"
	echoContent red "—————————————————————————————————————————————————————————————"
	read -r -p "please choose:" blacklistStatus
	if [[ "${blacklistStatus}" == "1" ]]; then
		echoContent red "—————————————————————————————————————————————————————————————"
		echoContent yellow "# Precautions\n"
		echoContent yellow "1.Rules only support a list of predefined domains[https://github.com/v2fly/domain-list-community]"
		echoContent yellow "2.Detailed documentation[https://www.v2fly.org/config/routing.html]"
		echoContent yellow "3.If the kernel fails to start, please check the domain name and add the domain name again"
		echoContent yellow "4.Special characters are not allowed, pay attention to the format of comma"
		echoContent yellow "5.Every time you add it, it will be added again, and the last domain name will not be retained"
		echoContent yellow "6.Entry example:speedtest,facebook\n"
		read -r -p "Please enter the domain name according to the example above:" domainList

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting blackhole-out outboundTag

			routing=$(jq -r ".routing.rules += [{\"type\":\"field\",\"domain\":[\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"blackhole-out\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >${configPath}09_routing.json

		else
			cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "domain": [
            	"geosite:${domainList//,/\",\"geosite:}"
            ],
            "outboundTag": "blackhole-out"
          }
        ]
  }
}
EOF
		fi

		echoContent green " ---> Added successfully"

	elif [[ "${blacklistStatus}" == "2" ]]; then

		unInstallRouting blackhole-out outboundTag

		echoContent green " ---> Domain blacklist deleted successfully"
	else
		echoContent red " ---> wrong selection"
		exit 0
	fi
	reloadCore
}

# Uninstall Routing according to tag
unInstallRouting() {
	local tag=$1
	local type=$2
	local protocol=$3

	if [[ -f "${configPath}09_routing.json" ]]; then
		local routing
		if grep -q "${tag}" ${configPath}09_routing.json && grep -q "${type}" ${configPath}09_routing.json; then

			jq -c .routing.rules[] ${configPath}09_routing.json | while read -r line; do
				local index=$((index + 1))
				local delStatus=0
				if [[ "${type}" == "outboundTag" ]] && echo "${line}" | jq .outboundTag | grep -q "${tag}"; then
					delStatus=1
				elif [[ "${type}" == "inboundTag" ]] && echo "${line}" | jq .inboundTag | grep -q "${tag}"; then
					delStatus=1
				fi

				if [[ -n ${protocol} ]] && echo "${line}" | jq .protocol | grep -q "${protocol}"; then
					delStatus=1
				elif [[ -z ${protocol} ]] && [[ $(echo "${line}" | jq .protocol) != "null" ]]; then
					delStatus=0
				fi

				if [[ ${delStatus} == 1 ]]; then
					routing=$(jq -r 'del(.routing.rules['"$(("${index}" - 1))"'])' ${configPath}09_routing.json)
					echo "${routing}" | jq . >${configPath}09_routing.json
				fi
			done
		fi
	fi
}

# Uninstall outbound based on tag
unInstallOutbounds() {
	local tag=$1

	if grep -q "${tag}" ${configPath}10_ipv4_outbounds.json; then
		local ipv6OutIndex
		ipv6OutIndex=$(jq .outbounds[].tag ${configPath}10_ipv4_outbounds.json | awk '{print ""NR""":"$0}' | grep "${tag}" | awk -F "[:]" '{print $1}' | head -1)
		if [[ ${ipv6OutIndex} -gt 0 ]]; then
			routing=$(jq -r 'del(.outbounds['$(("${ipv6OutIndex}" - 1))'])' ${configPath}10_ipv4_outbounds.json)
			echo "${routing}" | jq . >${configPath}10_ipv4_outbounds.json
		fi
	fi

}

# uninstall sniffing
unInstallSniffing() {

	find ${configPath} -name "*inbounds.json*" | awk -F "[c][o][n][f][/]" '{print $2}' | while read -r inbound; do
		sniffing=$(jq -r 'del(.inbounds[0].sniffing)' "${configPath}${inbound}")
		echo "${sniffing}" | jq . >"${configPath}${inbound}"
	done
}

# install sniff
installSniffing() {

	find ${configPath} -name "*inbounds.json*" | awk -F "[c][o][n][f][/]" '{print $2}' | while read -r inbound; do
		sniffing=$(jq -r '.inbounds[0].sniffing = {"enabled":true,"destOverride":["http","tls"]}' "${configPath}${inbound}")
		echo "${sniffing}" | jq . >"${configPath}${inbound}"
	done
}

# warp router
warpRouting() {
	echoContent skyBlue "\n progress  $1/${totalProgress} : WARP offload"
	echoContent red "—————————————————————————————————————————————————————————————"
	#	echoContent yellow "# Precautions\n"
	#	echoContent yellow "1.The official warp has bugs after several rounds of testing. Restarting the warp will cause the warp to fail and fail to start, and the CPU usage may also skyrocket."
	#	echoContent yellow "2.It can be used normally without restarting the machine. If you have to use the official warp, it is recommended not to restart the machine"
	#	echoContent yellow "3.Some machines still work normally after restarting"
	#	echoContent yellow "4.Can not be used after restarting, you can also uninstall and reinstall"
	# install warp
	if [[ -z $(which warp-cli) ]]; then
		echo
		read -r -p "WARP is not installed, is it installed?[y/n]:" installCloudflareWarpStatus
		if [[ "${installCloudflareWarpStatus}" == "y" ]]; then
			installWarp
		else
			echoContent yellow " ---> Abandon the installation"
			exit 0
		fi
	fi

	echoContent red "\n—————————————————————————————————————————————————————————————"
	echoContent yellow "1.Add domain name"
	echoContent yellow "2.Uninstall WARP offload"
	echoContent red "—————————————————————————————————————————————————————————————"
	read -r -p "please choose:" warpStatus
	if [[ "${warpStatus}" == "1" ]]; then
		echoContent red "—————————————————————————————————————————————————————————————"
		echoContent yellow "# Precautions\n"
		echoContent yellow "1.Rules only support a list of predefined domains[https://github.com/v2fly/domain-list-community]"
		echoContent yellow "2.Detailed documentation[https://www.v2fly.org/config/routing.html]"
		echoContent yellow "3.Only traffic can be distributed to warp, not ipv4 or ipv6"
		echoContent yellow "4.If the kernel fails to start, please check the domain name and add the domain name again"
		echoContent yellow "5.Special characters are not allowed, pay attention to the format of comma"
		echoContent yellow "6.Every time you add it, it will be added again, and the last domain name will not be retained"
		echoContent yellow "7.Entry example:google,youtube,facebook\n"
		read -r -p "Please enter the domain name according to the example above:" domainList

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting warp-socks-out outboundTag

			routing=$(jq -r ".routing.rules += [{\"type\":\"field\",\"domain\":[\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"warp-socks-out\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >${configPath}09_routing.json

		else
			cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "domain": [
            	"geosite:${domainList//,/\",\"geosite:}"
            ],
            "outboundTag": "warp-socks-out"
          }
        ]
  }
}
EOF
		fi
		unInstallOutbounds warp-socks-out

		local outbounds
		outbounds=$(jq -r '.outbounds += [{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":31303}]},"tag":"warp-socks-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

		echoContent green " ---> Added successfully"

	elif [[ "${warpStatus}" == "2" ]]; then

		${removeType} cloudflare-warp >/dev/null 2>&1

		unInstallRouting warp-socks-out outboundTag

		unInstallOutbounds warp-socks-out

		echoContent green " ---> WARP offload successfully"
	else
		echoContent red " ---> wrong selection"
		exit 0
	fi
	reloadCore
}
# Streaming Toolbox
streamingToolbox() {
	echoContent skyBlue "\n schedule 1/${totalProgress} : Streaming Toolbox"
	echoContent red "\n—————————————————————————————————————————————————————————————"
	#	echoContent yellow "1.Netflix detection"
	echoContent yellow "1.Any door landing machine to unlock streaming media"
	echoContent yellow "2.DNS Unblock Streaming"
	read -r -p "please choose:" selectType

	case ${selectType} in
	1)
		dokodemoDoorUnblockStreamingMedia
		;;
	2)
		dnsUnlockNetflix
		;;
	esac

}

# Any Door Unlock Streaming
dokodemoDoorUnblockStreamingMedia() {
	echoContent skyBlue "\n progress 1/${totalProgress} : Any door landing machine to unlock streaming media"
	echoContent red "\n—————————————————————————————————————————————————————————————"
	echoContent yellow "# Precautions"
	echoContent yellow "For details on unlocking any door, please check this article[https://github.com/mack-a/v2ray-agent/blob/master/documents/netflix/dokodemo-unblock_netflix.md]\n"

	echoContent yellow "1.Add outbound"
	echoContent yellow "2.Add inbound"
	echoContent yellow "3.uninstall"
	read -r -p "please choose:" selectType

	case ${selectType} in
	1)
		setDokodemoDoorUnblockStreamingMediaOutbounds
		;;
	2)
		setDokodemoDoorUnblockStreamingMediaInbounds
		;;
	3)
		removeDokodemoDoorUnblockStreamingMedia
		;;
	esac
}

# Set any door to unlock Netflix [outbound]
setDokodemoDoorUnblockStreamingMediaOutbounds() {
	read -r -p "Please enter the IP to unlock the streaming vps:" setIP
	echoContent red "—————————————————————————————————————————————————————————————"
	echoContent yellow "# Precautions\n"
	echoContent yellow "1.Rules only support a list of predefined domains[https://github.com/v2fly/domain-list-community]"
	echoContent yellow "2.Detailed documentation[https://www.v2fly.org/config/routing.html]"
	echoContent yellow "3.If the kernel fails to start, please check the domain name and add the domain name again"
	echoContent yellow "4.Special characters are not allowed, pay attention to the format of commas"
	echoContent yellow "5.Every time you add it, it will be added again, and the last domain name will not be retained"
	echoContent yellow "6.Entry example:netflix,disney,hulu\n"
	read -r -p "Please enter the domain name according to the example above:" domainList

	if [[ -n "${setIP}" ]]; then

		unInstallOutbounds streamingMedia-80
		unInstallOutbounds streamingMedia-443

		outbounds=$(jq -r ".outbounds += [{\"tag\":\"streamingMedia-80\",\"protocol\":\"freedom\",\"settings\":{\"domainStrategy\":\"AsIs\",\"redirect\":\"${setIP}:22387\"}},{\"tag\":\"streamingMedia-443\",\"protocol\":\"freedom\",\"settings\":{\"domainStrategy\":\"AsIs\",\"redirect\":\"${setIP}:22388\"}}]" ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting streamingMedia-80 outboundTag
			unInstallRouting streamingMedia-443 outboundTag

			local routing

			routing=$(jq -r ".routing.rules += [{\"type\":\"field\",\"port\":80,\"domain\":[\"ip.sb\",\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"streamingMedia-80\"},{\"type\":\"field\",\"port\":443,\"domain\":[\"ip.sb\",\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"streamingMedia-443\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >${configPath}09_routing.json
		else
			cat <<EOF >${configPath}09_routing.json
{
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "port": 80,
        "domain": [
          "ip.sb",
          "geosite:${domainList//,/\",\"geosite:}"
        ],
        "outboundTag": "streamingMedia-80"
      },
      {
        "type": "field",
        "port": 443,
        "domain": [
          "ip.sb",
          "geosite:${domainList//,/\",\"geosite:}"
        ],
        "outboundTag": "streamingMedia-443"
      }
    ]
  }
}
EOF
		fi
		reloadCore
		echoContent green " ---> Add outbound unlock successfully"
		exit 0
	fi
	echoContent red " ---> ip cannot be empty"
}

# Set any door to unlock Netflix [inbound]
setDokodemoDoorUnblockStreamingMediaInbounds() {

	echoContent skyBlue "\n progress 1/${totalProgress} : Add inbound to any door"
	echoContent red "\n—————————————————————————————————————————————————————————————"
	echoContent yellow "# Precautions\n"
	echoContent yellow "1.Rules only support a list of predefined domains[https://github.com/v2fly/domain-list-community]"
	echoContent yellow "2.Detailed documentation[https://www.v2fly.org/config/routing.html]"
	echoContent yellow "3.If the kernel fails to start, please check the domain name and add the domain name again"
	echoContent yellow "4.Special characters are not allowed, pay attention to the format of comma"
	echoContent yellow "5.Every time you add it, it will be added again, and the last domain name will not be retained"
	echoContent yellow "6.ip entry example:1.1.1.1,1.1.1.2"
	echoContent yellow "7.The following domain name must be consistent with the outbound vps"
	echoContent yellow "8.Domain name entry example:netflix,disney,hulu\n"
	read -r -p "Please enter the IP that is allowed to access the unlocked vps:" setIPs
	if [[ -n "${setIPs}" ]]; then
		read -r -p "Please enter the domain name according to the example above:" domainList

		cat <<EOF >${configPath}01_netflix_inbounds.json
{
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 22387,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "0.0.0.0",
        "port": 80,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http"
        ]
      },
      "tag": "streamingMedia-80"
    },
    {
      "listen": "0.0.0.0",
      "port": 22388,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "0.0.0.0",
        "port": 443,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "tls"
        ]
      },
      "tag": "streamingMedia-443"
    }
  ]
}
EOF

		cat <<EOF >${configPath}10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting streamingMedia-80 inboundTag
			unInstallRouting streamingMedia-443 inboundTag

			local routing
			routing=$(jq -r ".routing.rules += [{\"source\":[\"${setIPs//,/\",\"}\"],\"type\":\"field\",\"inboundTag\":[\"streamingMedia-80\",\"streamingMedia-443\"],\"outboundTag\":\"direct\"},{\"domains\":[\"geosite:${domainList//,/\",\"geosite:}\"],\"type\":\"field\",\"inboundTag\":[\"streamingMedia-80\",\"streamingMedia-443\"],\"outboundTag\":\"blackhole-out\"}]" ${configPath}09_routing.json)
			echo "${routing}" | jq . >${configPath}09_routing.json
		else
			cat <<EOF >${configPath}09_routing.json
            {
              "routing": {
                "rules": [
                  {
                    "source": [
                    	"${setIPs//,/\",\"}"
                    ],
                    "type": "field",
                    "inboundTag": [
                      "streamingMedia-80",
                      "streamingMedia-443"
                    ],
                    "outboundTag": "direct"
                  },
                  {
                    "domains": [
                    	"geosite:${domainList//,/\",\"geosite:}"
                    ],
                    "type": "field",
                    "inboundTag": [
                      "streamingMedia-80",
                      "streamingMedia-443"
                    ],
                    "outboundTag": "blackhole-out"
                  }
                ]
              }
            }
EOF

		fi

		reloadCore
		echoContent green " ---> Add landing machine inbound unlock successfully"
		exit 0
	fi
	echoContent red " ---> ip cannot be empty"
}

# Remove any door to unlock Netflix
removeDokodemoDoorUnblockStreamingMedia() {

	unInstallOutbounds streamingMedia-80
	unInstallOutbounds streamingMedia-443

	unInstallRouting streamingMedia-80 inboundTag
	unInstallRouting streamingMedia-443 inboundTag

	unInstallRouting streamingMedia-80 outboundTag
	unInstallRouting streamingMedia-443 outboundTag

	rm -rf ${configPath}01_netflix_inbounds.json

	reloadCore
	echoContent green " ---> Uninstalled successfully"
}

# restart core
reloadCore() {
	if [[ "${coreInstallType}" == "1" ]]; then
		handleXray stop
		handleXray start
	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
		handleV2Ray stop
		handleV2Ray start
	fi
}

# dns unblock Netflix
dnsUnlockNetflix() {
	if [[ -z "${configPath}" ]]; then
		echoContent red " ---> Not installed, please use script to install"
		menu
		exit 0
	fi
	echoContent skyBlue "\n progress 1/${totalProgress} : dns unblock Netflix"
	echoContent red "\n—————————————————————————————————————————————————————————————"
	echoContent yellow "1.Install"
	echoContent yellow "2.Uninstall"
	read -r -p "please choose:" selectType

	case ${selectType} in
	1)
		setUnlockDNS
		;;
	2)
		removeUnlockDNS
		;;
	esac
}

# set dns
setUnlockDNS() {
	read -r -p "Please enter Unblock Streaming DNS:" setDNS
	if [[ -n ${setDNS} ]]; then
		echoContent red "—————————————————————————————————————————————————————————————"
		echoContent yellow "# Precautions\n"
		echoContent yellow "1.Rules only support a list of predefined domains[https://github.com/v2fly/domain-list-community]"
		echoContent yellow "2.Detailed documentation[https://www.v2fly.org/config/routing.html]"
		echoContent yellow "3.If the kernel fails to start, please check the domain name and add the domain name again"
		echoContent yellow "4.Special characters are not allowed, pay attention to the format of comma"
		echoContent yellow "5.Every time you add it, it will be added again, and the last domain name will not be retained"
		echoContent yellow "6.Entry example:netflix,disney,hulu"
		echoContent yellow "7.Please enter 1 for the default scheme, the default scheme includes the following"
		echoContent yellow "netflix,bahamut,hulu,hbo,disney,bbc,4chan,fox,abema,dmm,niconico,pixiv,bilibili,viu"
		read -r -p "Please enter the domain name according to the example above:" domainList
		if [[ "${domainList}" == "1" ]]; then
			cat <<EOF >${configPath}11_dns.json
            {
            	"dns": {
            		"servers": [
            			{
            				"address": "${setDNS}",
            				"port": 53,
            				"domains": [
            					"geosite:netflix",
            					"geosite:bahamut",
            					"geosite:hulu",
            					"geosite:hbo",
            					"geosite:disney",
            					"geosite:bbc",
            					"geosite:4chan",
            					"geosite:fox",
            					"geosite:abema",
            					"geosite:dmm",
            					"geosite:niconico",
            					"geosite:pixiv",
            					"geosite:bilibili",
            					"geosite:viu"
            				]
            			},
            		"localhost"
            		]
            	}
            }
EOF
		elif [[ -n "${domainList}" ]]; then
			cat <<EOF >${configPath}11_dns.json
                        {
                        	"dns": {
                        		"servers": [
                        			{
                        				"address": "${setDNS}",
                        				"port": 53,
                        				"domains": [
                        					"geosite:${domainList//,/\",\"geosite:}"
                        				]
                        			},
                        		"localhost"
                        		]
                        	}
                        }
EOF
		fi

		reloadCore

		echoContent yellow "\n ---> If you still can't watch it, you can try the following two solutions"
		echoContent yellow " 1.restart vps"
		echoContent yellow " 2.After uninstalling dns unlock，modify local[/etc/resolv.conf]DNS settings and restart vps\n"
	else
		echoContent red " ---> dns cannot be null"
	fi
	exit 0
}

# remove Netflix unblock
removeUnlockDNS() {
	cat <<EOF >${configPath}11_dns.json
{
	"dns": {
		"servers": [
			"localhost"
		]
	}
}
EOF
	reloadCore

	echoContent green " ---> Uninstalled successfully"

	exit 0
}

# v2ray-core personalized installation
customV2RayInstall() {
	echoContent skyBlue "\n————————————————————————Personalized installation———————————————"
	echoContent yellow "VLESS is pre-installed, and 0 is installed by default. If only 0 needs to be installed, only 0 can be selected."
	echoContent yellow "0.VLESS+TLS/XTLS+TCP"
	echoContent yellow "1.VLESS+TLS+WS[CDN]"
	echoContent yellow "2.Trojan+TLS+gRPC[CDN]"
	echoContent yellow "3.VMess+TLS+WS[CDN]"
	echoContent yellow "4.Trojan"
	echoContent yellow "5.VLESS+TLS+gRPC[CDN]"
	read -r -p "Please select [Multiple Choice], [Example: 123]:" selectCustomInstallType
	echoContent skyBlue "—————————————————————————————————————————————————————————————"
	if [[ -z ${selectCustomInstallType} ]]; then
		selectCustomInstallType=0
	fi
	if [[ "${selectCustomInstallType}" =~ ^[0-5]+$ ]]; then
		cleanUp xrayClean
		totalProgress=17
		installTools 1
		# apply for tls
		initTLSNginxConfig 2
		installTLS 3
		handleNginx stop
		# random path
		if echo ${selectCustomInstallType} | grep -q 1 || echo ${selectCustomInstallType} | grep -q 3 || echo ${selectCustomInstallType} | grep -q 4; then
			randomPathFunction 5
			customCDNIP 6
		fi
		nginxBlog 7
		updateRedirectNginxConf
		handleNginx start

		# Install V2Ray
		installV2Ray 8
		installV2RayService 9
		initV2RayConfig custom 10
		cleanUp xrayDel
		installCronTLS 14
		handleV2Ray stop
		handleV2Ray start
		# Generate an account
		checkGFWStatue 15
		showAccounts 16
	else
		echoContent red " ---> invalid input"
		customV2RayInstall
	fi
}

# Xray-core Personalized Installation
customXrayInstall() {
	echoContent skyBlue "\n————————————————————————Personalized installation———————————————"
	echoContent yellow "VLESS is pre-installed, and 0 is installed by default. If only 0 needs to be installed, only 0 can be selected."
	echoContent yellow "0.VLESS+TLS/XTLS+TCP"
	echoContent yellow "1.VLESS+TLS+WS[CDN]"
	echoContent yellow "2.Trojan+TLS+gRPC[CDN]"
	echoContent yellow "3.VMess+TLS+WS[CDN]"
	echoContent yellow "4.Trojan"
	echoContent yellow "5.VLESS+TLS+gRPC[CDN]"
	read -r -p "Please select [Multiple Choice], [Example:123]:" selectCustomInstallType
	echoContent skyBlue "—————————————————————————————————————————————————————————————"
	if [[ -z ${selectCustomInstallType} ]]; then
		echoContent red " ---> not nullable"
		customXrayInstall
	elif [[ "${selectCustomInstallType}" =~ ^[0-5]+$ ]]; then
		cleanUp v2rayClean
		totalProgress=17
		installTools 1
		# apply for tls
		initTLSNginxConfig 2
		installTLS 3
		handleNginx stop
		# random path
		if echo "${selectCustomInstallType}" | grep -q 1 || echo "${selectCustomInstallType}" | grep -q 2 || echo "${selectCustomInstallType}" | grep -q 3 || echo "${selectCustomInstallType}" | grep -q 5; then
			randomPathFunction 5
			customCDNIP 6
		fi
		nginxBlog 7
		updateRedirectNginxConf
		handleNginx start

		# Install V2Ray
		installXray 8
		installXrayService 9
		initXrayConfig custom 10
		cleanUp v2rayDel

		installCronTLS 14
		handleXray stop
		handleXray start
		# Generate an account
		checkGFWStatue 15
		showAccounts 16
	else
		echoContent red " ---> invalid input"
		customXrayInstall
	fi
}

# select core install---v2ray-core、xray-core
selectCoreInstall() {
	echoContent skyBlue "\n progress 1/${totalProgress} : select core install"
	echoContent red "\n—————————————————————————————————————————————————————————————"
	echoContent yellow "1.Xray-core"
	echoContent yellow "2.v2ray-core"
	echoContent red "—————————————————————————————————————————————————————————————"
	read -r -p "please choose:" selectCoreType
	case ${selectCoreType} in
	1)
		if [[ "${selectInstallType}" == "2" ]]; then
			customXrayInstall
		else
			xrayCoreInstall
		fi
		;;
	2)
		v2rayCoreVersion=
		if [[ "${selectInstallType}" == "2" ]]; then
			customV2RayInstall
		else
			v2rayCoreInstall
		fi
		;;
	3)
		v2rayCoreVersion=v4.32.1
		if [[ "${selectInstallType}" == "2" ]]; then
			customV2RayInstall
		else
			v2rayCoreInstall
		fi
		;;
	*)
		echoContent red ' ---> Choose wrong, choose again'
		selectCoreInstall
		;;
	esac
}

# v2ray-core Install 
v2rayCoreInstall() {
	cleanUp xrayClean
	selectCustomInstallType=
	totalProgress=13
	installTools 2
	# apply for tls
	initTLSNginxConfig 3
	installTLS 4
	handleNginx stop
	#	initNginxConfig 5
	randomPathFunction 5
	# install V2Ray
	installV2Ray 6
	installV2RayService 7
	customCDNIP 8
	initV2RayConfig all 9
	cleanUp xrayDel
	installCronTLS 10
	nginxBlog 11
	updateRedirectNginxConf
	handleV2Ray stop
	sleep 2
	handleV2Ray start
	handleNginx start
	# Generate an account
	checkGFWStatue 12
	showAccounts 13
}

# xray-core install
xrayCoreInstall() {
	cleanUp v2rayClean
	selectCustomInstallType=
	totalProgress=13
	installTools 2
	# apply for tls
	initTLSNginxConfig 3
	installTLS 4
	handleNginx stop
	randomPathFunction 5
	# Install Xray
	# handleV2Ray stop
	installXray 6
	installXrayService 7
	customCDNIP 8
	initXrayConfig all 9
	cleanUp v2rayDel
	installCronTLS 10
	nginxBlog 11
	updateRedirectNginxConf
	handleXray stop
	sleep 2
	handleXray start

	handleNginx start
	# Generate an account
	checkGFWStatue 12
	showAccounts 13
}

# core management
coreVersionManageMenu() {

	if [[ -z "${coreInstallType}" ]]; then
		echoContent red "\n ---> No installation directory detected, please execute script to install content"
		menu
		exit 0
	fi
	if [[ "${coreInstallType}" == "1" ]]; then
		xrayVersionManageMenu 1
	elif [[ "${coreInstallType}" == "2" ]]; then
		v2rayCoreVersion=
		v2rayVersionManageMenu 1

	elif [[ "${coreInstallType}" == "3" ]]; then
		v2rayCoreVersion=v4.32.1
		v2rayVersionManageMenu 1
	fi
}
# Timing task inspection certificate
cronRenewTLS() {
	if [[ "${renewTLS}" == "RenewTLS" ]]; then
		renewalTLS
		exit 0
	fi
}
# Account management
manageAccount() {
	echoContent skyBlue "\n progress 1/${totalProgress} : Account management"
	echoContent red "\n——————————————————————————————————————————————————————————————"
	echoContent yellow "# Every time you delete or add an account, you need to re-check the subscription to generate a subscription\n"
	echoContent yellow "1.View account"
	echoContent yellow "2.View Subscriptions"
	echoContent yellow "3.Add user"
	echoContent yellow "4.Delete users"
	echoContent red "——————————————————————————————————————————————————————————————"
	read -r -p "please enter:" manageAccountStatus
	if [[ "${manageAccountStatus}" == "1" ]]; then
		showAccounts 1
	elif [[ "${manageAccountStatus}" == "2" ]]; then
		subscribe 1
	elif [[ "${manageAccountStatus}" == "3" ]]; then
		addUser
	elif [[ "${manageAccountStatus}" == "4" ]]; then
		removeUser
	else
		echoContent red " ---> wrong selection"
	fi
}

# subscription
subscribe() {
	if [[ -n "${configPath}" ]]; then
		echoContent skyBlue "-------------------------Remark---------------------------------"
		echoContent yellow "# Subscriptions are regenerated when viewing subscriptions"
		echoContent yellow "# Every time you add or delete an account, you need to re-check the subscription"
		rm -rf /etc/v2ray-agent/subscribe/*
		rm -rf /etc/v2ray-agent/subscribe_tmp/*
		showAccounts >/dev/null
		mv /etc/v2ray-agent/subscribe_tmp/* /etc/v2ray-agent/subscribe/

		if [[ -n $(ls /etc/v2ray-agent/subscribe/) ]]; then
			find /etc/v2ray-agent/subscribe/* | while read -r email; do
				email=$(echo "${email}" | awk -F "[s][u][b][s][c][r][i][b][e][/]" '{print $2}')
				local base64Result
				base64Result=$(base64 -w 0 "/etc/v2ray-agent/subscribe/${email}")
				echo "${base64Result}" >"/etc/v2ray-agent/subscribe/${email}"
				echoContent skyBlue "——————————————————————————————————————————————————————————————"
				echoContent yellow "email：$(echo "${email}" | awk -F "[_]" '{print $1}')\n"
				echoContent yellow "url：https://${currentHost}/s/${email}\n"
				echoContent yellow "Online QR code：https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=https://${currentHost}/s/${email}\n"
				echo "https://${currentHost}/s/${email}" | qrencode -s 10 -m 1 -t UTF8
				echoContent skyBlue "——————————————————————————————————————————————————————————————"
			done
		fi
	else
		echoContent red " ---> Not Installed"
	fi
}

# toggle alpn
switchAlpn() {
	echoContent skyBlue "\n progress 1/${totalProgress} : switch alpn"
	if [[ -z ${currentAlpn} ]]; then
		echoContent red " ---> Unable to read alpn, please check if it is installed"
		exit 0
	fi

	echoContent red "\n——————————————————————————————————————————————————————————————"
	echoContent green "The current alpn first is：${currentAlpn}"
	echoContent yellow "  1.When http/1.1 is the first, trojan is available, and some gRPC clients are available [clients support manual selection of alpn available]"
	echoContent yellow "  2.When h2 is the first, gRPC is available, and some trojan clients are available [clients support manual selection of alpn available]"
	echoContent yellow "  3.If the client does not support manual replacement of alpn, it is recommended to use this function to change the sequence of alpn on the server to use the corresponding protocol"
	echoContent red "——————————————————————————————————————————————————————————————"

	if [[ "${currentAlpn}" == "http/1.1" ]]; then
		echoContent yellow "1.toggle alpn h2 first position"
	elif [[ "${currentAlpn}" == "h2" ]]; then
		echoContent yellow "1.toggle alpn http/1.1 first"
	else
		echoContent red 'incompatible'
	fi

	echoContent red "——————————————————————————————————————————————————————————————"

	read -r -p "please choose:" selectSwitchAlpnType
	if [[ "${selectSwitchAlpnType}" == "1" && "${currentAlpn}" == "http/1.1" ]]; then

		local frontingTypeJSON
		frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.xtlsSettings.alpn = [\"h2\",\"http/1.1\"]" ${configPath}${frontingType}.json)
		echo "${frontingTypeJSON}" | jq . >${configPath}${frontingType}.json

	elif [[ "${selectSwitchAlpnType}" == "1" && "${currentAlpn}" == "h2" ]]; then
		local frontingTypeJSON
		frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.xtlsSettings.alpn =[\"http/1.1\",\"h2\"]" ${configPath}${frontingType}.json)
		echo "${frontingTypeJSON}" | jq . >${configPath}${frontingType}.json
	else
		echoContent red " ---> wrong selection"
		exit 0
	fi
	reloadCore
}
# main menu
menu() {
	cd "$HOME" || exit
	echoContent red "\n——————————————————————————————————————————————————————————————"
	echoContent green "Rebluid：Ryadhisa"
	echoContent green "Original Script：Mack-a"
	echoContent green "Current Version：v2.5.50"
	echoContent green "Description: 8-in-1 Coexistence Script\c"
	showInstallStatus
	echoContent red "\n——————————————————————————————————————————————————————————————"
	if [[ -n "${coreInstallType}" ]]; then
		echoContent yellow "1.Re-install"
	else
		echoContent yellow "1.Install"
	fi

	echoContent yellow "2.Install In Any Combination"
	if echo ${currentInstallProtocolType} | grep -q trojan; then
		echoContent yellow "3.Switch VLESS[XTLS]"
	elif echo ${currentInstallProtocolType} | grep -q 0; then
		echoContent yellow "3.Switch Trojan[XTLS]"
	fi

	echoContent skyBlue "——————————————————————————————————————————————————————————————"
	echoContent yellow "4.Account management"
	echoContent yellow "5.Replace The Camouflage Station"
	echoContent yellow "6.Update Certificate"
	echoContent yellow "7.Replacing A CDN Node"
	echoContent yellow "8.IPv6 Offload"
	echoContent yellow "9.WARP Offload"
	echoContent yellow "10.Streaming Tool"
	echoContent yellow "11.Add New Port"
	echoContent yellow "12.BT Download Management"
	echoContent yellow "13.Switch Alpn"
	echoContent yellow "14.Domain Blacklist"
	echoContent skyBlue "——————————————————————————————————————————————————————————————"
	echoContent yellow "15.Core Management"
	echoContent yellow "16.Update Script"
	echoContent yellow "17.Install BBR, DD Scripts"
	echoContent skyBlue "——————————————————————————————————————————————————————————————"
	echoContent yellow "18.View Logs"
	echoContent yellow "19.Uninstall Script"
	echoContent red "——————————————————————————————————————————————————————————————"
	mkdirTools
	aliasInstall
	read -r -p "Please Choose:" selectInstallType
	case ${selectInstallType} in
	1)
		selectCoreInstall
		;;
	2)
		selectCoreInstall
		;;
	3)
		initXrayFrontingConfig 1
		;;
	4)
		manageAccount 1
		;;
	5)
		updateNginxBlog 1
		;;
	6)
		renewalTLS 1
		;;
	7)
		updateV2RayCDN 1
		;;
	8)
		ipv6Routing 1
		;;
	9)
		warpRouting 1
		;;
	10)
		streamingToolbox 1
		;;
	11)
		addCorePort 1
		;;
	12)
		btTools 1
		;;
	13)
		switchAlpn 1
		;;
	14)
		blacklist 1
		;;
	15)
		coreVersionManageMenu 1
		;;
	16)
		updateV2RayAgent 1
		;;
	17)
		bbrInstall
		;;
	18)
		checkLog 1
		;;
	19)
		unInstall 1
		;;
	esac
}
cronRenewTLS
menu
