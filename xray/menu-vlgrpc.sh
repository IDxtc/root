#!/bin/bash
function renewvlgrpc() {
clear
NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/xray/vlgrpc.json")
        if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
                clear
                echo ""
                echo "You have no existing clients!"
                exit 1
        fi

        clear
        echo ""
        echo "Select the existing client you want to renew"
        echo " Press CTRL+C to return"
        echo -e "==============================="
        grep -E "^### " "/etc/xray/vlgrpc.json" | cut -d ' ' -f 2-3 | nl -s ') '
        until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
                if [[ ${CLIENT_NUMBER} == '1' ]]; then
                        read -rp "Select one client [1]: " CLIENT_NUMBER
                else
                        read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
                fi
        done
read -p "Expired (days): " masaaktif
user=$(grep -E "^### " "/etc/xray/vlgrpc.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
exp=$(grep -E "^### " "/etc/xray/vlgrpc.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
now=$(date +%Y-%m-%d)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$now" +%s)
exp2=$(( (d1 - d2) / 86400 ))
exp3=$(($exp2 + $masaaktif))
exp4=`date -d "$exp3 days" +"%Y-%m-%d"`
sed -i "s/### $user $exp/### $user $exp4/g" /etc/xray/vlgrpc.json
service cron restart
clear
echo ""
echo " vlgrpc Account Was Successfully Renewed"
echo " =========================="
echo " Client Name : $user"
echo " Expired On  : $exp4"
echo " =========================="
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
}

function delvlgrpc() {
clear
NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/xray/vlgrpc.json")
        if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
                echo ""
                echo "You have no existing clients!"
                exit 1
        fi

       clear
        echo ""
        echo " Select the existing client you want to remove"
        echo " Press CTRL+C to return"
        echo " ==============================="
        echo "     No  Expired   User"
        grep -E "^### " "/etc/xray/vlgrpc.json" | cut -d ' ' -f 2-3 | nl -s ') '

        until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
                if [[ ${CLIENT_NUMBER} == '1' ]]; then
                        read -rp "Select one client [1]: " CLIENT_NUMBER
                else
                        read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
                fi
        done
user=$(grep -E "^### " "/etc/xray/vlgrpc.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
exp=$(grep -E "^### " "/etc/xray/vlgrpc.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
sed -i "/^### $user $exp/,/^},{/d" /etc/xray/vlgrpc.json
systemctl restart xray@vlgrpc

clear
echo " vlgrpc Account Deleted Successfully"
echo " =========================="
echo " Client Name : $user"
echo " Expired On  : $exp"
echo " =========================="
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
}

function cekvlgrpc() {
clear
echo -n > /tmp/other.txt
data=( `cat /etc/xray/vlgrpc.json | grep '^###' | cut -d ' ' -f 2`);
echo "-------------------------------";
echo "-----=[ vlgrpc User Login ]=-----";
echo "-------------------------------";
for akun in "${data[@]}"
do
if [[ -z "$akun" ]]; then
akun="tidakada"
fi
echo -n > /tmp/ipvlgrpc.txt
data2=( `netstat -anp | grep ESTABLISHED | grep tcp6 | grep xray | grep -w 443 | awk '{print $5}' | cut -d: -f1 | sort | uniq`);
for ip in "${data2[@]}"
do
jum=$(cat /var/log/xray/vlgrpc.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
if [[ "$jum" = "$ip" ]]; then
echo "$jum" >> /tmp/ipvlgrpc.txt
else
echo "$ip" >> /tmp/other.txt
fi
jum2=$(cat /tmp/ipvlgrpc.txt)
sed -i "/$jum2/d" /tmp/other.txt > /dev/null 2>&1
done
jum=$(cat /tmp/ipvlgrpc.txt)
if [[ -z "$jum" ]]; then
echo > /dev/null
else
jum2=$(cat /tmp/ipvlgrpc.txt | nl)
echo "user : $akun";
echo "$jum2";
echo "-------------------------------"
fi
rm -rf /tmp/ipvmess.txt
done
oth=$(cat /tmp/other.txt | sort | uniq | nl)
echo "other";
echo "$oth";
echo "-------------------------------"
rm -rf /tmp/other.txt
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
}

function addvlgrpc() {
clear
domain=$(cat /etc/xray/domain)
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
                read -rp "User: " -e user
                CLIENT_EXISTS=$(grep -w $user /etc/xray/vlgrpc.json | wc -l) 

                if [[ ${CLIENT_EXISTS} == '1' ]]; then
                        echo ""
                        echo "A client with the specified name was already created, please choose another name."
                        exit 1
                fi
        done
uuid=$(cat /proc/sys/kernel/random/uuid)
read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
sed -i '/#tls$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /etc/xray/vlgrpc.json
vlgrpclink1="vless://${uuid}@${domain}:443?mode=multi&security=tls&encryption=none&type=grpc&serviceName=vlgRPC&sni=bug.com#${user}"
systemctl restart xray@vlgrpc
clear
echo -e ""
echo -e "==========-Vless/gRPC-=========="
echo -e "Remarks        : ${user}"
echo -e "Domain         : ${domain}"
echo -e "port TLS       : 443"
echo -e "id             : ${uuid}"
echo -e "Encryption     : none"
echo -e "network        : ws"
echo -e "path           : /vlgRPC"
echo -e "================================="
echo -e "link TLS       : ${vlgrpclink1}"
echo -e "================================="
echo -e "Expired On     : $exp"
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
}

clear
echo -e "\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\E[0;41;36m           VLESS-gRPC - MENU       \E[0m"
echo -e "\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
echo -e " [\e[36m1\e[0m] • Add User Vless GRPC "
echo -e " [\e[36m2\e[0m] • Del User Vless GRPC "
echo -e " [\e[36m3\e[0m] • Cek User Vless GRPC "
echo -e " [\e[36m4\e[0m] • Renew User Vless GRPC "
echo -e ""
echo -e " [\e[31m0\e[0m] \e[31m • BACK TO MENU\033[0m"
echo -e   ""
echo -e   "Press x or [ Ctrl+C ] To-Exit"
echo -e ""
echo -e "\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
read -p " Select menu : " opt
echo -e ""
case $opt in
1) clear ; addvlgrpc ;;
2) clear ; delvlgrpc ;;
3) clear ; cekvlgrpc;;
4) clear ; renewvlgrpc ;;
0) clear ; menu ;;
x) exit ;;
*) echo -e "" ; echo "Press any key to back on menu" ; sleep 1 ; menu ;;
esac