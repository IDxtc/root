#!/bin/bash

function addtr() {
clear
domain=$(cat /etc/xray/domain)
read -rp "User: " -e user
egrep -w "^### $user" /etc/xray/trojan.json >/dev/null
if [ $? -eq 0 ]; then
echo -e "Username Sudah Ada"
exit 0
fi
uuid=$(cat /proc/sys/kernel/random/uuid)
read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
sed -i '/#tls$/a\### '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /etc/xray/trojan.json
systemctl restart xray@trojan
trojanlink="trojan://${uuid}@${domain}:443#$user"
clear
echo -e ""
echo -e "==========-XRAY/Trojan-=========="
echo -e "Remarks        : ${user}"
echo -e "Host/IP        : ${domain}"
echo -e "port           : 443"
echo -e "Key            : ${uuid}"
echo -e "link           : ${trojanlink}"
echo -e "================================="
echo -e "Expired On     : $exp"
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
}
function deltr() {
clear
NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/xray/trojan.json")
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
        grep -E "^### " "/etc/xray/trojan.json" | cut -d ' ' -f 2-3 | nl -s ') '
        until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
                if [[ ${CLIENT_NUMBER} == '1' ]]; then
                        read -rp "Select one client [1]: " CLIENT_NUMBER
                else
                        read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
                fi
        done
user=$(grep -E "^### " "/etc/xray/trojan.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
exp=$(grep -E "^### " "/etc/xray/trojan.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
sed -i "/^### $user $exp/,/^},{/d" /etc/xray/trojan.json
systemctl restart xray@trojan
clear
echo " Trojan Akun berhasil dihapus"
echo " =========================="
echo " Client Name : $user"
echo " Expired On  : $exp"
echo " =========================="
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
}

function cektr() {
clear
data=( `cat /etc/xray/trojan.json | grep '^###' | cut -d ' ' -f 2`);
echo "-------------------------------";
echo "-----=[ Trojan User Login ]=-----";
echo "-------------------------------";
for akun in "${data[@]}"
do
if [[ -z "$akun" ]]; then
akun="tidakada"
fi
data2=( `netstat -anp | grep ESTABLISHED | grep tcp6 | grep xray | awk '{print $5}' | cut -d: -f1 | sort | uniq`);
echo -n > /tmp/iptrojan.txt
for ip in "${data2[@]}"
do
jum=$(cat /var/log/xray/trojan.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
if [[ -z "$jum" ]]; then
echo > /dev/null
else
echo "$jum" >> /tmp/iptrojan.txt
fi
done
jum=$(cat /tmp/iptrojan.txt)
if [[ -z "$jum" ]]; then
echo > /dev/null
else
jum2=$(cat /tmp/iptrojan.txt | nl)
echo "user : $akun";
echo "$jum2";
echo "-------------------------------"
fi
done
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
}

function renewtr() {
clear
NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/xray/trojan.json")
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
        grep -E "^### " "/etc/xray/trojan.json" | cut -d ' ' -f 2-3 | nl -s ') '
        until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
                if [[ ${CLIENT_NUMBER} == '1' ]]; then
                        read -rp "Select one client [1]: " CLIENT_NUMBER
                else
                        read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
                fi
        done
read -p "Expired (days): " masaaktif
user=$(grep -E "^### " "/etc/xray/trojan.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
exp=$(grep -E "^### " "/etc/xray/trojan.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
now=$(date +%Y-%m-%d)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$now" +%s)
exp2=$(( (d1 - d2) / 86400 ))
exp3=$(($exp2 + $masaaktif))
exp4=`date -d "$exp3 days" +"%Y-%m-%d"`
sed -i "s/### $user $exp/### $user $exp4/g" /etc/xray/trojan.json
clear
echo ""
echo " Akun Trojan berhasil diperpanjang"
echo " =========================="
echo " Client Name : $user"
echo " Expired On  : $exp4"
echo " =========================="
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
}
clear
echo -e "\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\E[0;41;36m            TROJAN - MENU          \E[0m"
echo -e "\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
echo -e " [\e[36m1\e[0m] • Add User Trojan"
echo -e " [\e[36m2\e[0m] • Del User Trojan "
echo -e " [\e[36m3\e[0m] • Cek User Trojan "
echo -e " [\e[36m4\e[0m] • Renew User Trojan "
echo -e ""
echo -e " [\e[31m0\e[0m] \e[31m• BACK TO MENU\033[0m"
echo -e   ""
echo -e   "Press x or [ Ctrl+C ] To-Exit"
echo -e ""
echo -e "\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
read -p " Select menu : " opt
echo -e ""
case $opt in
1) clear ; addtr ;;
2) clear ; deltr ;;
3) clear ; cektr;;
4) clear ; renewtr ;;
0) clear ; menu ;;
x) exit ;;
*) echo -e "" ; echo "Press any key to back on menu" ; sleep 1 ; menu ;;
esac