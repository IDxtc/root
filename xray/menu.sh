#!/bin/bash
clear
echo -e "\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\E[0;41;36m            XRAY - MENU            \E[0m"
echo -e "\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
echo -e " [\e[36m1\e[0m] • Menu VMess"
echo -e " [\e[36m2\e[0m] • Menu Vless "
echo -e " [\e[36m3\e[0m] • Menu Vless GRPC "
echo -e " [\e[36m4\e[0m] • Menu Trojan"
echo -e " [\e[36m5\e[0m] • Menu Trojan GO "

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
1) clear ; menu-vmess ;;
2) clear ; menu-vless ;;
3) clear ; menu-vlgrpc ;;
4) clear ; menu-trojan;;
5) clear ; menu-trojanws ;;
0) clear ; menu ;;
x) exit ;;
*) echo -e "" ; echo "Press any key to back on menu" ; sleep 1 ; menu ;;
esac