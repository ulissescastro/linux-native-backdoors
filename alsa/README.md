Linux native "badBios" version
======================
*working in progress*

<a href="http://www.youtube.com/watch?feature=player_embedded&v=iokzWGWitws" target="_blank"><img src="http://img.youtube.com/vi/iokzWGWitws/0.jpg" alt="DNS Exfiltration POC" width="480" height="360" border="10" /></a>

```shell-session

#curl google API
curl -X POST \
--data-binary @'/tmp/hello.wav' \
--header 'Content-Type: audio/l16; rate=16000;' \
'https://www.google.com/speech-api/v2/recognize?output=json&lang=en-us&key=AIzaSyAqk7vE0vQDR3JItUPgFp6bcPqgJz8h8tI'

# pulseaudio tools (arecord)
arecord -d 5 --format=cd --channels=1 --rate=16000 --file-type wav -D default /tmp/trigger.wav

```

