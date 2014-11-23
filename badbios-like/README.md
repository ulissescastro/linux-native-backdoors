Linux native "badBios" version
======================
*working in progress*

```shell-session

#curl google API
curl -X POST \
--data-binary @'/tmp/hello.wav' \
--header 'Content-Type: audio/l16; rate=16000;' \
'https://www.google.com/speech-api/v2/recognize?output=json&lang=en-us&key=<your key>'

# pulseaudio tools (arecord)
arecord -d 5 --format=cd --channels=1 --rate=16000 --file-type wav -D default /tmp/trigger.wav

```

