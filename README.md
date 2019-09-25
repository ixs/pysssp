# pysssp

Python SSSP client.

SSSP - the Sophos Simple Scanning Protocol - is a protocol to talk to a persistant sophos virus scanner and feed data to it.

Protocol details can be found at https://www.sophos.com/en-us/medialibrary/PDFs/documentation/savi\_sssp\_13\_meng.pdf
For this to work, the SAV Dynamic Interface daemon needs to be running as well as a sophos AV daemon. Refer to https://www.sophos.com/en-us/medialibrary/PDFs/documentation/SAVDI-User-Manual.pdf for more details.

Example use:
```
$ sssp.py eicar.com
(False, 'Message is infected with EICAR-AV-Test')
$
```

Clamscan wrapper to read from stdin and scan via SAVDI TCP socket
```
$ clamscan-sssp -S inet:127.0.0.1:4020 -

```
This is useful to scan files on request with OwnCloud/Nextcloud's files\_antivirus app
