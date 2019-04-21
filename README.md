# pysssp

Python SSSP client.

SSSP - the Sophos Simple Scanning Protocol - is a protocol to talk to a persistant sophos virus scanner and feed data to it.

Protocol details can be found at https://www.sophos.com/en-us/medialibrary/PDFs/documentation/savi_sssp_13_meng.pdf
For this to work, the SAV Dynamic Interface daemon needs to be running as well as a sophos AV daemon. Refer to https://www.sophos.com/en-us/medialibrary/PDFs/documentation/SAVDI-User-Manual.pdf for more details.

Example use:
```
$ sssp.py eicar.com
(False, 'Message is infected with EICAR-AV-Test')
$
```
