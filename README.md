# VBFlasher
A set of tools to edit and flash both factory and custom made VBF files using a SocketCAN compatible interface.

Developed as a part of an Open Source Focus RS tuning stack but should be useful with many other models as well.

## Install
```
$ pip3 install can pyserial crccheck
```

## Code reuse
It can be used as a module to provide ISOTP implementation and UDS functionalities including SecurityAccess 

## Example usage
#### Update ABS module on a Ford Focus RS mk3
```
$ ./vbflasher.py can0 /tmp/E3B1-14C039-AA.vbf /tmp/G1FC-14C036-AF.vbf /tmp/G1FC-14C381-AF.vbf
```
#### Custom RDU calibration (170C temp limit) 

##### Extract binary
```
$ ./vbfextract.py /tmp/G1F7-14C367-AL.vbf
[+] DATA: G1F7-14C367-AL loaded
	Extracting: 0x00c08000, 0x2000 bytes... OK
```
##### Use Perl to tune your car!
```
$ perl -e 'print "\xAA\x00" x5' | dd of=/tmp/G1F7-14C367-AL.vbf.0x00c08000 bs=1 seek=$((0x136a)) conv=notrunc
```
##### Recreate VBF file
```
$ ./vbfmake.py --sw G1F7-14C367-AL-170C --type DATA --can CAN_HS --ecu 0x703 --fix-checksum --out /tmp/G1F7-14C367-AL-170C.vbf --erase-memory 0x00c08000:0x00002000,0x00ccfe80:0x00000180 0x00c08000:/tmp/G1F7-14C367-AL.vbf.0x00c08000

[*] Generating DATA VBF file for 0x703
	[+] Adding 0x2000 bytes block from /tmp/G1F7-14C367-AL.vbf.0x00c08000 at 0x00c08000

[*] Calculating checksum for G1F7-14C367 ...
	[+] Checksum 0x59ae. Fixed!

[+] Writing /tmp/G1F7-14C367-AL-170C.vbf ...
```

##### Flash it
```
$ ./vbflasher.py can0 /tmp/G1F7-14C368-AA.vbf /tmp/G1F7-14C366-AL.vbf /tmp/G1F7-14C367-AL-170C.vbf
[+] SBL: G1F7-14C368-AA loaded
[+] EXE: G1F7-14C366-AL loaded
[+] DATA: G1F7-14C367-AL-170C loaded

[+] Successfully opened can0

[+] Starting Diagnostic Session 0x02... OK
[ ] Unlocking the ECU...
	[+] Got seed: 1f 7c 69
	[+] Magic bytes: 0xfa5fc0
	[+] Sending key: 9a 64 ce
[+] Success!

[*] Loading SBL...

[ ] Requesting download of 0x000003d0 bytes to 0x00e00000
	[+] Sending 0x03d0 bytes block # 1/1... OK
[+] Transfer done.

[+] Calling SBL at 0xE00000... OK

[*] Flashing EXE...

[+] Erasing memory:
	0x00c0a000: 0x5000 bytes... OK
	0x00c10000: 0x30000 bytes... OK
	0x00c40000: 0x20000 bytes... OK
	0x00cc0000: 0x10000 bytes... OK

[ ] Requesting download of 0x00005000 bytes to 0x00c0a000
	[+] Sending 0x0400 bytes block #20/20... OK
[+] Transfer done.

[ ] Requesting download of 0x00050000 bytes to 0x00c10000
	[+] Sending 0x0400 bytes block #320/320... OK
[+] Transfer done.

[ ] Requesting download of 0x00000f00 bytes to 0x00cc0000
	[+] Sending 0x0300 bytes block # 4/4... OK
[+] Transfer done.

[ ] Requesting download of 0x00008378 bytes to 0x00cc1000
	[+] Sending 0x0378 bytes block #33/33... OK
[+] Transfer done.

[ ] Requesting download of 0x000003e4 bytes to 0x00cca000
	[+] Sending 0x03e4 bytes block # 1/1... OK
[+] Transfer done.

[ ] Requesting download of 0x00003e5c bytes to 0x00ccc000
	[+] Sending 0x025c bytes block #16/16... OK
[+] Transfer done.

[*] Flashing DATA...

[+] Erasing memory:
	0x00c08000: 0x2000 bytes... OK
	0x00ccfe80: 0x180 bytes... OK

[ ] Requesting download of 0x00002000 bytes to 0x00c08000
	[+] Sending 0x0400 bytes block # 8/8... OK
[+] Transfer done.

[?] HWPartNo: G1F7-14C365-AE
[?] PartNo: G1F7-7H417-AK
[?] Checking current strategy... G1F7-14C366-AL
[?] Current calibration: G1F7-14C367-AL
```
