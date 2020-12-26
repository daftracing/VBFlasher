#!/usr/bin/env python3

"""
This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import os
from time import sleep, time
from math import ceil
from io import BytesIO

import can
from subprocess import Popen, PIPE

from ford.vbf import Vbf
from ford.uds import keygen, fixedbytes, Ecu


def tccheck(can_interface):	
	cmd = "tc qdisc show | grep {} | cut -f2 -d' '".format(can_interface)

	with Popen(cmd, shell=True, stdout=PIPE, preexec_fn=os.setsid) as process:
	    output = process.communicate()[0]

	if output:
		if 'fifo' in output.decode("utf-8"):
			return True

	return False


class Vbflasher:
	def __init__(self, can_interface="can0", sbl_path=None, exe_path=None, data_path=None):
		self.ecuid = None
		self.has_sbl = False
		self.sbl = None
		self.exe = None
		self.data = None

		if sbl_path:
			self.sbl = Vbf(sbl_path)
			self.ecuid = self.sbl.ecuid
			self.has_sbl = True

		if exe_path:
			if not self.has_sbl:
				die("[!] No SBL loaded! Please add --sbl or --force")
			self.exe = Vbf(exe_path)
			if self.ecuid != self.exe.ecuid:
				die("[!] Loaded VBF file for a different ECU than before. Aborting.")

		if data_path:
			self.data = Vbf(data_path)

			if self.ecuid:
				if self.ecuid != self.data.ecuid:
					die("[!] Loaded VBF file for a different ECU than before. Aborting.")
			else:
				self.ecuid = self.data.ecuid

		if self.ecuid:
			self.ecu = Ecu(can_interface=can_interface, ecuid=self.ecuid)
			if not tccheck(can_interface):
				die("[!] Please set {} qdisc to pfifo_fast. Now it's too risky to continue...".format(can_interface))
		else:
			die("[!] No valid VBF loaded...")


	def tester(self):
		debug("[+] Sending TesterPresent to 0x{:x}... ".format(self.ecuid), end="")
		if self.ecu.UDSTesterPresent():
			debug("OK")
		else:
			die("\n[-] 0x{:x} did not send positive reposnse to our tester message... Aborting".format(self.ecuid))


	def ver(self):
		self.ecu.UDSDiagnosticSessionControl(0x01)
		sleep(2)

		tmp = self.ecu.getHWPartNo()
		debug("\n[?] HWPartNo: {}".format(tmp))

		tmp = self.ecu.getPartNo()
		debug("[?] PartNo: {}".format(tmp))

		debug("[?] Current software: ", end="")
		sw = self.ecu.getStrategy()
		if sw:
			debug(sw)
		else:
			die("\n[-] Unable to get the current strategy id. Aborting")


	def verEx(self):
		self.ecu.UDSDiagnosticSessionControl(0x01)
		sleep(2)

		tmp = self.ecu.getHWPartNo()
		debug("\n[?] HWPartNo: {}".format(tmp))

		tmp = self.ecu.getPartNo()
		debug("[?] PartNo: {}".format(tmp))

		debug("[?] Checking current strategy... ", end="")
		sw = self.ecu.getStrategy()
		if sw:
			debug(sw)
		else:
			die("\n[-] Unable to get the current strategy id. Aborting")

		tmp = self.ecu.UDSReadDataByIdentifier([0xf1, 0x24]).decode('UTF-8')
		debug("[?] Current calibration: {}".format(tmp))

		tmp = self.ecu.getCVN()
		debug("[?] CVN: {}\n".format(tmp))


	def start(self):
		debug("\n[+] Starting Diagnostic Session 0x02... ", end="")
		if self.ecu.UDSDiagnosticSessionControl(0x02): # 0x02
			debug("OK")
		else:
			die("\n[-] Unable to start diagnostic session. Aborting.")
		sleep(1)

		debug("[ ] Unlocking the ECU...")
		res, msg = self.ecu.unlock(0x01) # 0x01
		if res:
			debug(msg)
		else:
			die(msg)


	def upload(self, vbf):
		spinner = ['/','-', '\\', '|']
		fmt = int(vbf.header.get('data_format_identifier', '0x00'), 16)

		for ds in vbf.data:
			debug("\n[ ] Requesting download of 0x{:08x} bytes to 0x{:08x}".format(ds['size'], ds['addr']))
			chunk = self.ecu.UDSRequestDownload(addr=ds['addr'], size=ds['size'], fmt=fmt)
			if not chunk:
				die("[-] Download request failed. Aborting.")
			chunk = int(chunk.hex(), 16) - 2

			num = ceil(ds['size']/chunk)
			for i in range(1, num+1):

				d = ds['data'][(i-1)*chunk : i*chunk]
				debug("\r\t[{}] Sending 0x{:04x} bytes block #{:2d}/{}... ".format(spinner[i%4],len(d), i, num), end="")
				if self.ecu.UDSTransferData(i%256, d):
					pass
				else:
					die("\n[-] Failed. Aborting.")
			print('OK\r\t[+')

			if self.ecu.UDSRequestTransferExit():
				debug("[+] Transfer done.")
			else:
				die("[-] Transfer failed. Aborting.")


	def erase(self, vbf):
		if not vbf.header.get('erase'):
			return

		if type(vbf.header.get('erase')[0]) != list:
			vbf.header['erase'] = [vbf.header['erase']]

		debug("\n[+] Erasing memory:")
		for ds in vbf.header.get('erase'):
			addr = int(ds[0], 16)
			size = int(ds[1], 16)

			debug("\t0x{:08x}: 0x{:x} bytes... ".format(addr, size), end="")
			if self.ecu.erase(addr, size):
				debug("OK")
			else:
				die("[!] Unable to wipe memroy. Rather be safe than sorry. Bye...")


	def testerloop(self):
		while  True:
			self.ecu.UDSTesterPresent();
			sleep(1)


	def flash_sbl(self):
		self.upload(self.sbl)
		debug("\n[+] Calling SBL at {}... ".format(self.sbl.header['call']), end="")
		if self.ecu.SBLcall(int(self.sbl.header['call'], 16)):
			debug("OK")
		else:
			die("[-] Executing SBL failed. Aborting.")


	def flash_exe(self):
		self.erase(self.exe)
		self.upload(self.exe)
		self.ecu.commit()


	def flash_data(self):
		self.erase(self.data)
		self.upload(self.data)
		self.ecu.commit()


	def flash(self):
		if self.sbl:
			debug("\n[*] Loading SBL...")
			self.flash_sbl()

		if self.exe:
			debug("\n[*] Flashing EXE...")
			self.flash_exe()

		if self.data:
			debug("\n[*] Flashing DATA...")
			self.flash_data()


def usage(str):
	print('usage: {} interface sbl_file.vbf strategy_file.vbf calibration_file.vbf'.format(str))


def debug(str, end="\n"):
	print(str, end=end)
	sys.stdout.flush()


def die(str):
	print(str)
	sys.exit(-1)


if __name__ == '__main__':
	if len(sys.argv) < 5:
		usage(sys.argv[0])
		sys.exit(-1)

	iface = sys.argv[1]
	sbl_path = sys.argv[2]
	exe_path = sys.argv[3]
	data_path = sys.argv[4]

	try:
		flasher = Vbflasher(can_interface=iface, sbl_path=sbl_path, exe_path=exe_path, data_path=data_path)
	except OSError as e:
		enum = e.args[0]
		if enum == 19:
			die('[!] Unable to open device {}'.format(iface))
		if enum == 99:
			die('[!] Unable to assign ecu address = {}'.format(ecuid))
		die(e)

	debug("\n[+] Successfully opened {}".format(iface))

	flasher.start()
	flasher.flash()
	sleep(3)
	flasher.verEx()
