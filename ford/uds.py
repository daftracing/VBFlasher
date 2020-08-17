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
from array import array
from time import sleep

from ford.simpleisotp import SimpleISOTP

def debug(str, end="\n"):
	print(str, end=end)
	sys.stdout.flush()

class Ecu:
	def __init__(self, can_interface="vcan0", ecuid=0, bs=0, stmin=0xff, timeout=5):
		self.ssock = SimpleISOTP(can_interface, ecuid, ecuid+0x08)
		self.ecuid  = ecuid

	def recv(self):
		return self.ssock.recv()

	def send(self, msg):
		return self.ssock.send(msg)

	def Mode9(self, data):
		self.send(bytearray([0x09] + data))
		msg = self.recv()
		return msg

	def Reset(self, val=0x01):
		self.send(bytearray([0x11, val]))
		msg = self.recv()

		if msg and msg[0] == 0x51:
			return True
		return False

	def UDSTesterPresent(self):
		self.send(bytearray([0x3e, 0x00]))
		msg = self.recv()

		if msg and msg[0] == 0x7e:
			return True
		return False

	def UDSReadDataByIdentifier(self, id):
		self.send(bytearray([0x22] + id))

		msg = self.recv()
		if msg and msg[0] == 0x62:
			return msg[3:]
		return False		

	def UDSWriteDataByIdentifier(self, id, value):
		self.send(bytearray([0x2e] + id + value))
		msg = self.recv()
		if msg and msg[0] == 0x6e:
			return True
		return False

	def UDSDiagnosticSessionControl(self, id):
		self.send(bytearray([0x10, id]))
		msg = self.recv()
		if msg and msg[0] == 0x50:
			return True
		return False

	def UDSReadMemoryByAddress(self, addr, size, aslen=0x24):
		slen = aslen >> 4
		alen = aslen & 0x0f

		self.send(bytearray([0x23, aslen]) + addr.to_bytes(alen, 'big') + size.to_bytes(slen, 'big'))
		msg = self.recv()
		if msg and msg[0] == 0x63:
			return msg[1:]
		return False

	def UDSSecurityAccess(self, num, key=[]):
		self.send(bytearray([0x27, num] + key))
		msg = self.recv()
		if msg and msg[0] == 0x67:
			if key:
				return True
			return msg[2:]
		return False

	def UDSRequestDownload(self, addr, size, fmt=0x00, aslen=0x44):
		slen = aslen >> 4
		alen = aslen & 0x0f

		self.send(bytearray([0x34, fmt, aslen]) + addr.to_bytes(alen, 'big') + size.to_bytes(slen, 'big'))
		msg = self.recv()

		if msg and msg[0] == 0x74:
			return msg[2:]
		return False

	def UDSRequestUpload(self, addr, size, fmt=0x00, aslen=0x44):
		alen = aslen >> 4
		slen = aslen & 0x0f

		self.send(bytearray([0x35, fmt, aslen]) + addr.to_bytes(alen, 'big') + size.to_bytes(slen, 'big'))
		msg = self.recv()

		if msg and msg[0] == 0x75:
			return msg[2:]
		return False

	def UDSRequestTransferExit(self):
		self.send(bytearray([0x37]))
		while True:
			msg = self.recv()
			if msg:
				if msg[0] == 0x77:
					return True

	def UDSTransferData(self, num, data=bytearray()):
		self.send(bytearray([0x36, num]) + data)
		while True:
			msg = self.recv()
			if msg:
				if msg[0] == 0x76:
					return True

	def UDSTransferDataEx(self, num, data=bytearray()):
		self.send(bytearray([0x36, num]) + data)
		while True:
			msg = self.recv()
			if msg:
				if msg[0] == 0x76:
					return msg[2:]
				else:
					return False

	def UDSRoutineControl(self, cmd, data=b''):
		self.send(bytearray([0x31]+cmd) + data)
		while True:
			msg = self.recv()
			if msg:
				if msg[0] == 0x71:
					return True

	def UDSRoutineControlEx(self, cmd, data=b''):
		self.send(bytearray([0x31]+cmd) + data)
		while True:
			msg = self.recv()
			if msg:
				return msg[2:]
	
	def getHWPartNo(self):
		return self.UDSReadDataByIdentifier([0xf1, 0x11]).decode('utf-8')

	def getPartNo(self):
		return self.UDSReadDataByIdentifier([0xf1, 0x13]).decode('utf-8')

	def getStrategy(self):
		s = self.UDSReadDataByIdentifier([0xf1, 0x88])
		if s:
			return s.decode('utf-8')
		return False

	def getCalibrationID(self):
		return self.Mode9([0x04]).hex()

	def getCVN(self):
		return self.Mode9([0x06]).hex()

	def unlock(self, level):
		seed = self.UDSSecurityAccess(level)
		if seed:
			debug("\t[+] Got seed: {}".format(' '.join(map('{:02x}'.format, seed))))
			try:
				magic = fixedbytes[self.ecuid][level]
			except KeyError as e:
				return False, "[!] Failed! No magic bytes for 0x{:x} level 0x{:2x} found. Aborting.".format(self.ecuid, level)
			debug("\t[+] Magic bytes: 0x{:x}".format(magic))
			key = keygen(seed, magic)
			keystr = ' '.join(map('{:02x}'.format, key))
			debug("\t[+] Sending key: {}".format(keystr))
			if self.UDSSecurityAccess(level+1, key):
				return True, "[+] Success!"
			else:
				return False, "[-] Failed! Aborting."
		else:
			return False, "[-] Failed to get the seed bytes for SecurityAccess 0x{:02x}".format(level)

	def SBLcall(self, addr, alen=4):
		return self.UDSRoutineControl([0x01, 0x03, 0x01], addr.to_bytes(alen, 'big'))

	def commit(self):
		r = self.UDSRoutineControl([0x01, 0x03, 0x04])
		sleep(1)
		return r

	def erase(self, addr, size, aslen=0x44):
		alen = aslen >> 4
		slen = aslen & 0x0f
		return self.UDSRoutineControl([0x01, 0xff, 0x00], addr.to_bytes(alen, 'big') + size.to_bytes(slen, 'big'))

fixedbytes = {
	0x703: {0x01: 0xfa5fc0, 0x03: 0x92c13b},
	0x726: {0x01: 0xfaa8bd, 0x11: 0x128665},
	0x727: {0x03: 0x4ad0fb},
	0x730: {0x01: 0x9b2533},
	0x731: {0x11: 0x462A71},
	0x760: {0x01: 0x582613, 0x03: 0x76807f, 0x11: 0x06316B}
}

def keygen(seed, fixed):
	challengeCode = array('Q')

	challengeCode.append(fixed & 0xff)
	challengeCode.append((fixed >> 8) & 0xff)
	challengeCode.append((fixed >> 16) & 0xff)
	challengeCode.append((fixed >> 24) & 0xff)
	challengeCode.append((fixed >> 32) & 0xff)

	challengeCode.append(seed[2])
	challengeCode.append(seed[1])
	challengeCode.append(seed[0])

	temp1 = 0xC541A9
	for i in range(64):
		abit = temp1 & 0x01
		chbit = challengeCode[7] & 0x01
		bbit = abit ^ chbit

		temp2 = (temp1 >> 1) + bbit * 0x800000 & -1
		temp1 = (temp2 ^ 0x109028 * bbit) & -1
		challengeCode[7] = challengeCode[7] >> 1 & 0xff
		for a in range(7, 0, -1):
			challengeCode[a] = challengeCode[a] + (challengeCode[a - 1] & 1) * 128 & 0xff
			challengeCode[a - 1] = challengeCode[a - 1] >> 1

	
	key = [ temp1 >> 4 & 0xff, ((temp1 >> 12 & 0x0f) << 4) + (temp1 >> 20 & 0x0f), (temp1 >> 16 & 0x0f) + ((temp1 & 0x0f) << 4) ]

	return key

