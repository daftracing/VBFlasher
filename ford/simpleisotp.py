"""
This is by no means a full/proper ISOTP implementation. It aims to work with just the BROKEN Ford implementation.


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
from time import sleep
from io import BytesIO
import can

class SimpleISOTP:
	def __init__(self, can_interface, can_tx, can_rx):
		self.state = 0
		self.can_id = can_tx
		try:
			self.bus = can.interface.Bus(bustype='socketcan', channel=can_interface, bitrate=500000, receive_own_messages=False)
		except can.CanError as e:
			print("[!] Unable to open {}".format(can_interface))
			sys.exit(-1)

		can_filters = [{"can_id": can_rx, "can_mask": 0xfff, "extended": False}]
		self.bus.set_filters(can_filters)

	def putoncan(self, msg):
		sleep(0.002)
		return self.bus.send(msg)

	def send(self, payload):
		size = len(payload)

		if size < 8:
			self.state = 0
			data = bytearray([len(payload)]) + payload + bytearray([0x00] * (7-size))
			msg = can.Message(arbitration_id=self.can_id, data=data, extended_id=False)
			self.putoncan(msg)
		else:
			data = bytearray().fromhex('1{:03x}'.format(size)) + payload[:6]
			msg = can.Message(arbitration_id=self.can_id, data=data, extended_id=False)
			self.putoncan(msg)
			while True:
				fc = self.bus.recv()
				if fc.data[0] & 0xf0 == 0x30:
					break

			self.state = 1
			ds = BytesIO(payload[6:])

			while True:
				part = ds.read(7)
				if not part:
					self.state = 0
					break

				data = bytearray([0x20+self.state]) + part + bytearray([0x00] * (7-len(part)))
				msg = can.Message(arbitration_id=self.can_id, data=data, extended_id=False)
				self.putoncan(msg)
				if self.state < 0x0f:
					self.state += 1
				else:
					self.state = 0

	def recv(self):
		while True:
			data = self.bus.recv().data
			# print("DEBUG: {}".format(data))
			if not data:
				return None

			if self.state == 0 and (data[0] & 0xf0 == 0x10):
				self.state = 1
				size = (data[0] & 0x0f) * 0x100 + data[1]
				buf = BytesIO()
				received = 6
				buf.write(data[2:])

				data = bytearray([0x30]) + bytearray([0x00] * 7)
				msg = can.Message(arbitration_id=self.can_id, data=data, extended_id=False)				
				self.putoncan(msg)

			if self.state > 0 and (data[0] & 0xf0 == 0x20):
				self.state = 2

				if(received + 7 > size):
					buf.write(data[1:1+size-received])
				else:
					buf.write(data[1:])

				received += 7
				if received >= size:
					self.state = 0
					buf.seek(0)
					return buf.read()


			if self.state == 0 and (data[0] & 0xf0 != 0x30):
				size = data[0]
				return data[1:size+1]
