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
from io import StringIO
from struct import unpack

from ford.vbf_parser import Lark_StandAlone, Tree, Token

def die(str):
	print(str)
	sys.exit(-1)

def debug(s):
	return print(s)

parser = Lark_StandAlone()

class Vbf:
	def __init__(self, path):
		try:
			v = read(path)
			self.header = v['header']
			self.data = v['data']
			self.type = v['header']['sw_part_type']
			self.ecuid = int(v['header']['ecu_address'], 16)
		except FileNotFoundError as e:
			die("[!] Unable to open {}".format(path))
		except KeyError as e:
			die("[!] Incomplete VBF file header")

		debug("[+] {}: {} loaded".format(v['header']['sw_part_type'], v['header']['sw_part_number']))

def cparse(c):
	if type(c) == Tree:
		if c.data == 'list':
			l = list()
			for a in c.children:
				l.append(cparse(a))
			return l
		if c.data == 'string':
			return c.children[0][1:-1]
		return cparse(c.children[0])
	if type(c) == Token:
		return cparse(c.value)
		
	return c


def vbf_parse_header(f):
	r = dict()

	p = parser.parse(f.read())
	for c in p.children:
		if type(c) == Tree and c.data == 'pair':
			node = c.children[0].value
			val = cparse(c.children[1])
			r[node] = val

	return r

def vbf_get_header(data):
	header = bytearray()
	braces = 0

	for i in range(len(data)):
		ch = data[i]
		header.append(ch)
		
		if ch == 0x7d:
			braces = braces - 1
			if braces < 1:
				return i, header
		if ch == 0x7b:
			braces = braces + 1

def vbf_get_rawdata(header_end_pos, f):
	l = list()
	f.seek(header_end_pos+1)

	while True:
		b = f.read(8)
		if not b:
			break
			
		block = dict()
		block['addr'], block['size'], = unpack('>II', b)
		block['data'] = f.read(block['size'])
		block['checksum'] = f.read(2)

		l.append(block)

	return l


def read(path):
	vbf = dict()

	with open(path, 'rb') as f:
		data = f.read()
		header_len, header_data = vbf_get_header(data)
		vbf['header'] = vbf_parse_header(StringIO(header_data.decode('utf-8')))
		vbf['data'] = vbf_get_rawdata(header_len, f)

	return vbf

def usage(str):
	print('usage: {} file.vbf'.format(str))

if __name__ == '__main__':
	if len(sys.argv) < 2:
		usage(sys.argv[0])
		sys.exit(-1)
	try:
		vbf = read(sys.argv[1])
	except FileNotFoundError as e:
		print('[-] Unable to open {}'.format(path))
		sys.exit(-1)

	for a in vbf['data']:
		print('0x{:08x} 0x{:08x}'.format(a['addr'], a['size']))

