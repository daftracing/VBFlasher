#!/usr/bin/env python3

"""
FIXME: We don't care about the VBF file checksums for now -> will use vbflasher anyway

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
import argparse
from pathlib import Path
from struct import pack

from crccheck.crc import Crc16CcittFalse

from ford.vbf import Vbf

header = """vbf_version = 2.3;

header {{
    sw_part_number = "{}";
    sw_part_type = {};
    data_format_identifier = 0x00;
    network = {};
    ecu_address = {};
    frame_format = {};

    {}

    file_checksum = 0xdeadbeef;
}}"""

def die(str):
	print(str)
	sys.exit(-1)

def ck_list(algos):
	print("\t[!] Can't find suitable checksum algorithm. Available --sw options: ", end='')
	for a in algos:
		print("{} ".format(a),end='')
	print()

def ck_g1f7_14c367(blocks):
	c = Crc16CcittFalse.calc(blocks[0][2][0x100:])
	c1 = c & 0xff
	c2 = c >> 8
	
	print("\t[+] Checksum 0x{:02x}{:02x}. ".format(c1, c2), end='')
	if c1 == blocks[0][2][0xa4] and c2 == blocks[0][2][0xa5]:
		print("Correct!")
	else:
		blocks[0][2][0xa4] = c1
		blocks[0][2][0xa5] = c2
		print("Fixed!")

def ck_g1f7_14c366(blocks):
	last = False
	for b in blocks:
		if not last or b[0] > last[0]:
			last = b

	hend = last[2][-6:-2]
	if hend != b'\x20\x20\x20\x20':
		print("[!] Can't find checksum section in the last segment ...")
		return False

	pos = len(last[2])-16
	while pos and last[2][pos:pos+4] != b'\x10\x10\x10\x10':
		pos = pos - 1
		hpos = pos

	if not pos:
		print("[!] Can't find checksum section in the last segment ...")
		return False

	n = (last[2][pos+5] << 8) + last[2][pos+4]

	print("\t[+] Found {} entries checksum section in segment 0x{:08x} offset 0x{:08x}".format(n, last[0], pos))

	pos = pos + 6
	for a in range(n):
		addr = (last[2][pos+3] << 24 ) + (last[2][pos+2] << 16) + (last[2][pos+1] << 8) + last[2][pos]
		pos = pos + 4
		l = (last[2][pos+3] << 24 ) + (last[2][pos+2] << 16) + (last[2][pos+1] << 8) + last[2][pos]
		pos = pos + 4
		c = (last[2][pos+1] << 8) + last[2][pos]

		print("\t\t[+] 0x{:08x}: ".format(addr), end="")

		found = False
		for b in blocks:
			if b[0] <= addr and addr <= b[0] + b[1]:
				found = b

		if not found:
			print("Not found!\r\t\t[-")
		else:
			offset = addr - found[0]
			print("Found at 0x{:08x}+{:x}, ".format(found[0], offset), end="")
			val = 0
			for i in range(l):
				val = (val + found[2][offset+i]) & 0xffff 
			print("checksum 0x{:04x}. ".format(val), end="")
			if val == c:
				print("Correct!")
			else:
				last[2][pos+1] = val >> 8
				last[2][pos] = val & 0xff
				print("Fixed!")

		pos = pos + 2

	val = 0
	for i in range(n*10+10):
		val = (val + last[2][hpos+i]) & 0xffff
	print("\t[+] Header checksum: 0x{:02x}. ".format(val), end="")

	hc = (last[2][hpos+i+2] << 8) + last[2][hpos+i+1]
	if val == hc:
		print("Correct!")
	else:
		last[2][hpos+i+2] = val >> 8
		last[2][hpos+i+1] = val & 0xff
		print("Fixed!")


def fix_checksum(sw, blocks):
	algos = {
		"G1F7-14C366": ck_g1f7_14c366,
		"G1F7-14C367": ck_g1f7_14c367
	}

	if len(sw.split('-')) > 2:
		sw = '-'.join(sw.split('-')[0:2])

	print('\n[*] Calculating checksum for {} ...'.format(sw))
	algos.get(sw, lambda a: ck_list(algos))(blocks)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="Create VBF file containing 1+ blocks represented by addr:path pairs")
	parser.add_argument("--out", help="Outpu VBF file", required=True)
	parser.add_argument("--ecu", help="ECU address (like 0x760)", required=True)
	parser.add_argument("--can", help="CAN_HS or CAN_MS, HS by default", default="CAN_HS")
	parser.add_argument("--type", help="[SBL,EXE,SIG,...]", default="EXE")
	parser.add_argument("--sw", help="Software part number", default="")
	parser.add_argument("--call", help="Address to call, SBL block iteself by default", default=None)
	parser.add_argument("--frame-format", help="CAN frame format. Can be CAN_STANDARD (default) or CAN_EXTENDED", default="CAN_STANDARD")
	parser.add_argument("--erase-blocks", help="Comma separated list of blocks to erase before writing", default=False)
	parser.add_argument("--erase-memory", type=str, help='Comma separated list of memory ranges to erase described as addr:size')
	parser.add_argument("blocks", metavar='addr:path', type=str, nargs='+', help='list of blocks described as addr:path')

	parser.add_argument("--fix-checksum", help="Try to calculate known checksums, algorithm based on --sw", default=False, action='store_true')

	args = parser.parse_args()

	print("[*] Generating {} VBF file for {}".format(args.type, args.ecu))

	blocks = list()
	for p in args.blocks:
		addr,path = p.split(':')
		path = Path(path)

		addr = int(addr, 16)
		if not path.is_file():
			die("[!] Can't open {}".format(path))

		size = path.stat().st_size

		f = open(path, 'rb')
		data = f.read()
		blocks.append([addr, size, bytearray(data)])

		print("\t[+] Adding 0x{:x} bytes block from {} at 0x{:08x}".format(path.stat().st_size, path, addr))

	body = str()

	calladdr = False

	if args.type == "SBL":
		calladdr = "0x{:08x}".format(blocks[0][0])

	if args.call:
		if args.type != "SBL":
			print("[-] Does it really make sens to use call for non-SBL?!")
			calladdr = args.call
	
	if calladdr:
		body += "call = {};\n".format(args.call)
	
	e = str()

	if args.erase_blocks:
		for n in args.erase_blocks.split(','):
			b = blocks[int(n)-1]
			e += "{{ 0x{:08x}, 0x{:08x} }},".format(b[0], b[1])

	if args.erase_memory:
		for n in args.erase_memory.split(','):
			a = n.split(':')[0]
			b = n.split(':')[1]
			e += "{{ {}, {} }},".format(a, b)			

	if e:
		body += "erase = {{ {} }};".format(e[:-1])

	header = header.format(args.sw, args.type, args.can, args.ecu, args.frame_format, body)

	if args.fix_checksum:
		fix_checksum(args.sw, blocks)

	print("\n[+] Writing {} ...".format(args.out))
	with open(args.out, 'wb') as f:
		f.write(header.encode("ASCII"))
		for b in blocks:
			f.write(pack('>II', b[0], b[1]))
			f.write(b[2])
			f.write(b'AA')

