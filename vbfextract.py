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
from time import sleep
from math import ceil
from io import BytesIO

from ford.vbf import Vbf


def usage(str):
	print('usage: {} file.vbf'.format(str))

def debug(str, end="\n"):
	print(str, end=end)
	sys.stdout.flush()

def die(str):
	print(str)
	sys.exit(-1)

if __name__ == '__main__':
	if len(sys.argv) < 2:
		usage(sys.argv[0])
		sys.exit(-1)

	file = sys.argv[1]

	v = Vbf(file)

	for ds in v.data:
		with open('{}.0x{:08x}'.format(file, ds['addr']), 'wb') as f:
			debug("\tExtracting: 0x{:08x}, 0x{:x} bytes... ".format(ds['addr'], ds['size']), end="")
			f.write(ds['data'])
			f.close()
			debug("OK")

