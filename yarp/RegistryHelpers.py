# yarp: yet another registry parser
# (c) Maxim Suhanov

from __future__ import unicode_literals

from os import path, linesep
from collections import namedtuple

DiscoveredLogFiles = namedtuple('DiscoveredLogFiles', [ 'log_path', 'log1_path', 'log2_path' ])

def DiscoverLogFiles(PrimaryPath):
	"""Return a named tuple (DiscoveredLogFiles) describing a path to each transaction log file of a supplied primary file."""

	def DiscoverLogFilesInternal(PrimaryPath):
		# We prefer uppercase extensions.
		log = PrimaryPath + '.LOG'
		log1 = PrimaryPath + '.LOG1'
		log2 = PrimaryPath + '.LOG2'

		if path.isfile(log) or path.isfile(log1) or path.isfile(log2):
			# At least one file has an uppercase extension, use it and others (if present).
			if not path.isfile(log):
				log = None
			if not path.isfile(log1):
				log1 = None
			if not path.isfile(log2):
				log2 = None

			return DiscoveredLogFiles(log_path = log, log1_path = log1, log2_path = log2)

		# Now, switch to lowercase extensions.
		log = PrimaryPath + '.log'
		log1 = PrimaryPath + '.log1'
		log2 = PrimaryPath + '.log2'

		if path.isfile(log) or path.isfile(log1) or path.isfile(log2):
			# At least one file has a lowercase extension, use it and others (if present).
			if not path.isfile(log):
				log = None
			if not path.isfile(log1):
				log1 = None
			if not path.isfile(log2):
				log2 = None

			return DiscoveredLogFiles(log_path = log, log1_path = log1, log2_path = log2)

	directory, filename = path.split(PrimaryPath)
	filenames = sorted(set([ filename, filename.lower(), filename.upper() ]))
	for filename in filenames:
		result = DiscoverLogFilesInternal(path.join(directory, filename))
		if result is not None:
			return result

	# Give up.
	return DiscoveredLogFiles(log_path = None, log1_path = None, log2_path = None)

def HexDump(Buffer):
	"""Return bytes from Buffer as a hexdump-like string (16 bytes per line)."""

	def int2hex(i):
		return '{:02X}'.format(i)

	if type(Buffer) is not bytearray:
		Buffer = bytearray(Buffer)

	output_lines = ''

	i = 0
	while i < len(Buffer):
		bytes_line = Buffer[i : i + 16]

		address = int2hex(i)
		address = str(address).zfill(8)
		hex_line = ''
		ascii_line = ''

		k = 0
		while k < len(bytes_line):
			single_byte = bytes_line[k]

			hex_line += int2hex(single_byte)
			if k == 7 and k != len(bytes_line) - 1:
				hex_line += '-'
			elif k != len(bytes_line) - 1:
				hex_line += ' '

			if single_byte >= 32 and single_byte <= 126:
				ascii_line += chr(single_byte)
			else:
				ascii_line += '.'

			k += 1

		padding_count = 16 - k
		if padding_count > 0:
			hex_line += ' ' * 3 * padding_count

		output_lines += address + ' ' * 2 + hex_line + ' ' * 2 + ascii_line

		i += 16

		if i < len(Buffer):
			output_lines += linesep

	return output_lines
