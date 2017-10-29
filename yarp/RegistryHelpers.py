# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module contains various helper functions.

from __future__ import unicode_literals

from os import path, linesep
from collections import namedtuple
from io import BytesIO
from struct import unpack

NTFS_COMPRESSION_UNIT_SIZE = 16 * 4096 # 16 clusters, 4096 bytes per cluster.

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

def NTFSDecompressUnit(Buffer):
	"""Decompress NTFS data from Buffer (a single compression unit) using the LZNT1 algorithm."""

	def is_valid_write_request(offset, length):
		return offset + length <= 2*1024*1024*1024 # Reject obviously invalid write requests.

	if len(Buffer) > NTFS_COMPRESSION_UNIT_SIZE:
		return # Invalid length of input data.

	compression_bits = [ 0 ] * 4096

	offset_bits = 0
	y = 16
	for x in range(0, 4096):
		compression_bits[x] = 4 + offset_bits
		if x == y:
			y = y * 2
			offset_bits += 1

	src_index = 0
	dst_index = 0
	dbuf_obj = BytesIO()

	while src_index < len(Buffer):
		header_bytes = Buffer[src_index : src_index + 2]
		src_index += 2

		if len(header_bytes) < 2:
			break # Truncated header.

		header, = unpack('<H', header_bytes)

		if header == 0:
			break # End of the buffer.

		if header & 0x7000 != 0x3000:
			break # Invalid signature.

		if header & 0x8000 == 0:
			# Not a compressed block, copy literal data.
			block_size = (header & 0x0FFF) + 1

			if not is_valid_write_request(dst_index, block_size):
				break # Bogus data.

			dbuf_obj.seek(dst_index)
			bytes_ = Buffer[src_index : src_index + block_size]
			dbuf_obj.write(bytes_)

			if len(bytes_) == block_size:
				src_index += block_size
				dst_index += block_size
				continue
			else:
				break # Truncated literal data.

		# A compressed block.
		dst_chunk_start = dst_index
		src_chunk_end = src_index + (header & 0x0FFF) + 1

		bogus_data = False
		while src_index < src_chunk_end and src_index < len(Buffer) and not bogus_data:
			flags = Buffer[src_index]
			if type(flags) is not int:
				flags = ord(flags)

			src_index += 1

			for token in range(0, 8):
				if src_index >= src_chunk_end:
					break

				if src_index >= len(Buffer):
					# Truncated chunk.
					break

				flag = flags & 1
				flags = flags >> 1

				if flag == 0:
					# A literal byte, copy it.
					if not is_valid_write_request(dst_index, 1):
						# Bogus data.
						bogus_data = True
						break

					dbuf_obj.seek(dst_index)
					bytes_ = Buffer[src_index : src_index + 1]
					dbuf_obj.write(bytes_)

					if len(bytes_) == 1:
						dst_index += 1
						src_index += 1
						continue
					else:
						# Truncated chunk.
						bogus_data = True
						break

				# A compression tuple.
				length_bits = 16 - compression_bits[dst_index - dst_chunk_start]
				length_mask = (1 << length_bits) - 1

				ctuple_bytes = Buffer[src_index : src_index + 2]
				src_index += 2

				if len(ctuple_bytes) < 2:
					# Truncated chunk.
					bogus_data = True
					break

				ctuple, = unpack('<H', ctuple_bytes)
				back_off_rel = (ctuple >> length_bits) + 1
				back_off = dst_index - back_off_rel
				back_len = (ctuple & length_mask) + 3

				if back_off < dst_chunk_start:
					# Bogus compression tuple.
					bogus_data = True
					break

				for i in range(0, back_len):
					# Decompress data.
					dbuf_obj.seek(back_off)
					bytes_ = dbuf_obj.read(1)
					if len(bytes_) != 1:
						# Invalid offset.
						bogus_data = True
						break

					if not is_valid_write_request(dst_index, 1):
						# Bogus data.
						bogus_data = True
						break

					dbuf_obj.seek(dst_index)
					dbuf_obj.write(bytes_)

					dst_index += 1
					back_off += 1

				if bogus_data:
					break

		if dst_chunk_start + 4096 > dst_index:
			dst_skip = dst_chunk_start + 4096 - dst_index

			if is_valid_write_request(dst_index, dst_skip):
				dbuf_obj.seek(dst_index)
				bytes_ = b'\x00' * dst_skip
				dbuf_obj.write(bytes_)

				dst_index += dst_skip

	dbuf = dbuf_obj.getvalue()
	dbuf_obj.close()

	return dbuf

def NTFSCheckCompressedSignature(Buffer, Signature):
	"""Check if Buffer (a compressed block) contains a given signature (which cannot be compressed). The LZNT1 algorithm is assumed."""

	if len(Signature) == 0 or len(Signature) > 8:
		return False # Invalid signature.

	if len(Buffer) < 3 + len(Signature):
		return False # Truncated buffer.

	first_bytes = Buffer[ : 2 + len(Signature)]
	if first_bytes.endswith(Signature):
		header, = unpack('<H', Buffer[ : 2])
		return header & 0x7000 == 0x3000 and header & 0x8000 == 0

	first_bytes = Buffer[ : 3 + len(Signature)]
	if first_bytes.endswith(Signature):
		header, flags = unpack('<HB', Buffer[ : 3])
		return header & 0x7000 == 0x3000 and header & 0x8000 != 0 and (flags << (8 - len(Signature)) == 0)

	return False
