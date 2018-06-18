# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module contains various helper functions.

from __future__ import unicode_literals

from os import path, linesep
from collections import namedtuple
from io import BytesIO
from struct import unpack

NTFS_CLUSTER_SIZE = 4096
NTFS_COMPRESSION_UNIT_SIZE = 16 * NTFS_CLUSTER_SIZE

DiscoveredLogFiles = namedtuple('DiscoveredLogFiles', [ 'log_path', 'log1_path', 'log2_path' ])

DataAttribute = namedtuple('DataAttribute', [ 'data_runs' ]) # The 'data_runs' field contains a list of (offset, size) tuples (all units are clusters).

SecurityInfo = namedtuple('SecurityInfo', [ 'owner_sid' ])

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

	if len(Buffer) > NTFS_COMPRESSION_UNIT_SIZE or len(Buffer) < NTFS_CLUSTER_SIZE:
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
				table_idx = dst_index - dst_chunk_start
				try:
					length_bits = 16 - compression_bits[table_idx]
				except IndexError:
					# Bogus data.
					bogus_data = True
					break

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

		if bogus_data:
			break

	dbuf = dbuf_obj.getvalue()
	dbuf_obj.close()

	return dbuf

def NTFSDecompressUnitWithNoSlack(Buffer):
	"""Decompress NTFS data from Buffer (a single compression unit) using the LZNT1 algorithm, return a tuple (decompressed_buffer, effective_unit_size).
	The effective unit size will be equal to or less than NTFS_COMPRESSION_UNIT_SIZE. This function should be used if compression units are not aligned on a disk (there is no slack space).
	"""

	if len(Buffer) > NTFS_COMPRESSION_UNIT_SIZE or len(Buffer) < NTFS_CLUSTER_SIZE:
		return # Invalid length of input data.

	pos = 0
	while pos < len(Buffer) and pos < NTFS_COMPRESSION_UNIT_SIZE - NTFS_CLUSTER_SIZE:
		curr_buf = Buffer[ : pos + NTFS_CLUSTER_SIZE]
		if len(curr_buf) < NTFS_CLUSTER_SIZE or len(curr_buf) % NTFS_CLUSTER_SIZE != 0:
			break

		curr_buf_d = NTFSDecompressUnit(curr_buf)
		if len(curr_buf_d) == NTFS_COMPRESSION_UNIT_SIZE:
			return (curr_buf_d, pos + NTFS_CLUSTER_SIZE)

		pos += NTFS_CLUSTER_SIZE

	return (NTFSDecompressUnit(Buffer), NTFS_COMPRESSION_UNIT_SIZE)

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

def NTFSDecodeMappingPairs(MappingPairs):
	"""Decode mapping pairs (NTFS), return a tuple (data_size, data_runs).
	Note: Python 3 only.
	"""

	data_runs = []
	data_size = 0

	i = 0
	first_iter = True
	while True:
		if i >= len(MappingPairs):
			break

		header_byte = MappingPairs[i]
		if header_byte == 0:
			break

		i += 1

		count_length = header_byte & 15
		offset_length = header_byte >> 4

		if count_length == 0 or count_length > 8 or offset_length > 8:
			# Reject invalid values.
			break

		if offset_length == 0:
			# This is a sparse block, ignore it and stop.
			break

		count = MappingPairs[i : i + count_length]
		if len(count) != count_length:
			break

		i += count_length

		offset = MappingPairs[i : i + offset_length]
		if len(offset) != offset_length:
			break

		i += offset_length

		count = int.from_bytes(count, byteorder = 'little', signed = True)
		offset = int.from_bytes(offset, byteorder = 'little', signed = True)
		if count <= 0:
			# Invalid value.
			break

		data_size += count
		if first_iter:
			if offset == 0:
				# Invalid offset.
				break

			data_runs.append((offset, count))
			offset_prev = offset

			first_iter = False
		else:
			offset_curr = offset_prev + offset
			if offset_curr == 0:
				# Unallocated data run, ignore it and stop.
				break

			offset_prev = offset_curr

			data_runs.append((offset_curr, count))

	return (data_size, data_runs)

def NTFSValidateAndDecodeDataAttributeRecord(Buffer):
	"""Check if Buffer starts with an applicable data attribute record (NTFS) and decode this record, return a named tuple (DataAttribute) or None (if not decoded).
	A data attribute record is not applicable:
	 - when its LowestVcn is not equal to 0, because the carver does not deal with mapping pairs split between different records;
	 - when it contains a name, because the carver does not deal with alternate data streams;
	 - when it is resident, because there are no mapping pairs in this case;
	 - when its data is sparse, encrypted, or compressed.
	Note: Python 3 only.
	"""

	if len(Buffer) < 64 + 1: # The buffer with a candidate data attribute record is too small.
		return

	type_code, record_length, form_code, name_length, _, flags, _ = unpack('<LLBBHHH', Buffer[ : 16])

	if type_code != 0x80 or form_code != 0x01 or name_length != 0:
		# This is not a data attribute record, or this is a resident data attribute record, or this is a data attribute record with a name.
		return

	if record_length > len(Buffer) or record_length > 950 or record_length < 64:
		# The data attribute record is either too large or too small.
		return

	if record_length % 8 != 0:
		# The record length is not aligned.
		return

	if flags & 0x8000 > 0 or flags & 0x4000 > 0 or flags & 0x00FF > 0:
		# The data is sparse, or encrypted, or compressed.
		return

	nonresident_header = Buffer[16 : 64]
	lowest_vcn, highest_vcn, mapping_pairs_offset, _, allocated_length, file_size, valid_data_length = unpack('<QQH6sQQQ', nonresident_header)

	if lowest_vcn != 0:
		# Mapping pairs are split between different records.
		return

	if highest_vcn == 0 or mapping_pairs_offset < 64 or mapping_pairs_offset > 72:
		# Reject invalid values.
		return

	if allocated_length < 512 or allocated_length % 512 != 0 or file_size == 0 or valid_data_length == 0:
		# Reject invalid values.
		return

	mapping_pairs = Buffer[mapping_pairs_offset : record_length]
	if len(mapping_pairs) < 3: # A single mapping pair is at least 2 bytes in length. Also, there is a null byte at the end of mapping pairs.
		return

	data_size, data_runs = NTFSDecodeMappingPairs(mapping_pairs)

	if data_size == 0 or data_runs == []:
		# Invalid mapping pairs.
		return

	return DataAttribute(data_runs = data_runs)

def NTFSFindDataAttributeRecords(Buffer):
	"""Locate data attribute records (NTFS) in Buffer and decode these records, return a list of named tuples (DataAttribute).
	Note: Python 3 only.
	"""

	results = []

	pos = Buffer.find(b'\x80\x00\x00\x00')
	while pos != -1 and pos < len(Buffer) - 9:
		if Buffer[pos + 8] == 0x01 and Buffer[pos + 9] == 0:
			data_attr = NTFSValidateAndDecodeDataAttributeRecord(Buffer[pos : pos + 4096])
			if data_attr:
				results.append(data_attr)

		Buffer = Buffer[pos + 1 : ]
		pos = Buffer.find(b'\x80\x00\x00\x00')

	return results

def ParseSID(Buffer):
	"""Parse a security identifier, return a string.
	Note: Python 3 only.
	"""

	if len(Buffer) < 8:
		raise ValueError('SID buffer is too short')

	sid_revision, sid_subauthoritycount, sid_identifierauthority = unpack('<BB6s', Buffer[ : 8])
	sid_str = 'S-{}'.format(sid_revision)

	sid_identifierauthority_int = int.from_bytes(sid_identifierauthority, byteorder = 'big', signed = False)
	if sid_identifierauthority_int < 0x100000000:
		sid_str += '-{}'.format(sid_identifierauthority_int)
	else:
		sid_str += '-0x{}'.format(format(sid_identifierauthority_int, 'X'))

	sa_left = sid_subauthoritycount
	sa_offset = 8
	while sa_left > 0:
		sa_buf = Buffer[sa_offset : sa_offset + 4]
		if len(sa_buf) != 4:
			raise ValueError('SID buffer is too short for a subauthority')

		sa_int = unpack('<L', sa_buf)[0]
		sid_str += '-{}'.format(sa_int)

		sa_offset += 4
		sa_left -= 1

	return sid_str

def ParseSecurityDescriptorRelative(Buffer):
	"""Parse a relative security descriptor, return a named tuple (SecurityInfo).
	Note: Python 3 only.
	"""

	def ValidateOffset(Offset):
		if Offset == 0: # A special value (the field is missing).
			return True

		is_valid_offset = Offset >= 20 and Offset <= len(Buffer) - 4
		return is_valid_offset

	if len(Buffer) < 20:
		raise ValueError('Invalid size of a security descriptor')

	revision, sbz1, control, p_owner, p_group, p_sacl, p_dacl = unpack('<BBHLLLL', Buffer[ : 20])

	if revision != 1:
		raise ValueError('Invalid revision number')

	if control >> 15 == 0:
		raise ValueError('Not a relative security descriptor')

	is_owner_missing_or_invalid = (p_owner == 0) or (not ValidateOffset(p_owner))
	if is_owner_missing_or_invalid:
		# Give up, because we do not parse other fields.
		return SecurityInfo(owner_sid = None)

	owner_sid = ParseSID(Buffer[p_owner : ])

	return SecurityInfo(owner_sid = owner_sid)
