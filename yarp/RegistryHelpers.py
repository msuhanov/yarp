# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module contains various helper functions.

from __future__ import unicode_literals

from os import path, linesep
from collections import namedtuple
from io import BytesIO
from struct import unpack

__cython_armed__ = False

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


LZNT1_COMPRESSION_BITS = [ 0 ] * 4096

offset_bits = 0
y = 16
for x in range(0, 4096):
	LZNT1_COMPRESSION_BITS[x] = 4 + offset_bits
	if x == y:
		y = y * 2
		offset_bits += 1

def NTFSDecompressUnit(Buffer):
	"""Decompress NTFS data from Buffer (a single compression unit) using the LZNT1 algorithm."""

	def is_valid_write_request(offset, length):
		return offset + length <= 2*1024*1024*1024 # Reject obviously invalid write requests.

	if len(Buffer) > NTFS_COMPRESSION_UNIT_SIZE or len(Buffer) < NTFS_CLUSTER_SIZE:
		return b'' # Invalid length of input data.

	global LZNT1_COMPRESSION_BITS

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
					length_bits = 16 - LZNT1_COMPRESSION_BITS[table_idx]
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
		return (b'', 0) # Invalid length of input data.

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

def LZ77DecompressBuffer(Buffer):
	"""Decompress data from Buffer using the plain LZ77 algorithm, return the (decompressed_data, is_bogus_data, bytes_processed) tuple.
	If the 'is_bogus_data' item is set to True in that tuple, the 'decompressed_data' item contains partial data.
	The 'bytes_processed' item contains a number of bytes consumed during the decompression.
	"""

	def is_valid_write_request(offset):
		return offset < 2*1024*1024*1024 # Reject obviously invalid write requests.

	OutputObject = BytesIO()

	BufferedFlags = 0
	BufferedFlagCount = 0
	InputPosition = 0
	OutputPosition = 0
	LastLengthHalfByte = 0

	while True:
		if BufferedFlagCount == 0:
			BufferedFlags = Buffer[InputPosition : InputPosition + 4]

			if len(BufferedFlags) != 4:
				# Bogus data.
				break

			BufferedFlags, = unpack('<L', BufferedFlags)

			InputPosition += 4
			BufferedFlagCount = 32

		BufferedFlagCount -= 1
		if BufferedFlags & (1 << BufferedFlagCount) == 0:
			try:
				OneByte = Buffer[InputPosition]
			except IndexError:
				# Bogus data.
				break

			if type(OneByte) is not int:
				OneByte = ord(OneByte)

			OneByte = bytearray([OneByte])

			if is_valid_write_request(OutputPosition):
				OutputObject.seek(OutputPosition)
				OutputObject.write(OneByte)
			else:
				# Bogus data.
				break

			InputPosition += 1
			OutputPosition += 1
		else:
			if InputPosition == len(Buffer):
				# We are done.
				OutputBuffer = OutputObject.getvalue()
				OutputObject.close()

				return (OutputBuffer, False, InputPosition)

			MatchBytes = Buffer[InputPosition : InputPosition + 2]
			if len(MatchBytes) != 2:
				# Bogus data.
				break

			MatchBytes, = unpack('<H', MatchBytes)

			InputPosition += 2
			MatchLength = MatchBytes % 8
			MatchOffset = (MatchBytes // 8) + 1
			if MatchLength == 7:
				if LastLengthHalfByte == 0:
					try:
						MatchLength = Buffer[InputPosition]
					except IndexError:
						# Bogus data.
						break

					if type(MatchLength) is not int:
						MatchLength = ord(MatchLength)

					MatchLength = MatchLength % 16
					LastLengthHalfByte = InputPosition
					InputPosition += 1
				else:
					try:
						MatchLength = Buffer[LastLengthHalfByte]
					except IndexError:
						# Bogus data.
						break

					if type(MatchLength) is not int:
						MatchLength = ord(MatchLength)

					MatchLength = MatchLength // 16
					LastLengthHalfByte = 0

				if MatchLength == 15:
					try:
						MatchLength = Buffer[InputPosition]
					except IndexError:
						# Bogus data.
						break

					if type(MatchLength) is not int:
						MatchLength = ord(MatchLength)

					InputPosition += 1
					if MatchLength == 255:
						MatchLength = Buffer[InputPosition : InputPosition + 2]
						if len(MatchLength) != 2:
							# Bogus data.
							break

						MatchLength, = unpack('<H', MatchLength)
						InputPosition += 2
						if MatchLength < 15 + 7:
							# Bogus data.
							break

						MatchLength -= (15 + 7)

					MatchLength += 15

				MatchLength += 7

			MatchLength += 3

			bogus_data = False
			for i in range(0, MatchLength):
				if OutputPosition - MatchOffset < 0:
					# Bogus data.
					bogus_data = True
					break

				OutputObject.seek(OutputPosition - MatchOffset)
				OneByte = OutputObject.read(1)

				if len(OneByte) != 1:
					# Bogus data.
					bogus_data = True
					break

				if is_valid_write_request(OutputPosition):
					OutputObject.seek(OutputPosition)
					OutputObject.write(OneByte)
				else:
					# Bogus data.
					bogus_data = True
					break

				OutputPosition += 1

			if bogus_data:
				break

	# We are done (but data is bogus).
	OutputBuffer = OutputObject.getvalue()
	OutputObject.close()

	return (OutputBuffer, True, InputPosition)

def LZ77CheckCompressedSignature(Buffer, Signature):
	"""Check if Buffer (a compressed block of data) contains a given signature (which cannot be compressed using the plain LZ77 algorithm)."""

	if len(Signature) == 0 or len(Signature) > 32:
		return False # Invalid signature.

	if len(Buffer) < 4 + len(Signature):
		return False # Truncated buffer.

	first_bytes = Buffer[ : 4 + len(Signature)]
	if first_bytes.endswith(Signature):
		flags, = unpack('<L', Buffer[ : 4])
		return flags >> (32 - len(Signature)) == 0

	return False

def LZ77HuffmanDecompressBuffer(Buffer, CompatibilityMode = False):
	"""Decompress data from Buffer using the LZ77+Huffman algorithm, return the (decompressed_data, is_bogus_data, bytes_processed) tuple.
	If the 'is_bogus_data' item is set to True in that tuple, the 'decompressed_data' item contains partial data.
	The 'bytes_processed' item contains a number of bytes consumed during the decompression.
	When 'CompatibilityMode' is True, do the RtlDecompressBufferEx()-like decompression.
	"""

	def is_valid_write_request():
		return OutputObject.tell() < 2*1024*1024*1024 # Reject obviously invalid write requests.

	def Read16Bits(Position):
		TwoBytes = Buffer[Position : Position + 2]
		if len(TwoBytes) != 2:
			return

		NextBits, = unpack('<H', TwoBytes)
		return NextBits

	DecodingTable = dict()

	CurrentTableEntry = 0
	for BitLength in range(1, 16):
		for Symbol in range(0, 512):
			try:
				SymbolInBuffer = Buffer[Symbol // 2]
			except IndexError:
				# Bogus Huffman codes.
				return (b'', True, 0)

			if type(SymbolInBuffer) is not int:
				SymbolInBuffer = ord(SymbolInBuffer)

			if (Symbol % 2 == 0 and SymbolInBuffer & 0xF == BitLength) or (Symbol % 2 != 0 and SymbolInBuffer >> 4 == BitLength):
				EntryCount = 1 << (15 - BitLength)
				for i in range(0, EntryCount):
					if CurrentTableEntry >= 2 ** 15:
						# Bogus Huffman codes.
						return (b'', True, 0)

					DecodingTable[CurrentTableEntry] = Symbol
					CurrentTableEntry += 1

	if CurrentTableEntry != 2 ** 15:
		# Bogus Huffman codes.
		return (b'', True, 0)

	OutputObject = BytesIO()

	CurrentPosition = 256
	NextBits = Read16Bits(CurrentPosition)
	if NextBits is None:
		# Bogus data.
		return (b'', True, CurrentPosition)

	CurrentPosition += 2
	NextBits = NextBits << 16

	MoreBits = Read16Bits(CurrentPosition)
	if MoreBits is None:
		# Bogus data.
		return (b'', True, CurrentPosition)

	NextBits = NextBits | MoreBits
	CurrentPosition += 2

	ExtraBits = 16

	while True:
		Next15Bits = NextBits >> (32 - 15)
		try:
			HuffmanSymbol = DecodingTable[Next15Bits]
		except KeyError:
			# Bogus data.
			break

		HuffmanSymbolInBuffer = Buffer[HuffmanSymbol // 2]
		if type(HuffmanSymbolInBuffer) is not int:
			HuffmanSymbolInBuffer = ord(HuffmanSymbolInBuffer)

		if HuffmanSymbol % 2 == 0:
			HuffmanSymbolBitLength = HuffmanSymbolInBuffer & 0xF
		else:
			HuffmanSymbolBitLength = HuffmanSymbolInBuffer >> 4

		NextBits = (NextBits << HuffmanSymbolBitLength) & 0xFFFFFFFF
		ExtraBits -= HuffmanSymbolBitLength
		if ExtraBits < 0:
			MoreBits = Read16Bits(CurrentPosition)
			if MoreBits is None:
				# Bogus data.
				break

			NextBits = (NextBits | (MoreBits << abs(ExtraBits))) & 0xFFFFFFFF
			ExtraBits += 16
			CurrentPosition += 2

		if HuffmanSymbol < 256:
			OneByte = bytearray([HuffmanSymbol])
			if is_valid_write_request():
				OutputObject.write(OneByte)
			else:
				# Bogus data.
				break

		elif HuffmanSymbol == 256 and ((CompatibilityMode and CurrentPosition >= len(Buffer)) or not CompatibilityMode):
			# We are done.
			OutputBuffer = OutputObject.getvalue()
			OutputObject.close()
			return (OutputBuffer, False, CurrentPosition)
		else:
			HuffmanSymbol -= 256
			MatchLength = HuffmanSymbol % 16
			MatchOffsetBitLength = HuffmanSymbol // 16

			if MatchLength == 15:
				try:
					MatchLength = Buffer[CurrentPosition]
				except IndexError:
					# Bogus data.
					break

				if type(MatchLength) is not int:
					MatchLength = ord(MatchLength)

				CurrentPosition += 1

				if MatchLength == 255:
					MatchLength = Read16Bits(CurrentPosition)
					if MatchLength is None:
						# Bogus data.
						break

					CurrentPosition += 2

					if MatchLength < 15:
						# Bogus data.
						break

					MatchLength -= 15

				MatchLength += 15

			MatchLength += 3

			MatchOffset = NextBits >> (32 - MatchOffsetBitLength)
			MatchOffset += (1 << MatchOffsetBitLength)
			NextBits = (NextBits << MatchOffsetBitLength) & 0xFFFFFFFF
			ExtraBits -= MatchOffsetBitLength

			if ExtraBits < 0:
				MoreBits = Read16Bits(CurrentPosition)
				if MoreBits is None:
					# Bogus data.
					break

				NextBits = (NextBits | (MoreBits << abs(ExtraBits))) & 0xFFFFFFFF
				ExtraBits += 16
				CurrentPosition += 2

			CurrentOutputPosition = OutputObject.tell()

			bogus_data = False
			for i in range(0, MatchLength):
				if CurrentOutputPosition - MatchOffset + i < 0:
					# Bogus data.
					bogus_data = True
					break

				OutputObject.seek(CurrentOutputPosition - MatchOffset + i)
				OneByte = OutputObject.read(1)
				if len(OneByte) != 1:
					# Bogus data.
					bogus_data = True
					break

				OutputObject.seek(CurrentOutputPosition + i)

				if is_valid_write_request():
					OutputObject.write(OneByte)
				else:
					# Bogus data.
					bogus_data = True
					break

			if bogus_data:
				break

	# We are done (but data is bogus).
	OutputBuffer = OutputObject.getvalue()
	OutputObject.close()

	return (OutputBuffer, True, CurrentPosition)


# All functions related to the decompression of data are written to support both Python 2.7 and Python 3.
# Thus, these functions are very slow (Python is slow, but code written for both versions of the language is slower).
# To speed the things up, we optionally use a faster implementation written in Cython (the CyXpress module).
try:
	import CyXpress
except ImportError:
	pass
else:
	def NTFSDecompressUnit(Buffer):
		"""Decompress NTFS data from Buffer (a single compression unit) using the LZNT1 algorithm."""

		if len(Buffer) > NTFS_COMPRESSION_UNIT_SIZE or len(Buffer) < NTFS_CLUSTER_SIZE:
			return b'' # Invalid length of input data.

		return CyXpress.LZNT1DecompressBuffer(Buffer)

	LZ77DecompressBuffer = CyXpress.LZ77DecompressBuffer
	LZ77HuffmanDecompressBuffer = CyXpress.LZ77HuffmanDecompressBuffer

	__cython_armed__ = True
