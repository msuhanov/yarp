# cython: language_level=3, boundscheck=True, wraparound=False, nonecheck=False

# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module contains alternative (faster) versions of decompression functions (implemented in Cython).
#
# Currently, the module implements the following functions (each one is considered a variant of the Xpress algorithm):
#  - LZNT1: LZNT1DecompressBuffer();
#  - plain LZ77: LZ77DecompressBuffer();
#  - LZ77+Huffman: LZ77HuffmanDecompressBuffer().

cdef unsigned long OUTPUT_SIZE_MAX = 2*1024*1024*1024 # Do not handle decompressed data larger than this value (in bytes).

cdef list LZNT1_COMPRESSION_BITS = []

def LZNT1DecompressBuffer(bytes Buffer):
	"""Decompress data from Buffer using the LZNT1 algorithm."""

	global LZNT1_COMPRESSION_BITS

	cdef unsigned int offset_bits = 0
	cdef unsigned int y = 16
	cdef unsigned int x

	if len(LZNT1_COMPRESSION_BITS) == 0:
		LZNT1_COMPRESSION_BITS = [ 0 ] * 4096

		for x in range(0, 4096):
			LZNT1_COMPRESSION_BITS[x] = 4 + offset_bits
			if x == y:
				y = y * 2
				offset_bits += 1

	cdef unsigned long src_index = 0
	cdef unsigned long dst_index = 0

	cdef bytearray dbuf = bytearray()

	cdef unsigned int header, block_size
	cdef bytes bytes_
	cdef unsigned char byte
	cdef unsigned long dst_chunk_start, src_chunk_end
	cdef bint bogus_data
	cdef unsigned int flags, flag, token, table_idx, length_bits, length_mask
	cdef unsigned int ctuple, back_off_rel, back_off, back_len
	cdef unsigned int i

	while src_index < len(Buffer):
		try:
			header = Buffer[src_index] | (Buffer[src_index + 1] << 8)
		except IndexError:
			break # Truncated header.

		src_index += 2

		if header == 0:
			break # End of the buffer.

		if header & 0x7000 != 0x3000:
			break # Invalid signature.

		if header & 0x8000 == 0:
			# Not a compressed block, copy literal data.
			block_size = (header & 0x0FFF) + 1

			if not dst_index + block_size <= OUTPUT_SIZE_MAX: # Reject obviously invalid write requests.
				break # Bogus data.

			bytes_ = Buffer[src_index : src_index + block_size]
			dbuf.extend(bytes_)

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
					if not dst_index + 1 <= OUTPUT_SIZE_MAX: # Reject obviously invalid write requests.
						# Bogus data.
						bogus_data = True
						break

					try:
						byte = Buffer[src_index]
					except IndexError:
						# Truncated chunk.
						bogus_data = True
						break

					dbuf.append(byte)

					dst_index += 1
					src_index += 1
					continue

				# A compression tuple.
				table_idx = dst_index - dst_chunk_start
				try:
					length_bits = 16 - LZNT1_COMPRESSION_BITS[table_idx]
				except IndexError:
					# Bogus data.
					bogus_data = True
					break

				length_mask = (1 << length_bits) - 1

				try:
					ctuple = Buffer[src_index] | (Buffer[src_index + 1] << 8)
				except IndexError:
					# Truncated chunk.
					bogus_data = True
					break

				src_index += 2

				back_off_rel = (ctuple >> length_bits) + 1
				back_off = dst_index - back_off_rel
				back_len = (ctuple & length_mask) + 3

				if back_off < dst_chunk_start:
					# Bogus compression tuple.
					bogus_data = True
					break

				for i in range(0, back_len):
					# Decompress data.
					try:
						byte = dbuf[back_off]
					except IndexError:
						# Invalid offset.
						bogus_data = True
						break

					if not dst_index + 1 <= OUTPUT_SIZE_MAX: # Reject obviously invalid write requests.
						# Bogus data.
						bogus_data = True
						break

					dbuf.append(byte)

					dst_index += 1
					back_off += 1

				if bogus_data:
					break

		if bogus_data:
			break

	return dbuf

def LZ77DecompressBuffer(bytes Buffer):
	"""Decompress data from Buffer using the plain LZ77 algorithm, return the (decompressed_data, is_bogus_data, bytes_processed) tuple.
	If the 'is_bogus_data' item is set to True in that tuple, the 'decompressed_data' item contains partial data.
	The 'bytes_processed' item contains a number of bytes consumed during the decompression.
	"""

	cdef bytearray OutputBuffer = bytearray()

	cdef unsigned int BufferedFlags = 0
	cdef unsigned int BufferedFlagCount = 0
	cdef unsigned long InputPosition = 0
	cdef unsigned long OutputPosition = 0
	cdef unsigned int LastLengthHalfByte = 0

	cdef unsigned int i, MatchBytes, MatchLength, MatchOffset
	cdef bint bogus_data

	cdef unsigned char OneByte

	while True:
		if BufferedFlagCount == 0:
			try:
				BufferedFlags = Buffer[InputPosition] | (Buffer[InputPosition + 1] << 8) | (Buffer[InputPosition + 2] << 16) | (Buffer[InputPosition + 3] << 24)
			except IndexError:
				# Bogus data.
				break

			InputPosition += 4
			BufferedFlagCount = 32

		BufferedFlagCount -= 1
		if BufferedFlags & (1 << BufferedFlagCount) == 0:
			try:
				OneByte = Buffer[InputPosition]
			except IndexError:
				# Bogus data.
				break

			if OutputPosition < OUTPUT_SIZE_MAX: # Reject obviously invalid write requests.
				OutputBuffer.append(OneByte)
			else:
				# Bogus data.
				break

			InputPosition += 1
			OutputPosition += 1
		else:
			if InputPosition == len(Buffer):
				# We are done.
				return (OutputBuffer, False, InputPosition)

			try:
				MatchBytes = Buffer[InputPosition] | (Buffer[InputPosition + 1] << 8)
			except IndexError:
				# Bogus data.
				break

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

					MatchLength = MatchLength % 16
					LastLengthHalfByte = InputPosition
					InputPosition += 1
				else:
					try:
						MatchLength = Buffer[LastLengthHalfByte]
					except IndexError:
						# Bogus data.
						break

					MatchLength = MatchLength // 16
					LastLengthHalfByte = 0

				if MatchLength == 15:
					try:
						MatchLength = Buffer[InputPosition]
					except IndexError:
						# Bogus data.
						break

					InputPosition += 1
					if MatchLength == 255:
						try:
							MatchLength = Buffer[InputPosition] | (Buffer[InputPosition + 1] << 8)
						except IndexError:
							# Bogus data.
							break

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
				if OutputPosition < MatchOffset:
					# Bogus data.
					bogus_data = True
					break

				try:
					OneByte = OutputBuffer[OutputPosition - MatchOffset]
				except IndexError:
					# Bogus data.
					bogus_data = True
					break

				if OutputPosition < OUTPUT_SIZE_MAX: # Reject obviously invalid write requests.
					OutputBuffer.append(OneByte)
				else:
					# Bogus data.
					bogus_data = True
					break

				OutputPosition += 1

			if bogus_data:
				break

	# We are done (but data is bogus).
	return (OutputBuffer, True, InputPosition)

def LZ77HuffmanDecompressBuffer(bytes Buffer, bint CompatibilityMode = False):
	"""Decompress data from Buffer using the LZ77+Huffman algorithm, return the (decompressed_data, is_bogus_data, bytes_processed) tuple.
	If the 'is_bogus_data' item is set to True in that tuple, the 'decompressed_data' item contains partial data.
	The 'bytes_processed' item contains a number of bytes consumed during the decompression.
	When 'CompatibilityMode' is True, do the RtlDecompressBufferEx()-like decompression.
	"""

	cdef bytearray OutputBuffer = bytearray()

	cdef dict DecodingTable = dict()
	cdef unsigned int CurrentTableEntry = 0
	cdef unsigned int i, BitLength, Symbol, SymbolInBuffer, EntryCount

	for BitLength in range(1, 16):
		for Symbol in range(0, 512):
			try:
				SymbolInBuffer = Buffer[Symbol // 2]
			except IndexError:
				# Bogus Huffman codes.
				return (b'', True, 0)

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

	cdef unsigned long CurrentPosition = 256
	cdef unsigned long NextBits

	try:
		NextBits = Buffer[CurrentPosition] | (Buffer[CurrentPosition + 1] << 8)
	except IndexError:
		# Bogus data.
		return (b'', True, CurrentPosition)

	CurrentPosition += 2
	NextBits = NextBits << 16

	cdef unsigned long MoreBits

	try:
		MoreBits = Buffer[CurrentPosition] | (Buffer[CurrentPosition + 1] << 8)
	except IndexError:
		# Bogus data.
		return (b'', True, CurrentPosition)

	NextBits = NextBits | MoreBits
	CurrentPosition += 2

	cdef int ExtraBits = 16

	cdef unsigned long Next15Bits
	cdef unsigned int HuffmanSymbol, HuffmanSymbolInBuffer, HuffmanSymbolBitLength, MatchLength, MatchOffsetBitLength, MatchOffset
	cdef bint bogus_data

	cdef unsigned char OneByte
	cdef unsigned int CurrentOutputPosition

	while True:
		Next15Bits = NextBits >> (32 - 15)
		try:
			HuffmanSymbol = DecodingTable[Next15Bits]
		except KeyError:
			# Bogus data.
			break

		HuffmanSymbolInBuffer = Buffer[HuffmanSymbol // 2]

		if HuffmanSymbol % 2 == 0:
			HuffmanSymbolBitLength = HuffmanSymbolInBuffer & 0xF
		else:
			HuffmanSymbolBitLength = HuffmanSymbolInBuffer >> 4

		NextBits = (NextBits << HuffmanSymbolBitLength) & 0xFFFFFFFF
		ExtraBits -= HuffmanSymbolBitLength
		if ExtraBits < 0:
			try:
				MoreBits = Buffer[CurrentPosition] | (Buffer[CurrentPosition + 1] << 8)
			except IndexError:
				# Bogus data.
				break

			NextBits = (NextBits | (MoreBits << abs(ExtraBits))) & 0xFFFFFFFF
			ExtraBits += 16
			CurrentPosition += 2

		if HuffmanSymbol < 256:
			OneByte = HuffmanSymbol
			if len(OutputBuffer) < OUTPUT_SIZE_MAX: # Reject obviously invalid write requests.
				OutputBuffer.append(OneByte)
			else:
				# Bogus data.
				break

		elif HuffmanSymbol == 256 and ((CompatibilityMode and CurrentPosition >= len(Buffer)) or not CompatibilityMode):
			# We are done.
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

				CurrentPosition += 1

				if MatchLength == 255:
					try:
						MatchLength = Buffer[CurrentPosition] | (Buffer[CurrentPosition + 1] << 8)
					except IndexError:
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
				try:
					MoreBits = Buffer[CurrentPosition] | (Buffer[CurrentPosition + 1] << 8)
				except IndexError:
					# Bogus data.
					break

				NextBits = (NextBits | (MoreBits << abs(ExtraBits))) & 0xFFFFFFFF
				ExtraBits += 16
				CurrentPosition += 2

			CurrentOutputPosition = len(OutputBuffer)

			bogus_data = False
			for i in range(0, MatchLength):
				if CurrentOutputPosition + i < MatchOffset:
					# Bogus data.
					bogus_data = True
					break

				try:
					OneByte = OutputBuffer[CurrentOutputPosition - MatchOffset + i]
				except IndexError:
					# Bogus data.
					bogus_data = True
					break

				if CurrentOutputPosition + i < OUTPUT_SIZE_MAX: # Reject obviously invalid write requests.
					OutputBuffer.append(OneByte)
				else:
					# Bogus data.
					bogus_data = True
					break

			if bogus_data:
				break

	# We are done (but data is bogus).
	return (OutputBuffer, True, CurrentPosition)
