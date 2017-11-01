# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module implements an interface to carve registry hives from a disk image.

from __future__ import unicode_literals

from . import RegistryFile, RegistryHelpers
from .Registry import DecodeUnicode
from io import BytesIO
from struct import unpack
from collections import namedtuple

CarveResult = namedtuple('CarveResult', [ 'offset', 'size', 'truncated', 'truncation_point', 'truncation_scenario', 'filename' ])
CarveResultFragment = namedtuple('CarveResultFragment', [ 'offset', 'size', 'hbin_start' ])

CarveResultCompressed = namedtuple('CarveResultCompressed', [ 'offset', 'buffer_decompressed', 'filename' ])
CarveResultFragmentCompressed = namedtuple('CarveResultFragmentCompressed', [ 'offset', 'buffer_decompressed', 'hbin_start' ])

BaseBlockCheckResult = namedtuple('BaseBlockCheckResult', [ 'is_valid', 'hbins_data_size', 'filename', 'old_cells' ])
HiveBinCheckResult = namedtuple('HiveBinCheckResult', [ 'is_valid', 'size', 'offset_relative' ])
CellsCheckResult = namedtuple('CellsCheckResult', [ 'are_valid', 'truncation_point_relative' ])

SECTOR_SIZE = 512 # This is an assumed sector size.
FILE_MARGIN_SIZE = 4*1024*1024 # We will read more bytes than specified in the base block to account possible damage scenarios.
FILE_SIZE_MAX_MIB = 500 # We do not expect primary files to be larger than this (in MiB).
CELL_SIZE_MAX = 2*1024*1024 # We do not expect cells to be larger than this.
HBIN_SIZE_MAX = 64*1024*1024 # We do not expect hive bins to be larger than this.

def CheckBaseBlockOfPrimaryFile(Buffer):
	"""Check if Buffer contains a valid base block of a primary file and a hive bin, return a named tuple (BaseBlockCheckResult)."""

	if len(Buffer) < RegistryFile.BASE_BLOCK_LENGTH_PRIMARY + RegistryFile.HIVE_BIN_SIZE_ALIGNMENT:
		return BaseBlockCheckResult(is_valid = False, hbins_data_size = None, filename = None, old_cells = None)

	signature, __, __, __, major_version, minor_version, file_type, file_format, __, hbins_data_size, clustering_factor = unpack('<4sLLQLLLLLLL', Buffer[ : 48])

	if (signature == b'regf' and major_version in RegistryFile.MAJOR_VERSION_NUMBERS_SUPPORTED and minor_version in RegistryFile.MINOR_VERSION_NUMBERS_SUPPORTED and
		file_type == RegistryFile.FILE_TYPE_PRIMARY and file_format == RegistryFile.FILE_FORMAT_DIRECT_MEMORY_LOAD and clustering_factor == RegistryFile.FILE_CLUSTERING_FACTOR and
		hbins_data_size >= RegistryFile.HIVE_BIN_SIZE_ALIGNMENT and hbins_data_size % RegistryFile.HIVE_BIN_SIZE_ALIGNMENT == 0 and
		RegistryFile.BASE_BLOCK_LENGTH_PRIMARY + hbins_data_size <= FILE_SIZE_MAX_MIB * 1024 * 1024):

		log_signature = Buffer[RegistryFile.BASE_BLOCK_LENGTH_LOG : RegistryFile.BASE_BLOCK_LENGTH_LOG + 4]
		hbin_signature = Buffer[RegistryFile.BASE_BLOCK_LENGTH_PRIMARY : RegistryFile.BASE_BLOCK_LENGTH_PRIMARY + 4]
		if log_signature != b'DIRT' and log_signature != b'HvLE' and hbin_signature == b'hbin':
			try:
				filename = DecodeUnicode(Buffer[48 : 48 + 64], True).rstrip('\x00')
			except UnicodeDecodeError:
				pass
			else:
				old_cells = minor_version in RegistryFile.MINOR_VERSION_NUMBERS_FOR_OLD_CELL_FORMAT
				return BaseBlockCheckResult(is_valid = True, hbins_data_size = hbins_data_size, filename = filename, old_cells = old_cells)

	return BaseBlockCheckResult(is_valid = False, hbins_data_size = None, filename = None, old_cells = None)

def CheckHiveBin(Buffer, ExpectedOffsetRelative, AllowSmallSize = False):
	"""Check if Buffer contains a valid hive bin (without checking its cells), return a named tuple (HiveBinCheckResult)."""

	if not AllowSmallSize:
		min_size = RegistryFile.HIVE_BIN_SIZE_ALIGNMENT
	else:
		min_size = SECTOR_SIZE

	if len(Buffer) < min_size:
		return HiveBinCheckResult(is_valid = False, size = None, offset_relative = None)

	signature, offset, size = unpack('<4sLL', Buffer[ : 12])
	if (signature == b'hbin' and (offset == ExpectedOffsetRelative or ExpectedOffsetRelative is None) and size >= RegistryFile.HIVE_BIN_SIZE_ALIGNMENT and
		size % RegistryFile.HIVE_BIN_SIZE_ALIGNMENT == 0 and size <= HBIN_SIZE_MAX and RegistryFile.BASE_BLOCK_LENGTH_PRIMARY + offset < FILE_SIZE_MAX_MIB * 1024 * 1024 and
		(offset == 0 or offset % RegistryFile.HIVE_BIN_SIZE_ALIGNMENT == 0)):

		return HiveBinCheckResult(is_valid = True, size = size, offset_relative = offset)

	return HiveBinCheckResult(is_valid = False, size = None, offset_relative = None)

def CheckCellsOfHiveBin(Buffer, OldCells = False):
	"""Check if Buffer contains a hive bin with valid cells, return a named tuple (CellsCheckResult). A hive bin's header is not checked."""

	curr_pos_relative = 32
	prev_pos_relative = None
	while curr_pos_relative < len(Buffer):
		four_bytes = Buffer[curr_pos_relative : curr_pos_relative + 4]
		if len(four_bytes) < 4:
			return CellsCheckResult(are_valid = False, truncation_point_relative = curr_pos_relative)

		cell_size, = unpack('<l', four_bytes)
		cell_size_abs = abs(cell_size)

		if OldCells:
			cell_size_alignment = 16
		else:
			cell_size_alignment = 8

		if cell_size_abs < cell_size_alignment or cell_size_abs % cell_size_alignment != 0 or curr_pos_relative + cell_size_abs > len(Buffer) or cell_size_abs > CELL_SIZE_MAX:
			if prev_pos_relative is None:
				return CellsCheckResult(are_valid = False, truncation_point_relative = curr_pos_relative)

			# Try to locate the exact truncation point by looking for some common signatures.
			prev_cells = Buffer[32 : prev_pos_relative + prev_cell_size_abs]
			hbin_signature_pos = prev_cells.rfind(b'hbin')
			regf_signature_pos = prev_cells.rfind(b'regf')
			if hbin_signature_pos == -1 and regf_signature_pos != -1:
				signature_pos = regf_signature_pos
			elif hbin_signature_pos != -1 and regf_signature_pos == -1:
				signature_pos = hbin_signature_pos
			elif hbin_signature_pos != -1 and regf_signature_pos != -1:
				if regf_signature_pos > hbin_signature_pos:
					signature_pos = hbin_signature_pos
				else:
					signature_pos = regf_signature_pos
			else:
				signature_pos = None

			if signature_pos is not None:
				return CellsCheckResult(are_valid = False, truncation_point_relative = 32 + signature_pos)

			return CellsCheckResult(are_valid = False, truncation_point_relative = curr_pos_relative)

		prev_cell_size_abs = cell_size_abs
		prev_pos_relative = curr_pos_relative
		curr_pos_relative += cell_size_abs

	return CellsCheckResult(are_valid = True, truncation_point_relative = None)

def ValidateRandomFragment(Buffer, AllowNullBytesOnly):
	"""Check if Buffer contains a plausible registry fragment. This function is used to identify NTFS decompression errors, so only simple checks are performed."""

	offset = 0
	while offset < len(Buffer):
		signature = Buffer[offset : offset + 4]
		if signature == b'hbin':
			return True

		offset += RegistryFile.HIVE_BIN_SIZE_ALIGNMENT

	null_bytes_only = True
	for c in Buffer:
		if c != 0 and c != b'\x00':
			null_bytes_only = False

	if null_bytes_only and AllowNullBytesOnly:
		return True

	return False

class DiskImage(object):
	"""This class is used to read from a disk image (or a similar source that is aligned to 512 bytes)."""

	def __init__(self, file_object):
		self.file_object = file_object

	def size(self):
		self.file_object.seek(0, 2)
		return self.file_object.tell()

	def read(self, pos, size):
		self.file_object.seek(pos)
		return self.file_object.read(size)

class Carver(DiskImage):
	"""This class is used to carve registry files (primary) and registry fragments from a disk image."""

	def __init__(self, file_object):
		super(Carver, self).__init__(file_object)

	def carve(self, recover_fragments = False, ntfs_decompression = False):
		"""This method yields named tuples (CarveResult and, if 'recover_fragments' is True, CarveResultFragment).
		When 'ntfs_decompression' is True, data from compression units (NTFS) will be also recovered, this will yield
		CarveResultCompressed and, if 'recover_fragments' is also True, CarveResultFragmentCompressed named tuples.
		Note:
		Only the first bytes of each sector will be scanned for signatures, because registry files (primary) are always larger than
		an NTFS file record (a primary file is at least 8192 bytes in length, while a file record is 1024 or 4096 bytes in length),
		so the carver can skip data stored inside a file record (not starting at a sector boundary).
		"""

		compressed_regf_fragments = []

		pos = 0
		file_size = self.size()
		while pos < file_size:
			buf_size = RegistryFile.BASE_BLOCK_LENGTH_PRIMARY + RegistryFile.HIVE_BIN_SIZE_ALIGNMENT
			buf = self.read(pos, buf_size)

			if len(buf) < SECTOR_SIZE or len(buf) % SECTOR_SIZE != 0: # End of a file or a read error.
				break

			four_bytes = buf[ : 4]
			if four_bytes == b'regf':
				check_result = CheckBaseBlockOfPrimaryFile(buf)
				if check_result.is_valid:
					regf_offset = pos
					regf_size = RegistryFile.BASE_BLOCK_LENGTH_PRIMARY + check_result.hbins_data_size
					regf_buf = self.read(regf_offset, regf_size + FILE_MARGIN_SIZE)

					curr_pos_relative = RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
					expected_hbin_offset_relative = 0

					truncation_point = None
					last_hbin_buf = None

					while curr_pos_relative != regf_size:
						if curr_pos_relative > regf_size:
							regf_size = curr_pos_relative # Adjust the file size to include an unforeseeably large hive bin.
							break

						hbin_buf_partial = regf_buf[curr_pos_relative : curr_pos_relative + RegistryFile.HIVE_BIN_SIZE_ALIGNMENT]
						check_result_hbin = CheckHiveBin(hbin_buf_partial, expected_hbin_offset_relative)
						if not check_result_hbin.is_valid:
							truncation_point = regf_offset + curr_pos_relative
							regf_size = curr_pos_relative # Adjust the file size according to the truncation point.
							break

						last_hbin_buf = regf_buf[curr_pos_relative : curr_pos_relative + check_result_hbin.size]
						if len(last_hbin_buf) < check_result_hbin.size:
							padding_length = check_result_hbin.size - len(last_hbin_buf)
							last_hbin_buf += b'\x00' * padding_length

						curr_pos_relative += check_result_hbin.size
						expected_hbin_offset_relative += check_result_hbin.size

					if last_hbin_buf is None:
						# No valid hive bins found.
						pos += SECTOR_SIZE
						continue

					if truncation_point is None:
						# Probably no truncation.
						check_result_cells = CheckCellsOfHiveBin(last_hbin_buf, check_result.old_cells)
						if check_result_cells.are_valid:
							# No truncation.
							yield CarveResult(offset = regf_offset, size = regf_size, truncated = False, truncation_point = None, truncation_scenario = 0,
								filename = check_result.filename)
						else:
							# Truncation within the last hive bin.
							truncation_point = regf_offset + regf_size - len(last_hbin_buf) + check_result_cells.truncation_point_relative
							truncation_point = truncation_point // SECTOR_SIZE * SECTOR_SIZE # Adjust the truncation point according to the sector size.
							regf_size = truncation_point - regf_offset # Adjust the file size according to the truncation point.

							yield CarveResult(offset = regf_offset, size = regf_size, truncated = True, truncation_point = truncation_point, truncation_scenario = 2,
								filename = check_result.filename)
					else:
						# Obvious truncation.
						check_result_cells = CheckCellsOfHiveBin(last_hbin_buf, check_result.old_cells)
						if check_result_cells.are_valid:
							# Truncation at a boundary of a hive bin.
							yield CarveResult(offset = regf_offset, size = regf_size, truncated = True, truncation_point = truncation_point, truncation_scenario = 1,
								filename = check_result.filename)
						else:
							# Truncation within a hive bin.
							truncation_point = regf_offset + regf_size - len(last_hbin_buf) + check_result_cells.truncation_point_relative
							truncation_point = truncation_point // SECTOR_SIZE * SECTOR_SIZE # Adjust the truncation point according to the sector size.
							regf_size = truncation_point - regf_offset # Adjust the file size according to the truncation point.

							yield CarveResult(offset = regf_offset, size = regf_size, truncated = True, truncation_point = truncation_point, truncation_scenario = 3,
								filename = check_result.filename)

					if regf_size % SECTOR_SIZE == 0:
						pos += regf_size
					else:
						pos += regf_size + SECTOR_SIZE - regf_size % SECTOR_SIZE

					continue

			elif four_bytes == b'hbin' and recover_fragments:
				check_result_hbin = CheckHiveBin(buf, None, True)
				if check_result_hbin.is_valid:
					fragment_offset = pos
					fragment_hbin_start = check_result_hbin.offset_relative

					expected_hbin_offset_relative = check_result_hbin.offset_relative

					fragment_size = 0 # This value will be adjusted in the loop below.
					curr_pos_relative = 0 # We will scan the first hive bin in a current fragment again.
					while True:
						hbin_buf_partial = self.read(pos + curr_pos_relative, RegistryFile.HIVE_BIN_SIZE_ALIGNMENT)

						check_result_hbin = CheckHiveBin(hbin_buf_partial, expected_hbin_offset_relative, True)
						if not check_result_hbin.is_valid:
							break

						hbin_buf = self.read(pos + curr_pos_relative, check_result_hbin.size)
						if len(hbin_buf) < check_result_hbin.size:
							padding_length = check_result_hbin.size - len(hbin_buf)
							hbin_buf += b'\x00' * padding_length

						check_result_cells = CheckCellsOfHiveBin(hbin_buf) # We assume the new cell format here.
						if check_result_cells.are_valid:
							curr_pos_relative += check_result_hbin.size
							fragment_size += check_result_hbin.size
							expected_hbin_offset_relative += check_result_hbin.size
							continue

						fragment_size += check_result_cells.truncation_point_relative
						break

					if fragment_size == 0:
						# A read error when checking the first hive bin in a current fragment for the second time.
						break

					# Adjust the fragment size according to the sector size.
					fragment_size = fragment_size // SECTOR_SIZE * SECTOR_SIZE
					if fragment_size == 0:
						fragment_size = SECTOR_SIZE # Something is wrong with the hive bin in a fragment (like a format violation).

					yield CarveResultFragment(offset = fragment_offset, size = fragment_size, hbin_start = fragment_hbin_start)

					pos += fragment_size
					continue

			elif ntfs_decompression:
				# A compression unit may contain data belonging to another file in the slack space. Even a new compression unit may be in the slack space.
				# Here, the slack space is an area from the end of compressed clusters to the end of a corresponding compression unit.
				# Thus, we cannot skip over a processed compression unit without scanning the slack space.
				# Sometimes there is no slack space after compressed clusters on a disk (and a new compression unit starts immediately).
				# We also track offsets of compressed units belonging to primary files, so we will not report their hive bins as fragments later.

				seven_bytes = buf[ : 7]
				if RegistryHelpers.NTFSCheckCompressedSignature(seven_bytes, b'regf'):
					regf_fragments = { False: [], True: [] }
					result_1 = None
					result_2 = None

					for no_slack in [ False, True ]:
						buf_compressed = self.read(pos, RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE)
						if no_slack:
							buf_decompressed, effective_unit_size = RegistryHelpers.NTFSDecompressUnitWithNoSlack(buf_compressed)
						else:
							buf_decompressed = RegistryHelpers.NTFSDecompressUnit(buf_compressed)
							effective_unit_size = RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE

						if len(buf_decompressed) == RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE:
							check_result = CheckBaseBlockOfPrimaryFile(buf_decompressed)
							if check_result.is_valid:
								regf_offset = pos
								regf_buf_obj = BytesIO()
								regf_buf_obj.write(buf_decompressed)

								curr_pos_relative = effective_unit_size
								while regf_buf_obj.tell() < RegistryFile.BASE_BLOCK_LENGTH_PRIMARY + check_result.hbins_data_size:
									buf_raw = self.read(pos + curr_pos_relative, RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE)
									if len(buf_raw) != RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE:
										break # Truncated compression unit.

									regf_fragments[no_slack].append(pos + curr_pos_relative)

									if no_slack:
										buf_decompressed, effective_unit_size = RegistryHelpers.NTFSDecompressUnitWithNoSlack(buf_raw)
									else:
										buf_decompressed = RegistryHelpers.NTFSDecompressUnit(buf_raw)
										effective_unit_size = RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE

									if len(buf_decompressed) == RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE:
										regf_buf_obj.write(buf_decompressed)
									else:
										if len(buf_decompressed) > 0 and ValidateRandomFragment(buf_decompressed, True):
											regf_buf_obj.write(buf_decompressed)
											break # We are at the end of a compressed file (or we got bogus data in the compression unit).
										elif ValidateRandomFragment(buf_raw, False):
											regf_buf_obj.write(buf_raw) # Literal (not compressed) data run.
										else:
											break # Bogus data.

									curr_pos_relative += effective_unit_size

								regf_buf = regf_buf_obj.getvalue()
								regf_buf_obj.close()

								if no_slack:
									result_1 = CarveResultCompressed(offset = regf_offset, buffer_decompressed = regf_buf, filename = check_result.filename)
								else:
									result_2 = CarveResultCompressed(offset = regf_offset, buffer_decompressed = regf_buf, filename = check_result.filename)

					if result_1 is not None and result_2 is None:
						yield result_1
					elif result_2 is not None and result_1 is None:
						yield result_2
					elif result_1 is not None and result_2 is not None:
						if len(result_1.buffer_decompressed) > len(result_2.buffer_decompressed):
							compressed_regf_fragments.extend(regf_fragments[True])
							yield result_1
						else:
							compressed_regf_fragments.extend(regf_fragments[False])
							yield result_2

				elif recover_fragments and RegistryHelpers.NTFSCheckCompressedSignature(seven_bytes, b'hbin'):
					if pos not in compressed_regf_fragments:
						buf_compressed = self.read(pos, RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE)
						buf_decompressed = RegistryHelpers.NTFSDecompressUnit(buf_compressed)

						if (len(buf_decompressed) >= RegistryFile.HIVE_BIN_SIZE_ALIGNMENT and len(buf_decompressed) % RegistryFile.HIVE_BIN_SIZE_ALIGNMENT == 0 and
							len(buf_decompressed) <= RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE):

							check_result_hbin = CheckHiveBin(buf_decompressed, None)
							if check_result_hbin.is_valid:
								fragment_offset = pos

								yield CarveResultFragmentCompressed(offset = fragment_offset, buffer_decompressed = buf_decompressed,
									hbin_start = check_result_hbin.offset_relative)

			pos += SECTOR_SIZE
