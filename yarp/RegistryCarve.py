# yarp: yet another registry parser
# (c) Maxim Suhanov

from __future__ import unicode_literals

from . import RegistryFile
from .Registry import DecodeUnicode
from struct import unpack
from collections import namedtuple

CarveResult = namedtuple('CarveResult', [ 'offset', 'size', 'truncated', 'truncation_point', 'truncation_scenario', 'filename' ])
BaseBlockCheckResult = namedtuple('BaseBlockCheckResult', [ 'is_valid', 'hbins_data_size', 'filename', 'old_cells' ])
HiveBinCheckResult = namedtuple('HiveBinCheckResult', [ 'is_valid', 'size' ])
CellsCheckResult = namedtuple('CellsCheckResult', [ 'are_valid', 'truncation_point_relative' ])

SECTOR_SIZE = 512 # This is an assumed sector size.
FILE_MARGIN_SIZE = 4*1024*1024 # We will read more bytes than specified in the base block to account possible damage scenarios.
FILE_SIZE_MAX_MIB = 500 # We do not expect primary files to be larger than this (in MiB).

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

def CheckHiveBin(Buffer, ExpectedOffsetRelative):
	"""Check if Buffer contains a valid hive bin (without checking its cells), return a named tuple (HiveBinCheckResult)."""

	if len(Buffer) < RegistryFile.HIVE_BIN_SIZE_ALIGNMENT:
		return HiveBinCheckResult(is_valid = False, size = None)

	signature, offset, size = unpack('<4sLL', Buffer[ : 12])
	if signature == b'hbin' and offset == ExpectedOffsetRelative and size >= RegistryFile.HIVE_BIN_SIZE_ALIGNMENT and size % RegistryFile.HIVE_BIN_SIZE_ALIGNMENT == 0:
		return HiveBinCheckResult(is_valid = True, size = size)

	return HiveBinCheckResult(is_valid = False, size = None)

def CheckCellsOfHiveBin(Buffer, OldCells = False):
	"""Check if Buffer contains a hive bin with valid cells, return a named tuple (CellsCheckResult). A hive bin's header is not checked."""

	curr_pos_relative = 32
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

		if cell_size_abs < cell_size_alignment or cell_size_abs % cell_size_alignment != 0:
			return CellsCheckResult(are_valid = False, truncation_point_relative = curr_pos_relative)

		curr_pos_relative += cell_size_abs

	return CellsCheckResult(are_valid = True, truncation_point_relative = None)

class DiskImage(object):
	"""This class is used to read from a disk image (or a similar source)."""

	def __init__(self, file_object):
		self.file_object = file_object

	def size(self):
		self.file_object.seek(0, 2)
		return self.file_object.tell()

	def read(self, pos, size):
		self.file_object.seek(pos)
		return self.file_object.read(size)

class Carver(DiskImage):
	"""This class is used to carve registry files (primary) from a disk image."""

	def __init__(self, file_object):
		super(Carver, self).__init__(file_object)

	def carve(self):
		"""This method yields named tuples (CarveResult)."""

		pos = 0
		file_size = self.size()
		while pos < file_size:
			buf_size = RegistryFile.BASE_BLOCK_LENGTH_PRIMARY + RegistryFile.HIVE_BIN_SIZE_ALIGNMENT
			buf = self.read(pos, buf_size)

			if len(buf) < buf_size: # End of a file or a read error.
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

			pos += SECTOR_SIZE
