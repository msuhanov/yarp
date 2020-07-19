# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module implements an interface to carve registry hives (and fragments) from a disk image (or a memory image).

from __future__ import unicode_literals

from . import Registry, RegistryFile, RegistryRecords, RegistryHelpers
from .Registry import DecodeUnicode
from .RegistryRecover import MAX_PLAUSIBLE_SUBKEYS_COUNT, MAX_PLAUSIBLE_VALUES_COUNT
from io import BytesIO
import pickle
from struct import unpack
from collections import namedtuple
from ctypes import c_uint32
import mmap

CarveResult = namedtuple('CarveResult', [ 'offset', 'size', 'hbins_data_size', 'truncated', 'truncation_point', 'truncation_scenario', 'filename' ])
CarveResultFragment = namedtuple('CarveResultFragment', [ 'offset', 'size', 'hbin_start', 'suggested_margin_rounded', 'suggested_margin' ])

CarveResultCompressed = namedtuple('CarveResultCompressed', [ 'offset', 'buffer_decompressed', 'filename' ])
CarveResultFragmentCompressed = namedtuple('CarveResultFragmentCompressed', [ 'offset', 'buffer_decompressed', 'hbin_start' ])

CarveResultLog = namedtuple('CarveResultLog', [ 'offset', 'size', 'log_entries_count' ])

CarveResultMemory = namedtuple('CarveResultMemory', [ 'offset', 'buffer', 'hbin_start', 'compressed', 'partial_decompression' ])
CarveResultDeepMemory = namedtuple('CarveResultDeepMemory', [ 'offset', 'cell_data', 'key_node_or_key_value', 'is_key_node' ])

BaseBlockCheckResult = namedtuple('BaseBlockCheckResult', [ 'is_valid', 'hbins_data_size', 'filename', 'old_cells' ])
HiveBinCheckResult = namedtuple('HiveBinCheckResult', [ 'is_valid', 'size', 'offset_relative' ])
CellsCheckResult = namedtuple('CellsCheckResult', [ 'are_valid', 'truncation_point_relative' ])
LogEntryCheckResult = namedtuple('LogEntryCheckResult', [ 'is_valid', 'size', 'next_sequence_number' ])

SECTOR_SIZE = 512 # This is an assumed sector size.
PAGE_SIZE = 4096 # This is a memory page size.
FILE_MARGIN_SIZE = 4*1024*1024 # We will read more bytes than specified in the base block to account possible damage scenarios.
FILE_SIZE_MAX_MIB = 500 # We do not expect a primary file to be larger than this (in MiB).
CELL_SIZE_MAX = 2*1024*1024 # We do not expect a cell to be larger than this.
HBIN_SIZE_MAX = 64*1024*1024 # We do not expect a hive bin to be larger than this.
LOG_ENTRY_SIZE_MAX = 64*1024*1024 # We do not expect a log entry to be larger than this. Also, we will read candidate log entries in chunks of this size.

class ValidationException(Registry.RegistryException):
	"""This exception is raised when a reconstructed hive is invalid."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

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

def CheckLogEntry(Buffer, ExpectedSequenceNumber):
	"""Check if Buffer contains a valid log entry, return a named tuple (LogEntryCheckResult)."""

	if len(Buffer) < SECTOR_SIZE:
		return LogEntryCheckResult(is_valid = False, size = None, next_sequence_number = None)

	signature, size, __, sequence_number = unpack('<4sLLL', Buffer[ : 16])
	if signature != b'HvLE' or size > LOG_ENTRY_SIZE_MAX or len(Buffer) < size:
		return LogEntryCheckResult(is_valid = False, size = None, next_sequence_number = None)

	if ExpectedSequenceNumber is None:
		sequence_number_expected = sequence_number
	else:
		sequence_number_expected = ExpectedSequenceNumber

	log_entry_obj = BytesIO(Buffer[ : size])
	try:
		log_entry = RegistryFile.LogEntry(log_entry_obj, 0, sequence_number_expected)
	except (RegistryFile.LogEntryException, RegistryFile.ReadException) as e:
		return LogEntryCheckResult(is_valid = False, size = None, next_sequence_number = None)

	return LogEntryCheckResult(is_valid = True, size = size, next_sequence_number = c_uint32(sequence_number + 1).value)

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
			break

	if null_bytes_only and AllowNullBytesOnly:
		return True

	return False

def ValidateRandomCells(Buffer, OldCells = False):
	"""Check if Buffer contains plausible cells, return an offset pointing to the start of cells (or None).
	This function is used to detect a margin of a registry fragment.
	"""

	def Walk(Buffer, OldCells):
		def ValidateLargeCell(Buffer):
			if len(Buffer) < 72:
				return True

			cnt = 0
			offset = 16
			while offset < len(Buffer):
				if Buffer[offset : offset + 4] in [ b'\xFF\xFFnk', b'\xFF\xFFvk' ]:
					cnt += 1

				offset += 2

			return cnt <= 3

		if len(Buffer) < 8:
			return False

		offset = 0
		while True:
			four_bytes = Buffer[offset : offset + 4]
			if len(four_bytes) != 4:
				break

			cell_size, = unpack('<l', four_bytes)
			cell_size_abs = abs(cell_size)

			if OldCells:
				cell_size_alignment = 16
			else:
				cell_size_alignment = 8

			if cell_size_abs < cell_size_alignment or cell_size_abs % cell_size_alignment != 0 or offset + cell_size_abs > len(Buffer) or cell_size_abs > CELL_SIZE_MAX:
				return False

			cell = Buffer[offset : offset + cell_size_abs]
			if not ValidateLargeCell(cell):
				return False

			offset += cell_size_abs

		return offset == len(Buffer)

	offset = 0
	while offset < len(Buffer):
		if Walk(Buffer[offset: ], OldCells):
			return offset

		offset += 8

	return

def ValidateKeyNodeOrKeyValue(KeyNodeOrKeyValue):
	"""Perform a simple check if a key node or a key value contains obviously invalid data."""

	slack_size = len(KeyNodeOrKeyValue.get_slack())
	if slack_size >= 16:
		return False

	if type(KeyNodeOrKeyValue) is RegistryRecords.KeyValue:
		key_value = KeyNodeOrKeyValue
		if key_value.is_data_inline():
			if key_value.get_data_size_real() > 4:
				return False
		else:
			data_offset = key_value.get_data_offset()
			if key_value.get_data_size_real() > 0 and (data_offset < 8 or data_offset % 8 != 0):
				return False

		try:
			name = key_value.get_value_name()
		except RegistryRecords.ParseException:
			return False
	else:
		key_node = KeyNodeOrKeyValue
		if key_node.get_subkeys_count() > MAX_PLAUSIBLE_SUBKEYS_COUNT or key_node.get_volatile_subkeys_count() > MAX_PLAUSIBLE_SUBKEYS_COUNT:
			return False

		if key_node.get_flags() & RegistryRecords.KEY_PREDEF_HANDLE == 0 and key_node.get_key_values_count() > MAX_PLAUSIBLE_VALUES_COUNT:
			return False

		try:
			name = key_node.get_key_name()
		except RegistryRecords.ParseException:
			return False

	return True

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

class MemoryImage(object):
	"""This class is used to read from a memory image (including memory chunks from other sources).
	In order to achieve better performance, a memory image (as a file object) is mapped (if possible) or read into the memory.
	"""

	fileno = None
	file_object = None
	mode = None

	def __init__(self, file_object_or_bytes_object):
		try:
			file_object_or_bytes_object.read
			file_object_or_bytes_object.seek
		except AttributeError:
			# This is a bytes object.
			self.mode = 1
			self.data = file_object_or_bytes_object
			return

		# This is a file object.
		self.file_object = file_object_or_bytes_object

		try:
			self.fileno = self.file_object.fileno()
			self.data = mmap.mmap(self.fileno, 0, access = mmap.ACCESS_READ)
		except Exception:
			self.mode = 3
		else:
			self.mode = 2

	def size(self):
		if self.mode == 2:
			return self.data.size()
		elif self.mode == 1:
			return len(self.data)
		else:
			self.file_object.seek(0, 2)
			return self.file_object.tell()

	def read(self, pos, size):
		if self.mode == 1 or self.mode == 2:
			return self.data[pos : pos + size]
		else:
			self.file_object.seek(pos)
			return self.file_object.read(size)

class Carver(DiskImage):
	"""This class is used to carve registry files (primary and transaction log) and registry fragments from a disk image."""

	progress_callback = None
	"""A progress callback. Arguments: bytes_read, bytes_total."""

	def __init__(self, file_object):
		super(Carver, self).__init__(file_object)

		self.callback_threshold = 2*1024*1024*1024 # In bytes.

	def call_progress_callback(self, bytes_read, bytes_total):
		"""Call the progress callback, if defined."""

		if self.progress_callback is None:
			return

		if bytes_read < self.callback_threshold or bytes_read % self.callback_threshold != 0:
			return

		self.progress_callback(bytes_read, bytes_total)

	def carve(self, recover_fragments = False, ntfs_decompression = False, suggest_margin = False, recover_logs = False):
		"""This method yields named tuples (CarveResult and, if 'recover_fragments' is True, CarveResultFragment).
		When 'ntfs_decompression' is True, data from compression units (NTFS) will be also recovered, this will yield
		CarveResultCompressed and, if 'recover_fragments' is also True, CarveResultFragmentCompressed named tuples.
		When 'suggest_margin' is True, set the 'suggested_margin' and 'suggested_margin_rounded' fields for each CarveResultFragment named tuple.
		When 'recover_logs' is True, log entries (new format) will be also recovered, this will yield CarveResultLog named tuples.
		Note:
		Only the first bytes of each sector will be scanned for signatures, because registry files (primary) are always larger than
		an NTFS file record (a primary file is at least 8192 bytes in length, while a file record is 1024 or 4096 bytes in length),
		so the carver can skip data stored inside a file record (not starting at a sector boundary).
		"""

		compressed_regf_fragments = []

		pos = 0
		prev_result_end_pos = 0
		file_size = self.size()
		while pos < file_size:
			self.call_progress_callback(pos, file_size)

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
					regf_hbins_data_size = check_result.hbins_data_size
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
							yield CarveResult(offset = regf_offset, size = regf_size, hbins_data_size = regf_hbins_data_size, truncated = False, truncation_point = None,
								truncation_scenario = 0, filename = check_result.filename)
						else:
							# Truncation within the last hive bin.
							truncation_point = regf_offset + regf_size - len(last_hbin_buf) + check_result_cells.truncation_point_relative
							truncation_point = truncation_point // SECTOR_SIZE * SECTOR_SIZE # Adjust the truncation point according to the sector size.
							regf_size = truncation_point - regf_offset # Adjust the file size according to the truncation point.

							yield CarveResult(offset = regf_offset, size = regf_size, hbins_data_size = regf_hbins_data_size, truncated = True, truncation_point = truncation_point,
								truncation_scenario = 2, filename = check_result.filename)
					else:
						# Obvious truncation.
						check_result_cells = CheckCellsOfHiveBin(last_hbin_buf, check_result.old_cells)
						if check_result_cells.are_valid:
							# Truncation at a boundary of a hive bin.
							yield CarveResult(offset = regf_offset, size = regf_size, hbins_data_size = regf_hbins_data_size, truncated = True, truncation_point = truncation_point,
								truncation_scenario = 1, filename = check_result.filename)
						else:
							# Truncation within a hive bin.
							truncation_point = regf_offset + regf_size - len(last_hbin_buf) + check_result_cells.truncation_point_relative
							truncation_point = truncation_point // SECTOR_SIZE * SECTOR_SIZE # Adjust the truncation point according to the sector size.
							regf_size = truncation_point - regf_offset # Adjust the file size according to the truncation point.

							yield CarveResult(offset = regf_offset, size = regf_size, hbins_data_size = regf_hbins_data_size, truncated = True, truncation_point = truncation_point,
								truncation_scenario = 3, filename = check_result.filename)

					if regf_size % SECTOR_SIZE == 0:
						pos += regf_size
					else:
						pos += regf_size + SECTOR_SIZE - regf_size % SECTOR_SIZE

					prev_result_end_pos = pos
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

					suggested_margin = None
					suggested_margin_rounded = None
					if suggest_margin:
						# Check the preceding bytes (at most 16 sectors) for a possible margin.
						margin_check_size = fragment_offset - prev_result_end_pos
						if margin_check_size > 16 * SECTOR_SIZE:
							margin_check_size = 16 * SECTOR_SIZE
						else:
							margin_check_size = margin_check_size // SECTOR_SIZE * SECTOR_SIZE

						if margin_check_size > 0 and fragment_hbin_start > 0:
							margin_buf = self.read(fragment_offset - margin_check_size, margin_check_size)
							if len(margin_buf) == margin_check_size:
								offset_in_margin_buf = ValidateRandomCells(margin_buf)
								if offset_in_margin_buf is None:
									# No margin.
									suggested_margin = 0
									suggested_margin_rounded = 0
								else:
									# A margin is present.
									suggested_margin = margin_check_size - offset_in_margin_buf
									suggested_margin_rounded = margin_check_size - (offset_in_margin_buf // SECTOR_SIZE * SECTOR_SIZE)
									if suggested_margin_rounded + 32 > fragment_hbin_start:
										# A margin is too large, give up.
										suggested_margin = 0
										suggested_margin_rounded = 0
							else:
								# A read error, give up.
								suggested_margin = 0
								suggested_margin_rounded = 0
						else:
							# Obviously, there is no margin.
							suggested_margin = 0
							suggested_margin_rounded = 0

					yield CarveResultFragment(offset = fragment_offset, size = fragment_size, hbin_start = fragment_hbin_start, suggested_margin_rounded = suggested_margin_rounded, suggested_margin = suggested_margin)

					pos += fragment_size
					prev_result_end_pos = pos
					continue

			elif four_bytes == b'HvLE' and recover_logs:
				log_entry_buf = self.read(pos, LOG_ENTRY_SIZE_MAX)
				check_result_log_entry = CheckLogEntry(log_entry_buf, None)

				if check_result_log_entry.is_valid:
					log_offset = pos
					log_size = check_result_log_entry.size
					log_entries_count = 1

					curr_pos_relative = check_result_log_entry.size
					while True:
						log_entry_buf = self.read(pos + curr_pos_relative, LOG_ENTRY_SIZE_MAX)
						check_result_log_entry = CheckLogEntry(log_entry_buf, check_result_log_entry.next_sequence_number)

						if not check_result_log_entry.is_valid:
							break

						log_entries_count += 1
						log_size += check_result_log_entry.size
						curr_pos_relative += check_result_log_entry.size

					yield CarveResultLog(offset = log_offset, size = log_size, log_entries_count = log_entries_count)

					if log_size % SECTOR_SIZE == 0:
						pos += log_size
					else:
						pos += log_size + SECTOR_SIZE - log_size % SECTOR_SIZE

					continue

			elif ntfs_decompression:
				# A compression unit may contain data belonging to another file in the slack space. Even a new compression unit may be in the slack space.
				# Here, the slack space is an area from the end of compressed clusters to the end of a corresponding compression unit.
				# Thus, we cannot skip over a processed compression unit without scanning the slack space.
				# Sometimes there is no slack space after compressed clusters on a disk (and a new compression unit for the same file starts immediately).
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
						compressed_regf_fragments.extend(regf_fragments[True])
						yield result_1
					elif result_2 is not None and result_1 is None:
						compressed_regf_fragments.extend(regf_fragments[False])
						yield result_2
					elif result_1 is not None and result_2 is not None:
						if len(result_1.buffer_decompressed) > len(result_2.buffer_decompressed):
							compressed_regf_fragments.extend(regf_fragments[True])
							yield result_1
						else:
							compressed_regf_fragments.extend(regf_fragments[False])
							yield result_2

					prev_result_end_pos = pos + SECTOR_SIZE # This is an assumed position.

				elif recover_fragments and RegistryHelpers.NTFSCheckCompressedSignature(seven_bytes, b'hbin'):
					if pos not in compressed_regf_fragments:
						# Not a known fragment of a compressed primary file.
						buf_compressed = self.read(pos, RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE)
						buf_decompressed = RegistryHelpers.NTFSDecompressUnit(buf_compressed)

						if (len(buf_decompressed) >= RegistryFile.HIVE_BIN_SIZE_ALIGNMENT and len(buf_decompressed) % RegistryFile.HIVE_BIN_SIZE_ALIGNMENT == 0 and
							len(buf_decompressed) <= RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE):

							check_result_hbin = CheckHiveBin(buf_decompressed, None)
							if check_result_hbin.is_valid:
								fragment_offset = pos

								yield CarveResultFragmentCompressed(offset = fragment_offset, buffer_decompressed = buf_decompressed,
									hbin_start = check_result_hbin.offset_relative)

								prev_result_end_pos = pos + SECTOR_SIZE # This is an assumed position.

			pos += SECTOR_SIZE

class HiveReconstructor(object):
	"""This class is used to carve registry files (primary), registry fragments from a disk image, and then to reassemble each of them into a single file (the reconstruction process).
	Compressed (NTFS) registry files (primary), registry fragments are not supported.
	"""

	regf_fragments = None
	"""Current metadata about truncated primary files (a list of CarveResult objects)."""

	hbin_fragments = None
	"""Current metadata about registry fragments (a list of CarveResultFragment objects)."""

	progress_callback = None
	"""A progress callback (called before a truncated primary file is processed). No arguments."""

	def __init__(self, file_object):
		self.file_object = file_object
		self.carver = Carver(self.file_object)

		self.regf_fragments = []
		self.hbin_fragments = []

		self.unreferenced_limit = 5
		"""It is okay for a hive to have this number of unreferenced allocated cells (or less)."""

		self.unreferenced_fraction = 10
		"""It is okay for a hive to have the following number of unreferenced allocated cells (at most): len(hive.registry_file.cell_map_free) // self.unreferenced_fraction."""

	def call_progress_callback(self):
		"""Call the progress callback, if defined."""

		if self.progress_callback is None:
			return

		self.progress_callback()

	def read_safe(self, size):
		"""Read a specified number of bytes from a disk image at the current position (offset)."""

		buf = self.file_object.read(size)

		if size > 0 and size % 512 == 0 and len(buf) > 0 and len(buf) % 512 != 0:
			raise IOError('Invalid number of bytes returned by the read() method')

		return buf

	def find_fragments(self):
		"""Carve fragments (including truncated primary files) from a disk image, return the number of truncated primary files found."""

		self.regf_fragments = []
		self.hbin_fragments = []

		for i in self.carver.carve(True, False):
			if type(i) is CarveResult:
				if i.truncated:
					self.regf_fragments.append(i)
			else:
				self.hbin_fragments.append(i)

		return len(self.regf_fragments)

	def save_fragments(self, file_path):
		"""Save the current metadata about fragments (including truncated primary files) to a file (using the 'pickle' module)."""

		with open(file_path, 'wb') as f:
			pickle.dump((self.regf_fragments, self.hbin_fragments), f)

	def load_fragments(self, file_path):
		"""Load the metadata about fragments (including truncated primary files) from a file (using the 'pickle' module), return the number of truncated primary files loaded."""

		with open(file_path, 'rb') as f:
			self.regf_fragments, self.hbin_fragments = pickle.load(f)

		return len(self.regf_fragments)

	def set_fragments(self, fragments_list):
		"""Load the metadata about fragments (including truncated primary files) from an existing list, return the number of truncated primary files loaded."""

		self.regf_fragments = []
		self.hbin_fragments = []

		for i in fragments_list:
			if type(i) is CarveResult:
				if i.truncated:
					self.regf_fragments.append(i)
			elif type(i) is CarveResultFragment:
				self.hbin_fragments.append(i)

		return len(self.regf_fragments)

	def validate_reconstructed_hive(self, primary_object):
		"""Check if a reconstructed hive looks valid. If not, an exception is raised."""

		hive = Registry.RegistryHive(primary_object)
		hive.walk_everywhere()

		unref_count = len(hive.registry_file.cell_map_free - hive.registry_file.cell_map_unallocated)
		if unref_count > self.unreferenced_limit and unref_count > (len(hive.registry_file.cell_map_free) // self.unreferenced_fraction):
			raise ValidationException('Too many unreferenced allocated cells')

		file_size_expected = hive.registry_file.baseblock.effective_hbins_data_size + RegistryFile.BASE_BLOCK_LENGTH_PRIMARY

		primary_object.seek(0, 2)
		file_size_real = primary_object.tell()

		if file_size_real > 1024*1024 and file_size_real > 2 * file_size_expected:
			raise ValidationException('File is too large')

	def reconstruct_bifragmented(self):
		"""Try to reconstruct primary files using two fragments for each primary file."""

		for first_fragment in self.regf_fragments[:]:
			self.call_progress_callback()

			hbins_data_size_first = first_fragment.size - RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
			hbins_data_size_second = first_fragment.hbins_data_size - hbins_data_size_first

			self.file_object.seek(first_fragment.offset)
			primary_buf = self.read_safe(first_fragment.size)
			if len(primary_buf) < first_fragment.size: # The truncation point is beyond the end of the image.
				hbins_data_size_first = len(primary_buf) - RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
				hbins_data_size_second = first_fragment.hbins_data_size - hbins_data_size_first

			if len(primary_buf) < RegistryFile.BASE_BLOCK_LENGTH_PRIMARY + RegistryFile.HIVE_BIN_SIZE_ALIGNMENT: # The first fragment is too small.
				continue

			primary_obj = BytesIO(primary_buf)

			primary_file = RegistryFile.PrimaryFileTruncated(primary_obj)
			for hive_bin in primary_file.hive_bins(): # Get the last hive bin in the first fragment.
				pass

			second_fragment_margin = hive_bin.get_offset() + hive_bin.get_size() - hbins_data_size_first
			if second_fragment_margin < 0:
				second_fragment_margin = 0

			second_hbin_start = hive_bin.get_offset() + hive_bin.get_size()

			for second_fragment in self.hbin_fragments[:]:
				if second_fragment.hbin_start == second_hbin_start and second_fragment.size + second_fragment_margin >= hbins_data_size_second:
					if second_fragment.offset - second_fragment_margin >= 0:
						self.file_object.seek(second_fragment.offset - second_fragment_margin)
						fragment_buf = self.read_safe(second_fragment.size + second_fragment_margin)
					else:
						continue

					primary_obj.seek(len(primary_buf))
					primary_obj.write(fragment_buf)

					# Validate the hive.
					try:
						self.validate_reconstructed_hive(primary_obj)
					except Registry.RegistryException:
						# The hive is invalid, remove the second fragment.
						primary_obj.truncate(len(primary_buf))
					else:
						# The hive is valid.
						self.regf_fragments.remove(first_fragment)
						self.hbin_fragments.remove(second_fragment)

						yield (first_fragment, primary_obj.getvalue())
						break

			primary_obj.close()

	def reconstruct_trifragmented(self):
		"""Try to reconstruct primary files using three fragments for each primary file."""

		for first_fragment in self.regf_fragments[:]:
			self.call_progress_callback()

			fragment_done = False

			hbins_data_size_first = first_fragment.size - RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
			hbins_data_size_remaining = first_fragment.hbins_data_size - hbins_data_size_first

			self.file_object.seek(first_fragment.offset)
			primary_buf = self.read_safe(first_fragment.size)
			if len(primary_buf) < first_fragment.size: # The truncation point is beyond the end of the image.
				hbins_data_size_first = len(primary_buf) - RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
				hbins_data_size_remaining = first_fragment.hbins_data_size - hbins_data_size_first

			if len(primary_buf) < RegistryFile.BASE_BLOCK_LENGTH_PRIMARY + RegistryFile.HIVE_BIN_SIZE_ALIGNMENT: # The first fragment is too small.
				continue

			primary_obj = BytesIO(primary_buf)

			primary_file = RegistryFile.PrimaryFileTruncated(primary_obj)
			for hive_bin in primary_file.hive_bins(): # Get the last hive bin in the first fragment.
				pass

			second_fragment_margin = hive_bin.get_offset() + hive_bin.get_size() - hbins_data_size_first
			if second_fragment_margin < 0:
				second_fragment_margin = 0

			second_hbin_start = hive_bin.get_offset() + hive_bin.get_size()

			for second_fragment in self.hbin_fragments[:]:
				if second_fragment.hbin_start == second_hbin_start and second_fragment.size + second_fragment_margin < hbins_data_size_remaining:
					if second_fragment.offset - second_fragment_margin >= 0:
						self.file_object.seek(second_fragment.offset - second_fragment_margin)
						fragment_buf_2 = self.read_safe(second_fragment.size + second_fragment_margin)
					else:
						continue

					primary_obj.seek(len(primary_buf))
					primary_obj.write(fragment_buf_2)

					hbins_data_size_remaining_2 = hbins_data_size_remaining - len(fragment_buf_2)

					primary_file = RegistryFile.PrimaryFileTruncated(primary_obj)
					for hive_bin in primary_file.hive_bins(): # Get the last hive bin in the first two fragments.
						pass

					third_fragment_margin = hive_bin.get_offset() + hive_bin.get_size() - (hbins_data_size_first + len(fragment_buf_2))
					if third_fragment_margin < 0:
						third_fragment_margin = 0

					third_hbin_start = hive_bin.get_offset() + hive_bin.get_size()
					for third_fragment in self.hbin_fragments[:]:
						if third_fragment.hbin_start == third_hbin_start and third_fragment.size + third_fragment_margin >= hbins_data_size_remaining_2:
							if third_fragment.offset - third_fragment_margin >= 0:
								self.file_object.seek(third_fragment.offset - third_fragment_margin)
								fragment_buf_3 = self.read_safe(third_fragment.size + third_fragment_margin)
							else:
								continue

							primary_obj.seek(len(primary_buf) + len(fragment_buf_2))
							primary_obj.write(fragment_buf_3)

							# Validate the hive.
							try:
								self.validate_reconstructed_hive(primary_obj)
							except Registry.RegistryException:
								# The hive is invalid, remove the third fragment.
								primary_obj.truncate(len(primary_buf) + len(fragment_buf_2))
							else:
								# The hive is valid.
								self.regf_fragments.remove(first_fragment)
								self.hbin_fragments.remove(second_fragment)
								self.hbin_fragments.remove(third_fragment)

								yield (first_fragment, primary_obj.getvalue())

								fragment_done = True
								break

					if fragment_done:
						break

					primary_obj.truncate(len(primary_buf)) # Remove the second fragment.

			primary_obj.close()

	def reconstruct_quadfragmented(self):
		"""Try to reconstruct primary files using four fragments for each primary file."""

		for first_fragment in self.regf_fragments[:]:
			self.call_progress_callback()

			fragment_done = False

			hbins_data_size_first = first_fragment.size - RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
			hbins_data_size_remaining = first_fragment.hbins_data_size - hbins_data_size_first

			self.file_object.seek(first_fragment.offset)
			primary_buf = self.read_safe(first_fragment.size)
			if len(primary_buf) < first_fragment.size: # The truncation point is beyond the end of the image.
				hbins_data_size_first = len(primary_buf) - RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
				hbins_data_size_remaining = first_fragment.hbins_data_size - hbins_data_size_first

			if len(primary_buf) < RegistryFile.BASE_BLOCK_LENGTH_PRIMARY + RegistryFile.HIVE_BIN_SIZE_ALIGNMENT: # The first fragment is too small.
				continue

			primary_obj = BytesIO(primary_buf)

			primary_file = RegistryFile.PrimaryFileTruncated(primary_obj)
			for hive_bin in primary_file.hive_bins(): # Get the last hive bin in the first fragment.
				pass

			second_fragment_margin = hive_bin.get_offset() + hive_bin.get_size() - hbins_data_size_first
			if second_fragment_margin < 0:
				second_fragment_margin = 0

			second_hbin_start = hive_bin.get_offset() + hive_bin.get_size()

			for second_fragment in self.hbin_fragments[:]:
				if second_fragment.hbin_start == second_hbin_start and second_fragment.size + second_fragment_margin < hbins_data_size_remaining:
					if second_fragment.offset - second_fragment_margin >= 0:
						self.file_object.seek(second_fragment.offset - second_fragment_margin)
						fragment_buf_2 = self.read_safe(second_fragment.size + second_fragment_margin)
					else:
						continue

					primary_obj.seek(len(primary_buf))
					primary_obj.write(fragment_buf_2)

					hbins_data_size_remaining_2 = hbins_data_size_remaining - len(fragment_buf_2)

					primary_file = RegistryFile.PrimaryFileTruncated(primary_obj)
					for hive_bin in primary_file.hive_bins(): # Get the last hive bin in the first two fragments.
						pass

					third_fragment_margin = hive_bin.get_offset() + hive_bin.get_size() - (hbins_data_size_first + len(fragment_buf_2))
					if third_fragment_margin < 0:
						third_fragment_margin = 0

					third_hbin_start = hive_bin.get_offset() + hive_bin.get_size()

					for third_fragment in self.hbin_fragments[:]:
						if third_fragment.hbin_start == third_hbin_start and third_fragment.size + third_fragment_margin < hbins_data_size_remaining_2:
							if third_fragment.offset - third_fragment_margin >= 0:
								self.file_object.seek(third_fragment.offset - third_fragment_margin)
								fragment_buf_3 = self.read_safe(third_fragment.size + third_fragment_margin)
							else:
								continue

							primary_obj.seek(len(primary_buf) + len(fragment_buf_2))
							primary_obj.write(fragment_buf_3)

							hbins_data_size_remaining_3 = hbins_data_size_remaining_2 - len(fragment_buf_3)

							primary_file = RegistryFile.PrimaryFileTruncated(primary_obj)
							for hive_bin in primary_file.hive_bins(): # Get the last hive bin in the first three fragments.
								pass

							fourth_fragment_margin = hive_bin.get_offset() + hive_bin.get_size() - (hbins_data_size_first + len(fragment_buf_2) + len(fragment_buf_3))
							if fourth_fragment_margin < 0:
								fourth_fragment_margin = 0

							fourth_hbin_start = hive_bin.get_offset() + hive_bin.get_size()

							for fourth_fragment in self.hbin_fragments[:]:
								if fourth_fragment.hbin_start == fourth_hbin_start and fourth_fragment.size + fourth_fragment_margin >= hbins_data_size_remaining_3:
									if fourth_fragment.offset - fourth_fragment_margin >= 0:
										self.file_object.seek(fourth_fragment.offset - fourth_fragment_margin)
										fragment_buf_4 = self.read_safe(fourth_fragment.size + fourth_fragment_margin)
									else:
										continue

									primary_obj.seek(len(primary_buf) + len(fragment_buf_2) + len(fragment_buf_3))
									primary_obj.write(fragment_buf_4)

									# Validate the hive.
									try:
										self.validate_reconstructed_hive(primary_obj)
									except Registry.RegistryException:
										# The hive is invalid, remove the fourth fragment.
										primary_obj.truncate(len(primary_buf) + len(fragment_buf_2) + len(fragment_buf_3))
									else:
										# The hive is valid.
										self.regf_fragments.remove(first_fragment)
										self.hbin_fragments.remove(second_fragment)
										self.hbin_fragments.remove(third_fragment)
										self.hbin_fragments.remove(fourth_fragment)

										yield (first_fragment, primary_obj.getvalue())

										fragment_done = True
										break

							if fragment_done:
								break

							primary_obj.truncate(len(primary_buf) + len(fragment_buf_2)) # Remove the third fragment.

					if fragment_done:
						break

					primary_obj.truncate(len(primary_buf)) # Remove the second fragment.

			primary_obj.close()

	def reconstruct_incremental(self, mode = 0):
		"""Try to reconstruct primary files using up to 150 fragments for each primary file. The reconstruction process is not exhaustive here.
		When 'mode' is 0, only the largest suitable fragment will be used in each step.
		When 'mode' is 1, the largest suitable fragment will be used in each step after the first one, and the second largest fragment will be used in the first step.
		A step is an act of picking the next fragment for a primary file."""

		hbin_fragments_count_max = 149 # The first fragment is not counted.


		def find_largest_fragment(hbin_start):
			fragments = []
			for fragment in self.hbin_fragments[:]:
				if fragment.hbin_start == hbin_start:
					fragments.append(fragment)

			largest_fragment = None
			for fragment in fragments:
				if largest_fragment is None or fragment.size > largest_fragment.size:
					largest_fragment = fragment

			return largest_fragment

		def find_second_largest_fragment(hbin_start):
			fragments = []
			for fragment in self.hbin_fragments[:]:
				if fragment.hbin_start == hbin_start:
					fragments.append(fragment)

			largest_fragment = None
			for fragment in fragments:
				if largest_fragment is None or fragment.size > largest_fragment.size:
					largest_fragment = fragment

			if largest_fragment is None:
				return

			fragments.remove(largest_fragment)
			if len(fragments) == 0:
				return

			largest_fragment = None
			for fragment in fragments:
				if largest_fragment is None or fragment.size > largest_fragment.size:
					largest_fragment = fragment

			return largest_fragment


		for first_fragment in self.regf_fragments[:]:
			self.call_progress_callback()

			hbins_data_size_first = first_fragment.size - RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
			hbins_data_size_remaining = first_fragment.hbins_data_size - hbins_data_size_first

			self.file_object.seek(first_fragment.offset)
			primary_buf = self.read_safe(first_fragment.size)
			if len(primary_buf) < first_fragment.size: # The truncation point is beyond the end of the image.
				hbins_data_size_first = len(primary_buf) - RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
				hbins_data_size_remaining = first_fragment.hbins_data_size - hbins_data_size_first

			if len(primary_buf) < RegistryFile.BASE_BLOCK_LENGTH_PRIMARY + RegistryFile.HIVE_BIN_SIZE_ALIGNMENT: # The first fragment is too small.
				continue

			primary_obj = BytesIO(primary_buf)
			next_fragments_used = []

			for step in range(0, hbin_fragments_count_max):
				primary_file = RegistryFile.PrimaryFileTruncated(primary_obj)
				for hive_bin in primary_file.hive_bins(): # Get the last hive bin in the first fragment.
					pass

				next_fragment_margin = hive_bin.get_offset() + hive_bin.get_size() - hbins_data_size_first
				if next_fragment_margin < 0:
					next_fragment_margin = 0

				next_hbin_start = hive_bin.get_offset() + hive_bin.get_size()

				if mode == 0:
					next_fragment = find_largest_fragment(next_hbin_start)
				if mode == 1 and step == 0:
					next_fragment = find_second_largest_fragment(next_hbin_start)
				else:
					next_fragment = find_largest_fragment(next_hbin_start)

				if next_fragment is None:
					break # No fragment found, give up.

				if next_fragment.offset - next_fragment_margin < 0:
					break # Wrong fragment, give up.

				self.file_object.seek(next_fragment.offset - next_fragment_margin)
				next_fragment_buf = self.read_safe(next_fragment.size + next_fragment_margin)

				primary_obj.seek(0, 2)
				primary_obj.write(next_fragment_buf)

				next_fragments_used.append(next_fragment)

				hbins_data_size_first += len(next_fragment_buf)
				hbins_data_size_remaining = first_fragment.hbins_data_size - hbins_data_size_first

				if hbins_data_size_remaining <= 0:
					# Validate the hive.
					try:
						self.validate_reconstructed_hive(primary_obj)
					except Registry.RegistryException:
						# The hive is invalid.
						break
					else:
						# The hive is valid.
						self.regf_fragments.remove(first_fragment)
						for fragment in next_fragments_used:
							self.hbin_fragments.remove(fragment)

						yield (first_fragment, primary_obj.getvalue())

					break # We are done.

			primary_obj.close()

	def reconstruct_fragmented(self):
		"""Try to reconstruct primary files using a variable number of fragments (two, three, four, or more) for each primary file.
		This method will yield the following tuples: (first_fragment, reconstructed_buffer). The type of the 'first_fragment' is CarveResult.
		The current metadata is modified by this method: reconstructed fragments are removed from the lists.
		This method is a wrapper for other reconstruct_*() methods.
		"""

		for r in self.reconstruct_bifragmented():
			yield r

		for r in self.reconstruct_trifragmented():
			yield r

		for r in self.reconstruct_quadfragmented():
			yield r

		for r in self.reconstruct_incremental(0):
			yield r

		for r in self.reconstruct_incremental(1):
			yield r

class NTFSAwareCarver(DiskImage):
	"""This class is used to carve fragmented registry files (primary) from an NTFS volume (a disk image) using active and remnant data attribute records.
	Compressed (NTFS) registry files (primary) and unfragmented registry files (primary) are not carved.
	Note: Python 3 only.
	"""

	regf_fragments = None
	"""Current metadata about truncated primary files (a list of CarveResult objects)."""

	data_runs = None
	"""Current metadata about NTFS data runs (a list of DataAttribute objects)."""

	cluster_sizes = None
	"""A list of common cluster sizes (NTFS)."""

	progress_callback  = None
	"""A progress callback. Arguments: bytes_read, bytes_total. Note: the carver may read a disk image twice."""

	def __init__(self, file_object):
		super(NTFSAwareCarver, self).__init__(file_object)

		self.regf_fragments = []
		self.data_runs = []

		self.chunk_size = 32768
		self.callback_threshold = 2*1024*1024*1024 # In bytes (a multiple of the 'chunk_size' value).

		self.cluster_sizes = [ 4096, 512, 1024, 2048, 8192 ]

	def call_progress_callback(self, bytes_read, bytes_total):
		"""Call the progress callback, if defined."""

		if self.progress_callback is None:
			return

		if bytes_read < self.callback_threshold or bytes_read % self.callback_threshold != 0:
			return

		self.progress_callback(bytes_read, bytes_total)

	def find_fragments(self):
		"""Carve truncated primary files from a disk image, return the number of truncated primary files found."""

		self.regf_fragments = []

		carver = Carver(self.file_object)
		carver.progress_callback = self.progress_callback

		for result in carver.carve(False, False):
			if result.truncated:
				self.regf_fragments.append(result)

		return len(self.regf_fragments)

	def save_fragments(self, file_path):
		"""Save the current metadata about truncated primary files to a file (using the 'pickle' module)."""

		with open(file_path, 'wb') as f:
			pickle.dump(self.regf_fragments, f)

	def load_fragments(self, file_path):
		"""Load the metadata about truncated primary files from a file (using the 'pickle' module), return the number of truncated primary files loaded."""

		with open(file_path, 'rb') as f:
			self.regf_fragments = pickle.load(f)

		return len(self.regf_fragments)

	def set_fragments(self, fragments_list):
		"""Load the metadata about truncated primary files from an existing list, return the number of truncated primary files loaded."""

		self.regf_fragments = []

		for i in fragments_list:
			if type(i) is CarveResult:
				if i.truncated:
					self.regf_fragments.append(i)

		return len(self.regf_fragments)

	def find_data_runs(self):
		"""Carve data runs from a disk image, return the number of data runs found."""

		self.data_runs = []

		pos = 0
		file_size = self.size()
		while pos < file_size:
			self.call_progress_callback(pos, file_size)

			buf = self.read(pos, self.chunk_size)
			data_attrs = RegistryHelpers.NTFSFindDataAttributeRecords(buf)
			if len(data_attrs) > 0:
				self.data_runs.extend(data_attrs)

			if len(buf) != self.chunk_size: # End of a file or a read error.
				break

			pos += self.chunk_size

		return len(self.data_runs)

	def save_data_runs(self, file_path):
		"""Save the current metadata about data runs to a file (using the 'pickle' module)."""

		with open(file_path, 'wb') as f:
			pickle.dump(self.data_runs, f)

	def load_data_runs(self, file_path):
		"""Load the metadata about data runs from a file (using the 'pickle' module), return the number of data runs loaded."""

		with open(file_path, 'rb') as f:
			self.data_runs = pickle.load(f)

		return len(self.data_runs)

	def set_data_runs(self, data_runs_list):
		"""Load the metadata about data runs from an existing list, return the number of data runs loaded."""

		self.data_runs = []

		for i in data_runs_list:
			if type(i) is RegistryHelpers.DataAttribute:
				self.data_runs.append(i)

		return len(self.data_runs)

	def validate_reconstructed_hive(self, primary_object):
		"""Check if a reconstructed hive looks valid. If not, an exception is raised."""

		hive = Registry.RegistryHive(primary_object)
		hive.walk_everywhere()

		file_size_expected = hive.registry_file.baseblock.effective_hbins_data_size + RegistryFile.BASE_BLOCK_LENGTH_PRIMARY

		primary_object.seek(0, 2)
		file_size_real = primary_object.tell()

		if file_size_real > 1024*1024 and file_size_real > 2 * file_size_expected:
			raise ValidationException('File is too large')

	def reconstruct_ntfs(self, ntfs_volume_offset = 0):
		"""This method yields the following tuples: (first_fragment, reconstructed_buffer). The type of the 'first_fragment' is CarveResult.
		The 'ntfs_volume_offset' argument is the NTFS volume offset in bytes.
		Reconstructed truncated primary files and corresponding data runs are removed from the metadata lists by this method.
		"""

		if ntfs_volume_offset > 0 and ntfs_volume_offset % SECTOR_SIZE != 0:
			raise ValueError('Invalid NTFS volume offset: {}'.format(ntfs_volume_offset))

		for cluster_size in self.cluster_sizes:
			for regf_fragment in self.regf_fragments[:]:
				regf_offset_in_volume = regf_fragment.offset - ntfs_volume_offset
				if regf_offset_in_volume <= 0:
					# The fragment does not belong to this volume.
					continue

				if regf_offset_in_volume < cluster_size or regf_offset_in_volume % cluster_size != 0:
					# The fragment does not belong to this volume or the cluster size is wrong.
					continue

				regf_cluster = regf_offset_in_volume // cluster_size

				for attr in self.data_runs[:]:
					if len(attr.data_runs) <= 1:
						# Not a fragmented data run.
						continue

					first_cluster = attr.data_runs[0][0]
					if regf_cluster != first_cluster:
						continue

					# Found a matching data run.
					primary_object = BytesIO()
					for offset_in_clusters, size_in_clusters in attr.data_runs:
						offset = offset_in_clusters * cluster_size + ntfs_volume_offset
						size = size_in_clusters * cluster_size

						if offset + size > 0xFFFFFFFFFFFFFFFF:
							# Invalid chunk.
							break

						if size > FILE_SIZE_MAX_MIB * 1024 * 1024:
							# Chunk is too large.
							break

						curr_buf = self.read(offset, size)
						primary_object.write(curr_buf)

						if primary_object.tell() > FILE_SIZE_MAX_MIB * 1024 * 1024:
							# File is too large.
							break

						if len(curr_buf) != size:
							# Truncated data.
							break

					try:
						self.validate_reconstructed_hive(primary_object)
					except Registry.RegistryException:
						pass
					else:
						self.regf_fragments.remove(regf_fragment)
						self.data_runs.remove(attr)

						yield (regf_fragment, primary_object.getvalue())

						primary_object.close()
						break

					primary_object.close()

class MemoryCarver(MemoryImage):
	"""This class is used to carve registry fragments from a memory image (or a similar source: e.g., a page file)."""

	progress_callback = None
	"""A progress callback. Arguments: bytes_read, bytes_total."""

	def __init__(self, file_object):
		super(MemoryCarver, self).__init__(file_object)

		self.callback_threshold = 1*1024*1024 # In bytes.

	def call_progress_callback(self, bytes_read, bytes_total):
		"""Call the progress callback, if defined."""

		if self.progress_callback is None:
			return

		if bytes_read < self.callback_threshold or bytes_read % self.callback_threshold != 0:
			return

		self.progress_callback(bytes_read, bytes_total)

	def carve(self, allow_compressed_remnants = False):
		"""This method yields named tuples (CarveResultMemory).
		If 'allow_compressed_remnants' is True, examine partial compressed data (which cannot be decompressed to a full memory page).
		Notes: all possible offsets are tried in the image; only registry fragments (without their margins) are extracted.
		"""

		pos = 0
		prev_result_end_pos = 0
		file_size = self.size()
		while pos < file_size:
			self.call_progress_callback(pos, file_size)

			buf = self.read(pos, PAGE_SIZE)
			if len(buf) == 0: # End of a file or a read error.
				break

			if b'hbin' not in buf: # Do the quick check.
				jump = len(buf) - 16
				if jump > 0: # Jump over a useless buffer (minus some bytes to account possible compression).
					pos += jump
					continue

			four_bytes = buf[ : 4]
			eight_bytes = buf[ : 8]

			if four_bytes == b'hbin':
				buf = self.read(pos, 32 * PAGE_SIZE) # Read more memory pages (we will check if they are contiguous).

				if len(buf) == 0: # End of a file or a read error.
					break

				check_result_hbin = CheckHiveBin(buf, None, True)
				if check_result_hbin.is_valid:
					hbin_buf = buf[ : check_result_hbin.size]

					if len(hbin_buf) < check_result_hbin.size:
						padding_length = check_result_hbin.size - len(hbin_buf)
						hbin_buf += b'\x00' * padding_length

					check_result_cells = CheckCellsOfHiveBin(hbin_buf) # We assume the new cell format here.
					if not check_result_cells.are_valid:
						# The hive bin is truncated.
						fragment_offset = pos
						fragment_size = check_result_cells.truncation_point_relative
						fragment_hbin_start = check_result_hbin.offset_relative

						fragment_buf = buf[ : fragment_size]
						if len(fragment_buf) > 32:
							# There is at least one cell, report the fragment.
							yield CarveResultMemory(offset = fragment_offset, buffer = fragment_buf,
								hbin_start = fragment_hbin_start, compressed = False, partial_decompression = None)

							pos += 32 # We do not know the exact truncation point within the last cell.
							prev_result_end_pos = pos # This is an assumed position.
							continue
					else:
						# The hive bin is valid, scan for more hive bins.
						fragment_offset = pos
						fragment_hbin_start = check_result_hbin.offset_relative

						expected_hbin_offset_relative = check_result_hbin.offset_relative

						fragment_size = 0 # This value will be adjusted in the loop below.
						curr_pos_relative = 0 # We will scan the first hive bin in a current chunk again.
						padding_used = False
						while True:
							hbin_buf_partial = buf[curr_pos_relative : curr_pos_relative + RegistryFile.HIVE_BIN_SIZE_ALIGNMENT]

							check_result_hbin = CheckHiveBin(hbin_buf_partial, expected_hbin_offset_relative, True)
							if not check_result_hbin.is_valid:
								break

							hbin_buf = buf[curr_pos_relative : curr_pos_relative + check_result_hbin.size]

							if len(hbin_buf) < check_result_hbin.size:
								padding_length = check_result_hbin.size - len(hbin_buf)
								hbin_buf += b'\x00' * padding_length
								padding_used = True

							check_result_cells = CheckCellsOfHiveBin(hbin_buf) # We assume the new cell format here.
							if check_result_cells.are_valid:
								curr_pos_relative += check_result_hbin.size
								fragment_size += check_result_hbin.size
								expected_hbin_offset_relative += check_result_hbin.size

								if not padding_used:
									continue
								else:
									break

							fragment_size += check_result_cells.truncation_point_relative
							break

						if fragment_size > 0:
							fragment_buf = buf[ : fragment_size]

							padding_used = False
							if len(fragment_buf) < fragment_size:
								padding_length = fragment_size - len(fragment_buf)
								fragment_buf += b'\x00' * padding_length
								padding_used = True

							yield CarveResultMemory(offset = fragment_offset, buffer = fragment_buf,
								hbin_start = fragment_hbin_start, compressed = False, partial_decompression = None)

							if not padding_used:
								pos += fragment_size
							else:
								pos += fragment_size - padding_length

							prev_result_end_pos = pos
							continue

			elif pos % 16 == 0 and RegistryHelpers.LZ77CheckCompressedSignature(eight_bytes, b'hbin'): # Compressed memory pages are aligned to 16 bytes.
				buf = self.read(pos, PAGE_SIZE)

				if len(buf) <= 16: # End of a file or a read error.
					break

				buf_decompressed, __, __ = RegistryHelpers.LZ77DecompressBuffer(buf)
				if len(buf_decompressed) >= PAGE_SIZE or (allow_compressed_remnants and len(buf_decompressed) >= 128):
					# Remove bogus data at the end of the buffer.
					# It is there because we did not know the exact size of compressed data.
					buf_decompressed = buf_decompressed[ : PAGE_SIZE]

					is_partial = len(buf_decompressed) < PAGE_SIZE
					if is_partial:
						# Add extra null bytes.
						padding_length = PAGE_SIZE - len(buf_decompressed)
						buf_decompressed += b'\x00' * padding_length

					check_result_hbin = CheckHiveBin(buf_decompressed, None, True)
					if check_result_hbin.is_valid:
						# We assume that only one hive bin can be present in a single memory page.
						# This is always true (because a hive bin cannot be smaller than a memory page).
						hbin_buf = buf_decompressed[ : check_result_hbin.size]

						fragment_offset = pos
						fragment_hbin_start = check_result_hbin.offset_relative

						check_result_cells = CheckCellsOfHiveBin(hbin_buf) # We assume the new cell format here.
						if check_result_cells.are_valid:
							yield CarveResultMemory(offset = fragment_offset, buffer = hbin_buf,
								hbin_start = fragment_hbin_start, compressed = True, partial_decompression = is_partial)
						elif check_result_cells.truncation_point_relative > 32:
							# There is at least one cell, report the fragment.
							hbin_buf = hbin_buf[ : check_result_cells.truncation_point_relative]
							yield CarveResultMemory(offset = fragment_offset, buffer = hbin_buf,
								hbin_start = fragment_hbin_start, compressed = True, partial_decompression = is_partial)

						pos += 16
						prev_result_end_pos = pos # This is an assumed position.
						continue

			pos += 1

	def carve_deep(self):
		"""This method yields named tuples (CarveResultDeepMemory).
		Notes: this method can be used to examine sources like files containing disclosed (leaked) uninitialized kernel memory; only the new cell format is supported.
		There is no way to distinguish between compressed and normal (not compressed) cells, both can pass the validation check and both can be present in memory leaks.
		"""

		pos = 0
		file_size = self.size()
		while pos < file_size:
			self.call_progress_callback(pos, file_size)

			buf = self.read(pos, PAGE_SIZE)
			if len(buf) == 0: # End of a file or a read error.
				break

			if b'\xFF\xFFnk' not in buf and b'\xFF\xFFvk' not in buf and b'\x00\x00nk' not in buf and b'\x00\x00vk' not in buf: # Do the quick check.
				pos += len(buf) # Jump over a useless buffer.
				continue

			six_bytes = buf[ : 6]
			if len(six_bytes) != 6:
				break # End of a file or a read error.

			if six_bytes.endswith(b'nk') or six_bytes.endswith(b'vk'):
				cell_size, = unpack('<l', six_bytes[ : 4])
				cell_size_abs = abs(cell_size)

				if cell_size_abs >= 8 and cell_size_abs % 8 == 0 and pos + cell_size_abs <= file_size and cell_size_abs <= CELL_SIZE_MAX:
					cell_data = self.read(pos + 4, cell_size_abs - 4)

					try:
						key_node_or_key_value = RegistryRecords.KeyNode(cell_data)
						is_key_node = True
					except Registry.RegistryException:
						try:
							key_node_or_key_value = RegistryRecords.KeyValue(cell_data)
							is_key_node = False
						except Registry.RegistryException:
							key_node_or_key_value = None
							is_key_node = None

					try:
						if key_node_or_key_value is not None and ValidateKeyNodeOrKeyValue(key_node_or_key_value):
							yield CarveResultDeepMemory(offset = pos, cell_data = cell_data, key_node_or_key_value = key_node_or_key_value, is_key_node = is_key_node)
					except Registry.RegistryException:
						pass

			pos += 1
