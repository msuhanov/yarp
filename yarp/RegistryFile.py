# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module implements a low-level interface to work with registry hives.

from __future__ import unicode_literals

from struct import unpack, pack
from ctypes import c_uint32
from io import BytesIO
from shutil import copyfileobj
from collections import namedtuple

MAJOR_VERSION_NUMBERS_SUPPORTED = set([1])
MINOR_VERSION_NUMBERS_SUPPORTED = set([1, 2, 3, 4, 5, 6])

MINOR_VERSION_NUMBERS_FOR_OLD_CELL_FORMAT = set([1])
MINOR_VERSION_NUMBERS_FOR_NEW_CELL_FORMAT = set(MINOR_VERSION_NUMBERS_SUPPORTED - MINOR_VERSION_NUMBERS_FOR_OLD_CELL_FORMAT)

FILE_TYPE_PRIMARY     = 0 # Primary (normal) file.
FILE_TYPE_LOG_OLD     = 1 # Transaction log file (old format).
FILE_TYPE_LOG_VERYOLD = 2 # Transaction log file (the same old format, but with a different type number).
FILE_TYPE_LOG_NEW     = 6 # Transaction log file (new format).
FILE_TYPES_SUPPORTED  = set([FILE_TYPE_PRIMARY, FILE_TYPE_LOG_OLD, FILE_TYPE_LOG_VERYOLD, FILE_TYPE_LOG_NEW])

FILE_FORMAT_DIRECT_MEMORY_LOAD = 1

HIVE_FLAG_KTM_LOCKED             = 0x1
HIVE_FLAG_DEFRAGMENTED           = 0x2
HIVE_FLAG_LAYERED_KEYS_SUPPORTED = 0x2 # The same value.

BASE_BLOCK_LENGTH_PRIMARY = 4096
FILE_CLUSTERING_FACTOR    = 1 # This is the only value expected (even when the sector size is not 512 bytes).
BASE_BLOCK_LENGTH_LOG     = 512 * FILE_CLUSTERING_FACTOR

MARVIN32_SEED = 0x82EF4D887A4E55C5 # This is the seed for log entries.

HIVE_BIN_SIZE_ALIGNMENT = 4096

CELL_OFFSET_NIL = 0xFFFFFFFF
CELL_SIZE_MAX_NAIVE = 10 * 1024 * 1024

DirtyPageMeta = namedtuple('DirtyPageMeta', [ 'relative_offset_primary', 'relative_offset_log' ])
DirtyPageReference = namedtuple('DirtyPageReference', [ 'relative_offset_primary', 'size' ])

def Marvin32(Buffer, Seed = MARVIN32_SEED):
	"""Calculate and return the Marvin32 hash (64 bits) of Buffer."""

	def ROTL(X, N, W):
		return (X.value << N) | (X.value >> (W - N))

	def Mix(State, Val):
		lo, hi = State
		lo.value += Val.value
		hi.value ^= lo.value
		lo.value = ROTL(lo, 20, 32) + hi.value
		hi.value = ROTL(hi, 9, 32) ^ lo.value
		lo.value = ROTL(lo, 27, 32) + hi.value
		hi.value = ROTL(hi, 19, 32)
		return (lo, hi)

	lo = c_uint32(Seed)
	hi = c_uint32(Seed >> 32)
	state = (lo, hi)

	length = len(Buffer)
	pos = 0
	val = c_uint32()

	while length >= 4:
		val.value = unpack('<L', Buffer[pos : pos + 4])[0]
		state = Mix(state, val)
		pos += 4
		length -= 4

	final = c_uint32(0x80)
	if length == 3:
		final.value = (final.value << 8) | Buffer[pos + 2]
	elif length == 2:
		final.value = (final.value << 8) | Buffer[pos + 1]
	elif length == 1:
		final.value = (final.value << 8) | Buffer[pos]

	state = Mix(state, final)
	state = Mix(state, c_uint32(0))
	lo, hi = state
	return (hi.value << 32) | lo.value

def LogEntryFlagsToBaseBlockFlags(LogEntryFlags, BaseBlockFlags):
	"""Convert flags from a log entry for use in a base block."""

	if LogEntryFlags & 1 > 0:
		if BaseBlockFlags & 1 == 0:
			BaseBlockFlags += 1
	else:
		if BaseBlockFlags & 1 > 0:
			BaseBlockFlags -= 1

	return BaseBlockFlags

class RegistryException(Exception):
	"""This is a top-level exception for this module."""

	pass

class ReadException(RegistryException):
	"""This exception is raised when a read error has occurred.
	This exception does not supersede standard I/O exceptions.
	"""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class NotSupportedException(RegistryException):
	"""This exception is raised when something is not supported."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class BaseBlockException(RegistryException):
	"""This exception is raised when something is invalid in a base block."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class FileSizeException(RegistryException):
	"""This exception is raised when a file has an obviously invalid size."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class HiveBinException(RegistryException):
	"""This exception is raised when something is invalid in a hive bin."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class HiveCellException(RegistryException):
	"""This exception is raised when something is wrong with a hive cell."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class DirtyVectorException(RegistryException):
	"""This exception is raised when something is invalid in a dirty vector."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class DirtyPageException(RegistryException):
	"""This exception is raised when a dirty page is invalid (truncated)."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class LogEntryException(RegistryException):
	"""This exception is raised when a log entry is invalid."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class RecoveryException(RegistryException):
	"""This exception is raised when a recovery error has occurred."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class NotEligibleException(RegistryException):
	"""This exception is raised when a transaction log file cannot be applied to a primary file."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class CellOffsetException(RegistryException):
	"""This exception is raised when an invalid cell has been requested."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class RegistryFile(object):
	"""This is a generic class for registry files, it provides low-level methods for reading, parsing, and writing data.
	All methods are self-explanatory.
	"""

	def __init__(self, file_object, file_offset = 0):
		self.file_object = file_object
		self.file_offset = file_offset

	def get_file_size(self):
		self.file_object.seek(0, 2)
		return self.file_object.tell()

	def read_binary(self, pos, length):
		try:
			self.file_object.seek(self.file_offset + pos)
			b = self.file_object.read(length)
		except (OverflowError, OSError):
			raise ReadException('Cannot read data (offset overflow)')

		if len(b) == length:
			return b

		raise ReadException('Cannot read data (expected: {} bytes, read: {} bytes)'.format(length, len(b)))

	def write_binary(self, pos, data):
		self.file_object.seek(self.file_offset + pos)
		self.file_object.write(data)

	def read_uint32(self, pos):
		b = self.read_binary(pos, 4)
		return unpack('<L', b)[0]

	def write_uint32(self, pos, i):
		b = pack('<L', i)
		self.write_binary(pos, b)

	def read_int32(self, pos):
		b = self.read_binary(pos, 4)
		return unpack('<l', b)[0]

	def write_int32(self, pos, i):
		b = pack('<l', i)
		self.write_binary(pos, b)

	def read_uint64(self, pos):
		b = self.read_binary(pos, 8)
		return unpack('<Q', b)[0]

	def write_uint64(self, pos, i):
		b = pack('<Q', i)
		self.write_binary(pos, b)

class BaseBlock(RegistryFile):
	"""This is a class for a base block of a registry file, it provides methods to access various fields of the base block.
	Most methods are self-explanatory.
	"""

	is_primary_file = None
	"""True if this is a primary file."""

	is_baseblock_valid = None
	"""True if this base block has a valid checksum."""

	is_file_dirty = None
	"""True if this file needs to be recovered."""

	effective_root_cell_offset = None
	"""A root cell offset to be used when parsing a primary file."""

	effective_last_written_timestamp = None
	"""A last written timestamp to be used during the recovery."""

	effective_last_reorganized_timestamp = None
	"""A last reorganized timestamp to be used when dealing with access bits."""

	effective_hbins_data_size = None
	"""A hive bins data size to be used when parsing a primary file."""

	effective_version = None
	"""A minor version number to be used when parsing a primary file."""

	effective_flags = None
	"""Flags to be used."""

	use_old_cell_format = None
	"""True if the old cell format is used in a primary file."""

	def __init__(self, file_object, no_hive_bins = False):
		super(BaseBlock, self).__init__(file_object)

		signature = self.get_signature()
		if signature != b'regf': # This is the only check possible before we validate the base block.
			raise BaseBlockException('Invalid signature: {}'.format(signature))

		# We have to trust these fields even if the base block is not valid. We can adjust these values later (according to the log file).
		self.effective_root_cell_offset = self.get_root_cell_offset()
		self.effective_version = self.get_minor_version()
		self.effective_last_reorganized_timestamp = self.get_last_reorganized_timestamp()
		self.effective_flags = self.get_flags()

		self.use_old_cell_format = self.effective_version in MINOR_VERSION_NUMBERS_FOR_OLD_CELL_FORMAT

		self.is_primary_file = self.get_file_type() == FILE_TYPE_PRIMARY # We have to trust this field even if the base block is not valid.
		if self.is_primary_file:
			file_size = self.get_file_size()
			if file_size < BASE_BLOCK_LENGTH_PRIMARY + HIVE_BIN_SIZE_ALIGNMENT and not no_hive_bins: # Check if a base block and at least one hive bin can be present in the file.
				raise FileSizeException('Invalid file size: {}'.format(file_size))

			hbins_data_size_guessed = ((file_size - BASE_BLOCK_LENGTH_PRIMARY) // HIVE_BIN_SIZE_ALIGNMENT) * HIVE_BIN_SIZE_ALIGNMENT # Keep the value aligned.

			if not no_hive_bins:
				first_hbin_timestamp = HiveBin(self.file_object, BASE_BLOCK_LENGTH_PRIMARY, True, self.use_old_cell_format).get_timestamp()
				self.effective_last_written_timestamp = first_hbin_timestamp

		self.is_baseblock_valid = self.validate_checksum()

		if not self.is_baseblock_valid:
			self.is_file_dirty = True
			if self.is_primary_file:
				self.effective_hbins_data_size = hbins_data_size_guessed

			return # We cannot trust the base block, return.

		self.is_file_dirty = self.get_primary_sequence_number() != self.get_secondary_sequence_number()
		self.effective_last_written_timestamp = self.get_last_written_timestamp()

		hbins_data_size = self.get_hbins_data_size()
		self.effective_hbins_data_size = hbins_data_size

		major_version = self.get_major_version()
		if major_version not in MAJOR_VERSION_NUMBERS_SUPPORTED:
			raise NotSupportedException('Major version not supported: {}'.format(major_version))

		minor_version = self.get_minor_version()
		if minor_version not in MINOR_VERSION_NUMBERS_SUPPORTED:
			raise NotSupportedException('Minor version not supported: {}'.format(minor_version))

		file_type = self.get_file_type()
		if file_type not in FILE_TYPES_SUPPORTED:
			raise NotSupportedException('File type not supported: {}'.format(file_type))

		file_format = self.get_file_format()
		if file_format != FILE_FORMAT_DIRECT_MEMORY_LOAD:
			raise NotSupportedException('File format not supported: {}'.format(file_format))

		clustering_factor = self.get_clustering_factor()
		if clustering_factor != FILE_CLUSTERING_FACTOR:
			raise NotSupportedException('Clustering factor not supported: {}'.format(clustering_factor))

		if hbins_data_size < HIVE_BIN_SIZE_ALIGNMENT or hbins_data_size % HIVE_BIN_SIZE_ALIGNMENT != 0:
			raise BaseBlockException('Invalid hive bins data size: {}'.format(hbins_data_size))

	def get_signature(self):
		return self.read_binary(0, 4)

	def get_primary_sequence_number(self):
		return self.read_uint32(4)

	def get_secondary_sequence_number(self):
		return self.read_uint32(8)

	def write_synchronized_sequence_numbers(self, sequence_number):
		self.write_uint32(4, sequence_number)
		self.write_uint32(8, sequence_number)

	def get_last_written_timestamp(self):
		return self.read_uint64(12)

	def get_major_version(self):
		return self.read_uint32(20)

	def get_minor_version(self):
		return self.read_uint32(24)

	def get_file_type(self):
		return self.read_uint32(28)

	def write_file_type(self, file_type):
		self.write_uint32(28, file_type)

	def get_file_format(self):
		return self.read_uint32(32)

	def get_root_cell_offset(self):
		return self.read_uint32(36)

	def get_hbins_data_size(self):
		return self.read_uint32(40)

	def write_hbins_data_size(self, hbins_data_size):
		self.write_uint32(40, hbins_data_size)

	def get_clustering_factor(self):
		return self.read_uint32(44)

	def get_filename(self):
		return self.read_binary(48, 64)

	def get_checksum(self):
		return self.read_uint32(508)

	def write_checksum(self, checksum):
		self.write_uint32(508, checksum)

	def get_boot_type(self):
		if not self.is_primary_file:
			return

		return self.read_uint32(4088)

	def get_boot_recover(self):
		if not self.is_primary_file:
			return

		return self.read_uint32(4092)

	def get_rmid(self):
		return self.read_binary(112, 16)

	def get_logid(self):
		return self.read_binary(128, 16)

	def get_flags(self):
		return self.read_uint32(144)

	def write_flags(self, flags):
		self.write_uint32(144, flags)

	def get_tmid(self):
		return self.read_binary(148, 16)

	def get_guid_signature(self):
		return self.read_binary(164, 4)

	def is_hive_rmtm(self):
		"""Compare a GUID signature recorded in a file to the 'rmtm' string."""

		return self.get_guid_signature() == b'rmtm'

	def get_last_reorganized_timestamp(self):
		timestamp = self.read_uint64(168)
		if timestamp & 3 == 0 or timestamp & 3 == 3:
			return

		return timestamp

	def get_last_reorganize_type(self):
		timestamp = self.get_last_reorganized_timestamp()
		if timestamp is not None:
			return timestamp & 3

	def get_thawtmid(self):
		if not self.is_primary_file:
			return

		return self.read_binary(4040, 16)

	def get_thawrmid(self):
		if not self.is_primary_file:
			return

		return self.read_binary(4056, 16)

	def get_thawlogid(self):
		if not self.is_primary_file:
			return

		return self.read_binary(4072, 16)

	def calculate_checksum(self):
		csum = 0

		i = 0
		while i < 508:
			cval = self.read_uint32(i)
			csum ^= cval
			i += 4

		if csum == 0:
			csum = 1
		elif csum == 0xFFFFFFFF:
			csum = 0xFFFFFFFE

		return csum

	def validate_checksum(self):
		"""Compare a calculated checksum to the checksum recorded in a file."""

		return self.calculate_checksum() == self.get_checksum()

	def update_checksum(self):
		self.write_checksum(self.calculate_checksum())

	def get_offreg_signature_old(self):
		return self.read_binary(168, 4)

	def get_offreg_flags_old(self):
		return self.read_uint32(172)

	def get_offreg_signature_new(self):
		return self.read_binary(176, 4)

	def get_offreg_flags_new(self):
		return self.read_uint32(180)

	def is_hive_serialized_using_offreg(self):
		"""Check if a hive was serialized using the offreg.dll library."""

		if self.get_offreg_signature_old() == b'OfRg' and self.get_offreg_flags_old() == 1:
			return True

		if self.get_offreg_signature_new() == b'OfRg' and self.get_offreg_flags_new() == 1:
			return True

		return False

	def get_offreg_serialization_timestamp(self):
		if not self.is_primary_file:
			return

		if not self.is_hive_serialized_using_offreg():
			return

		return self.read_uint64(512)

class HiveBin(RegistryFile):
	"""This is a class for a hive bin, it provides methods to access various fields of the hive bin.
	All methods are self-explanatory.
	"""

	cells = None
	"""A list of cells (HiveCell) in this hive bin."""

	def __init__(self, file_object, file_offset, tolerate_cell_errors = False, use_old_cell_format = False):
		super(HiveBin, self).__init__(file_object, file_offset)

		signature = self.get_signature()
		if signature != b'hbin':
			raise HiveBinException('Invalid signature: {}'.format(signature))

		hbin_offset = self.get_offset()
		if hbin_offset != file_offset - BASE_BLOCK_LENGTH_PRIMARY:
			raise HiveBinException('Offset mismatch: {} != {} - {}'.format(hbin_offset, file_offset, BASE_BLOCK_LENGTH_PRIMARY))

		hbin_size = self.get_size()
		if hbin_size < HIVE_BIN_SIZE_ALIGNMENT or hbin_size % HIVE_BIN_SIZE_ALIGNMENT != 0:
			raise HiveBinException('Invalid size: {}'.format(hbin_size))

		self.cells = []

		if use_old_cell_format:
			last_expected = CELL_OFFSET_NIL

		curr_pos = file_offset + 32
		while curr_pos < file_offset + hbin_size:
			try:
				curr_cell = HiveCell(file_object, curr_pos, use_old_cell_format)
			except HiveCellException:
				if tolerate_cell_errors:
					break
				else:
					raise

			cell_absolute_size = curr_cell.get_absolute_size()
			if curr_pos + cell_absolute_size <= file_offset + hbin_size:
				self.cells.append(curr_cell)
			else:
				exception = HiveCellException('Cell is too large for this hive bin (exceeding its boundary)')
				if tolerate_cell_errors:
					break
				else:
					raise exception

			if use_old_cell_format:
				last = curr_cell.get_last()
				if last != last_expected:
					exception = HiveCellException('Last pointer mismatch: {} != {}'.format(last, last_expected))
					if not tolerate_cell_errors:
						raise exception

				last_expected = curr_pos - file_offset

			curr_pos += cell_absolute_size

	def get_signature(self):
		return self.read_binary(0, 4)

	def get_offset(self):
		return self.read_uint32(4)

	def get_size(self):
		return self.read_uint32(8)

	def get_reserved(self):
		return self.read_binary(12, 8)

	def get_timestamp(self):
		return self.read_uint64(20)

	def get_spare(self):
		return self.read_uint32(28)

	def get_memalloc(self):
		return self.read_uint32(28) # The same offset as in the previous field.

class HiveCell(RegistryFile):
	"""This is a class for a hive cell, it provides methods to deal with the hive cell.
	Most methods are self-explanatory.
	"""

	def __init__(self, file_object, file_offset, use_old_cell_format = False):
		super(HiveCell, self).__init__(file_object, file_offset)

		self.use_old_cell_format = use_old_cell_format

		try:
			cell_absolute_size = self.get_absolute_size()
		except ReadException:
			cell_absolute_size = None

		if not self.use_old_cell_format:
			cell_alignment = 8
		else:
			cell_alignment = 16

		if cell_absolute_size is None:
			raise HiveCellException('Unknown cell size')

		if cell_absolute_size < cell_alignment or cell_absolute_size % cell_alignment != 0:
			raise HiveCellException('Invalid cell size (absolute): {}'.format(cell_absolute_size))

	def get_size(self):
		return self.read_int32(0)

	def get_absolute_size(self):
		return abs(self.get_size())

	def is_allocated(self):
		return self.get_size() < 0

	def get_last(self):
		"""When the old cell format is used, return the last pointer (an offset to a previous cell in a current hive bin)."""

		if not self.use_old_cell_format:
			return

		return self.read_uint32(4)

	def get_cell_data(self):
		if not self.use_old_cell_format:
			cell_data_offset = 4
		else:
			cell_data_offset = 8

		return self.read_binary(cell_data_offset, self.get_absolute_size() - cell_data_offset)

class DirtyVector(RegistryFile):
	"""This is a class for a dirty vector, it provides methods to read the dirty vector and to map dirty pages."""

	bitmap = None
	"""Contents of a bitmap."""

	def __init__(self, file_object, file_offset, hbins_data_size):
		super(DirtyVector, self).__init__(file_object, file_offset)

		signature = self.get_signature()
		if signature != b'DIRT':
			raise DirtyVectorException('Invalid signature: {}'.format(signature))

		self.vector_length = hbins_data_size // 4096
		self.bitmap = bytearray(self.read_binary(4, self.vector_length))

	def get_signature(self):
		return self.read_binary(0, 4)

	def dirty_pages_meta(self):
		"""This method yields DirtyPageMeta tuples."""

		bit_pos = 0
		i = 0

		while bit_pos < self.vector_length * 8:
			is_bit_set = ((self.bitmap[bit_pos // 8] >> (bit_pos % 8)) & 1) != 0
			if is_bit_set:
				dirty_page_meta = DirtyPageMeta(relative_offset_primary = bit_pos * 512, relative_offset_log = i * 512)
				yield dirty_page_meta
				i += 1

			bit_pos += 1

class DirtyPage(RegistryFile):
	"""This is a class for a dirty page, describing its location and bytes (data)."""

	primary_file_offset = None
	log_file_offset = None
	page_size = None

	def __init__(self, file_object, log_file_offset, page_size, primary_file_offset):
		super(DirtyPage, self).__init__(file_object, log_file_offset)

		self.page_size = page_size
		self.primary_file_offset = primary_file_offset
		self.log_file_offset = log_file_offset

	def get_bytes(self):
		bytes_ = self.read_binary(0, self.page_size)
		if len(bytes_) != self.page_size:
			raise DirtyPageException('Truncated dirty page')

		return bytes_

class OldLogFile(object):
	"""This is a class for a transaction log file (old format)."""

	baseblock = None
	"""A base block in a log file (a BaseBlock object)."""

	dirtyvector = None
	"""A dirty vector in a log file (a DirtyVector object)."""

	def __init__(self, file_object):
		self.file_object = file_object

		self.baseblock = BaseBlock(self.file_object)

		if self.baseblock.get_file_type() != FILE_TYPE_LOG_OLD and self.baseblock.get_file_type() != FILE_TYPE_LOG_VERYOLD:
			raise BaseBlockException('Invalid file type')

		if self.baseblock.is_file_dirty:
			raise BaseBlockException('Dirty state')

		file_size = self.baseblock.get_file_size()
		if file_size < self.get_dirty_pages_starting_offset() + 512: # Check if at least one dirty page (512 bytes) can be present in the file.
			raise FileSizeException('Invalid file size: {}'.format(file_size))

		self.dirtyvector = DirtyVector(self.file_object, BASE_BLOCK_LENGTH_LOG, self.baseblock.effective_hbins_data_size)

	def get_dirty_pages_starting_offset(self):
		offset_unaligned = BASE_BLOCK_LENGTH_LOG + len(b'DIRT') + self.baseblock.effective_hbins_data_size // 4096
		sector_size = 512 # We do not expect other values (even when the sector size is not 512 bytes).

		if offset_unaligned % sector_size == 0:
			offset_aligned = offset_unaligned
		else:
			offset_aligned = offset_unaligned + sector_size - offset_unaligned % sector_size

		return offset_aligned

	def dirty_pages(self):
		"""This method yields DirtyPage objects."""

		log_file_base = self.get_dirty_pages_starting_offset()
		primary_file_base = BASE_BLOCK_LENGTH_PRIMARY

		for dirty_page_meta in self.dirtyvector.dirty_pages_meta():
			log_file_offset = dirty_page_meta.relative_offset_log + log_file_base
			primary_file_offset = dirty_page_meta.relative_offset_primary + primary_file_base

			dirty_page = DirtyPage(self.file_object, log_file_offset, 512, primary_file_offset)
			yield dirty_page

	def get_remnant_data(self, is_unused_log_file = False):
		"""This method returns remnant data."""

		remnant_data_start = self.get_dirty_pages_starting_offset()
		if not is_unused_log_file:
			for dirty_page in self.dirty_pages():
				try:
					b_ = dirty_page.get_bytes()
				except DirtyPageException:
					break

				remnant_data_start = dirty_page.log_file_offset + dirty_page.page_size

		self.file_object.seek(remnant_data_start)
		remnant_data = self.file_object.read()
		return remnant_data

class LogEntry(RegistryFile):
	"""This is a class for a log entry, it provides methods to read dirty pages references and to map dirty pages.
	Most methods are self-explanatory.
	"""

	def __init__(self, file_object, file_offset, expected_sequence_number):
		super(LogEntry, self).__init__(file_object, file_offset)

		signature = self.get_signature()
		if signature != b'HvLE':
			raise LogEntryException('Invalid signature: {}'.format(signature))

		size = self.get_size()
		if size < 512 or size % 512 != 0:
			raise LogEntryException('Invalid size: {}'.format(size))

		hbins_data_size = self.get_hbins_data_size()
		if hbins_data_size < HIVE_BIN_SIZE_ALIGNMENT or hbins_data_size % HIVE_BIN_SIZE_ALIGNMENT != 0:
			raise LogEntryException('Invalid hive bins data size: {}'.format(hbins_data_size))

		dirty_pages_count = self.get_dirty_pages_count()
		if dirty_pages_count == 0:
			raise LogEntryException('Invalid dirty pages count: {}'.format(dirty_pages_count))

		if not self.validate_hashes():
			raise LogEntryException('Invalid hashes')

		sequence_number = self.get_sequence_number()
		if sequence_number != expected_sequence_number:
			raise LogEntryException('Unexpected sequence number: {} != {}'.format(sequence_number, expected_sequence_number))

	def get_signature(self):
		return self.read_binary(0, 4)

	def get_size(self):
		return self.read_uint32(4)

	def get_flags(self):
		return self.read_uint32(8)

	def get_sequence_number(self):
		return self.read_uint32(12)

	def get_hbins_data_size(self):
		return self.read_uint32(16)

	def get_dirty_pages_count(self):
		return self.read_uint32(20)

	def get_hash_1(self):
		return self.read_uint64(24)

	def get_hash_2(self):
		return self.read_uint64(32)

	def calculate_hash_1(self):
		b = bytearray(self.read_binary(40, self.get_size() - 40))
		return Marvin32(b)

	def calculate_hash_2(self):
		b = bytearray(self.read_binary(0, 32))
		return Marvin32(b)

	def validate_hashes(self):
		"""Compare calculated hashes to hashes recorded in a log entry."""

		return self.get_hash_2() == self.calculate_hash_2() and self.get_hash_1() == self.calculate_hash_1()

	def get_dirty_pages_starting_offset(self):
		return 40 + self.get_dirty_pages_count() * 8

	def dirty_pages_references(self):
		"""This method yields DirtyPageReference tuples."""

		curr_pos = 40
		i = 0
		while i < self.get_dirty_pages_count():
			primary_file_offset_relative = self.read_uint32(curr_pos)
			page_size = self.read_uint32(curr_pos + 4)

			dirty_page_reference = DirtyPageReference(relative_offset_primary = primary_file_offset_relative, size = page_size)
			yield dirty_page_reference

			curr_pos += 8
			i += 1

	def dirty_pages(self):
		"""This method yields DirtyPage objects."""

		log_file_base = self.file_offset + self.get_dirty_pages_starting_offset()
		primary_file_base = BASE_BLOCK_LENGTH_PRIMARY

		delta = 0
		for dirty_page_reference in self.dirty_pages_references():
			primary_file_offset = dirty_page_reference.relative_offset_primary + primary_file_base
			page_size = dirty_page_reference.size

			log_file_offset = log_file_base + delta

			dirty_page = DirtyPage(self.file_object, log_file_offset, page_size, primary_file_offset)
			yield dirty_page

			delta += page_size

class NewLogFile(object):
	"""This is a class for a transaction log file (new format)."""

	baseblock = None
	"""A base block in a log file (a BaseBlock object)."""

	def __init__(self, file_object):
		self.file_object = file_object

		self.baseblock = BaseBlock(self.file_object)

		if self.baseblock.get_file_type() != FILE_TYPE_LOG_NEW:
			raise BaseBlockException('Invalid file type')

		if self.baseblock.is_file_dirty:
			raise BaseBlockException('Dirty state')

		self.file_size = self.baseblock.get_file_size()
		if self.file_size <= BASE_BLOCK_LENGTH_LOG + 40: # Check if at least one log entry can be present in the file.
			raise FileSizeException('Invalid file size: {}'.format(self.file_size))

		self.remnant_data_start = None

	def log_entries(self):
		"""This method yields LogEntry objects."""

		current_sequence_number = self.baseblock.get_primary_sequence_number()

		curr_pos = BASE_BLOCK_LENGTH_LOG
		while curr_pos < self.file_size:
			try:
				curr_logentry = LogEntry(self.file_object, curr_pos, current_sequence_number)
			except (LogEntryException, ReadException):
				break # We could read garbage at the end of the file, this is normal.

			yield curr_logentry

			curr_pos += curr_logentry.get_size()
			current_sequence_number = c_uint32(current_sequence_number + 1).value # Handle a possible overflow.

		self.remnant_data_start = curr_pos

	def get_remnant_data_pos(self, is_unused_log_file = False):
		"""This method returns the effective starting position of remnant data."""

		if not is_unused_log_file:
			if self.remnant_data_start is None:
				for log_entry in self.log_entries():
					pass

			return self.remnant_data_start
		else:
			return BASE_BLOCK_LENGTH_LOG

	def get_remnant_data(self, is_unused_log_file = False):
		"""This method returns remnant data."""

		remnant_data_start = self.get_remnant_data_pos(is_unused_log_file)

		self.file_object.seek(remnant_data_start)
		remnant_data = self.file_object.read()
		return remnant_data

	def remnant_log_entries(self, is_unused_log_file = False):
		"""This method yields LogEntry objects for remnant (but valid) log entries (if any)."""

		def parse_log_entry_header(buf):
			if len(buf) < 40:
				return (False, None)

			signature = buf[ : 4 ]
			if signature != b'HvLE':
				return (False, None)

			sequence_number_bytes = buf[ 12 : 16 ]
			sequence_number = unpack('<L', sequence_number_bytes)[0]

			return (True, sequence_number)

		curr_pos = self.get_remnant_data_pos(is_unused_log_file)
		while curr_pos < self.file_size:
			self.file_object.seek(curr_pos)
			buf = self.file_object.read(40)

			is_logentry, sequence_number = parse_log_entry_header(buf)
			if is_logentry:
				try:
					curr_logentry = LogEntry(self.file_object, curr_pos, sequence_number)
				except LogEntryException:
					pass
				except ReadException:
					break
				else:
					yield curr_logentry

					curr_pos += curr_logentry.get_size()
					continue

			curr_pos += 512

	def list_remnant_log_entries(self, is_unused_log_file = False):
		"""This method returns a sorted list of sequence numbers for remnant (but valid) log entries."""

		sequence_numbers = []

		for log_entry in self.remnant_log_entries(is_unused_log_file):
			sequence_numbers.append(log_entry.get_sequence_number())

		return sorted(sequence_numbers)

	def rebuild_primary_file_using_remnant_log_entries(self, is_unused_log_file = False, stop_after_sequence_number = None):
		"""This method rebuilds a truncated primary file using remnant (but valid) log entries, returns the BytesIO object with rebuilt data (or None).
		When 'stop_after_sequence_number' is not None, stop after applying a log entry with a specified sequence number.
		"""

		remnant_log_entries = dict()
		hbins_data_size_max = None

		for log_entry in self.remnant_log_entries(is_unused_log_file):
			sequence_number = log_entry.get_sequence_number()
			remnant_log_entries[sequence_number] = log_entry

			hbins_data_size = log_entry.get_hbins_data_size()
			if hbins_data_size_max is None or hbins_data_size_max < hbins_data_size:
				hbins_data_size_max = hbins_data_size

		if len(remnant_log_entries.keys()) == 0:
			return

		effective_version = self.baseblock.effective_version
		effective_root_cell_offset = self.baseblock.effective_root_cell_offset

		allocation_size = BASE_BLOCK_LENGTH_PRIMARY + hbins_data_size_max

		# Create a new file object using the calculated allocation size.
		truncated_primary_file_object = BytesIO(b'\x00' * allocation_size)

		# Create and fill a base block.
		reg_file = RegistryFile(truncated_primary_file_object)

		reg_file.write_binary(0, b'regf')
		reg_file.write_uint32(4, 1)
		reg_file.write_uint32(8, 1)
		reg_file.write_uint64(12, 0)
		reg_file.write_uint32(20, 1)
		reg_file.write_uint32(24, effective_version)
		reg_file.write_uint32(28, FILE_TYPE_PRIMARY)
		reg_file.write_uint32(32, FILE_FORMAT_DIRECT_MEMORY_LOAD)
		reg_file.write_uint32(36, effective_root_cell_offset)
		reg_file.write_uint32(40, hbins_data_size_max)
		reg_file.write_uint32(44, FILE_CLUSTERING_FACTOR)
		reg_file.write_binary(508, b'INVL')

		# Apply dirty pages from remnant log entries.
		for sequence_number in sorted(remnant_log_entries.keys()):
			log_entry = remnant_log_entries[sequence_number]

			# Update the sequence numbers.
			reg_file.write_uint32(4, sequence_number)
			reg_file.write_uint32(8, sequence_number)

			for dirty_page in log_entry.dirty_pages():
				# Update the hive bins data.
				try:
					dirty_page_bytes = dirty_page.get_bytes()
				except DirtyPageException:
					break # We do not want to break the outer loop.

				reg_file.write_binary(dirty_page.primary_file_offset, dirty_page_bytes)

			if stop_after_sequence_number is not None and sequence_number >= stop_after_sequence_number:
				break

		return truncated_primary_file_object

class PrimaryFile(object):
	"""This is a class for a primary file, it provides methods to read the file, to build the maps of cells, and to recover the file using a transaction log."""

	file = None
	"""A RegistryFile object for a primary file."""

	baseblock = None
	"""A base block in a primary file (a BaseBlock object)."""

	cell_map_allocated = None
	"""A map of allocated cells."""

	cell_map_unallocated = None
	"""A map of unallocated cells."""

	record_referenced_cells = False
	"""When True, the get_cell() method will add a requested cell to a map of allocated and referenced cells."""

	cell_map_referenced = None
	"""A map of allocated and referenced cells (empty by default)."""

	cell_map_free = None
	"""A map of free (unallocated, unreferenced) cells (empty by default, see the build_map_free() method)."""

	def __init__(self, file_object, tolerate_minor_errors = True):
		self.file_object = file_object
		self.writable = False
		self.file = RegistryFile(file_object)
		self.tolerate_minor_errors = tolerate_minor_errors

		self.old_log_file = None
		self.new_log_file = None
		self.log_apply_count = 0
		self.last_sequence_number = None

		self.baseblock = BaseBlock(self.file_object)
		if not self.baseblock.is_primary_file:
			raise NotSupportedException('Invalid file type')

		self.build_cell_maps()

	def hive_bins(self):
		"""This method yields HiveBin objects."""

		curr_pos = BASE_BLOCK_LENGTH_PRIMARY
		while curr_pos - BASE_BLOCK_LENGTH_PRIMARY < self.baseblock.effective_hbins_data_size:
			try:
				curr_hivebin = HiveBin(self.file_object, curr_pos, self.tolerate_minor_errors, self.baseblock.use_old_cell_format)
			except (HiveBinException, ReadException):
				if self.baseblock.is_file_dirty and self.log_apply_count == 0:
					# We could read garbage at the end of the dirty file, this is normal.
					self.baseblock.effective_hbins_data_size = curr_pos - BASE_BLOCK_LENGTH_PRIMARY
					break
				else:
					raise # If the file is not dirty (or we recovered the data), this is a serious error.

			yield curr_hivebin

			curr_pos += curr_hivebin.get_size()

	def build_cell_maps(self):
		"""Build the maps of allocated and unallocated cells, clear other maps."""

		self.cell_map_allocated = set()
		self.cell_map_unallocated = set()

		for hbin in self.hive_bins():
			for cell in hbin.cells:
				cell_file_offset = cell.file_offset
				if cell.is_allocated():
					self.cell_map_allocated.add(cell_file_offset)
				else:
					self.cell_map_unallocated.add(cell_file_offset)

		self.cell_map_free = set()
		self.cell_map_referenced = set()

	def build_map_free(self):
		"""Build the map of free cells."""

		self.cell_map_free = set()

		if len(self.cell_map_referenced) > 0:
			self.cell_map_free = self.cell_map_allocated - self.cell_map_referenced

		self.cell_map_free.update(self.cell_map_unallocated)

	def get_root_cell(self):
		"""Get and return data from a root cell."""

		return self.get_cell(self.baseblock.effective_root_cell_offset)

	def get_cell(self, cell_relative_offset):
		"""Get and return data from a cell. The cell must be in the map of allocated cells."""

		if cell_relative_offset == CELL_OFFSET_NIL:
			raise CellOffsetException('Got CELL_OFFSET_NIL')

		cell_file_offset = BASE_BLOCK_LENGTH_PRIMARY + cell_relative_offset
		if len(self.cell_map_allocated) > 0 and cell_file_offset not in self.cell_map_allocated:
			raise CellOffsetException('There is no valid cell starting at this offset (relative): {}'.format(cell_relative_offset))

		if self.record_referenced_cells:
			self.cell_map_referenced.add(cell_file_offset)

		cell = HiveCell(self.file_object, cell_file_offset, self.baseblock.use_old_cell_format)
		return cell.get_cell_data()

	def get_cell_naive(self, cell_relative_offset):
		"""Get and return data from a cell naively."""

		if cell_relative_offset == CELL_OFFSET_NIL:
			raise CellOffsetException('Got CELL_OFFSET_NIL')

		cell_file_offset = BASE_BLOCK_LENGTH_PRIMARY + cell_relative_offset

		cell = HiveCell(self.file_object, cell_file_offset, self.baseblock.use_old_cell_format)

		size = cell.get_absolute_size()
		if size > CELL_SIZE_MAX_NAIVE:
			raise CellOffsetException('Got an obviously invalid offset (relative)')

		return cell.get_cell_data()

	def create_writable_file_object(self):
		"""Create a writable copy of a file object (used to recover a primary file)."""

		if self.writable:
			return

		new_file_object = BytesIO()

		# Copy data to the new writable file object.
		self.file_object.seek(0)
		copyfileobj(self.file_object, new_file_object)

		self.original_file_object = self.file_object
		self.file_object = new_file_object
		self.file = RegistryFile(self.file_object)

		self.writable = True

	def discard_writable_file_object(self):
		"""Discard a writable copy of a file object."""

		if not self.writable:
			return

		self.file_object.close()
		self.file_object = self.original_file_object
		self.__init__(self.file_object, self.tolerate_minor_errors)

	def save_recovered_hive(self, filepath):
		"""Save the recovered hive to a new primary file (using its path)."""

		if self.log_apply_count == 0:
			raise NotSupportedException('Cannot save a hive that was not recovered')

		if self.baseblock.is_baseblock_valid:
			# The base block is valid, use it.
			self.file_object.seek(0)
			baseblock_bytes = self.file_object.read(BASE_BLOCK_LENGTH_PRIMARY)
		else:
			# The base block is invalid, use another one from a transaction log file.
			if self.old_log_file is not None:
				self.old_log_file.file_object.seek(0)
				baseblock_bytes = self.old_log_file.file_object.read(BASE_BLOCK_LENGTH_LOG)
			elif self.new_log_file is not None:
				self.new_log_file.file_object.seek(0)
				baseblock_bytes = self.new_log_file.file_object.read(BASE_BLOCK_LENGTH_LOG)
			else:
				raise NotSupportedException('Cannot find a log file to be used to recover the base block')

		# Create a file object for the base block.
		baseblock_object = BytesIO(b'\x00' * BASE_BLOCK_LENGTH_PRIMARY)

		# Write the base block to the new file object.
		baseblock_object.seek(0)
		baseblock_object.write(baseblock_bytes)

		# Create a new BaseBlock object.
		baseblock = BaseBlock(baseblock_object, True)

		# Update various fields in the base block.
		if self.last_sequence_number is not None:
			baseblock.write_synchronized_sequence_numbers(self.last_sequence_number)
		else:
			baseblock.write_synchronized_sequence_numbers(baseblock.get_primary_sequence_number())

		baseblock.write_hbins_data_size(self.baseblock.effective_hbins_data_size)
		baseblock.write_flags(self.baseblock.effective_flags)
		baseblock.write_file_type(FILE_TYPE_PRIMARY)
		baseblock.update_checksum()

		with open(filepath, 'wb') as f:
			# Copy the old base block and the recovered hive bins data to a file.
			self.file_object.seek(0)
			copyfileobj(self.file_object, f)

			# Copy the new base block over the old one.
			baseblock_object.seek(0)
			f.seek(0)
			f.write(baseblock_object.read())

		# Close the file object.
		baseblock_object.close()

	def apply_old_log_file(self, log_file_object):
		"""Apply a transaction log file (old format) to a primary file."""

		if self.log_apply_count > 0:
			raise RecoveryException('A log file has been already applied')

		if not self.baseblock.is_file_dirty:
			raise RecoveryException('There is no need to apply the log file')

		self.old_log_file = OldLogFile(log_file_object)
		log_timestamp = self.old_log_file.baseblock.effective_last_written_timestamp
		primary_timestamp = self.baseblock.effective_last_written_timestamp

		if log_timestamp < primary_timestamp:
			raise NotEligibleException('This log file cannot be applied')

		self.baseblock.effective_hbins_data_size = self.old_log_file.baseblock.effective_hbins_data_size
		self.baseblock.effective_root_cell_offset = self.old_log_file.baseblock.effective_root_cell_offset
		self.baseblock.effective_version = self.old_log_file.baseblock.effective_version
		self.baseblock.use_old_cell_format = self.baseblock.effective_version in MINOR_VERSION_NUMBERS_FOR_OLD_CELL_FORMAT
		self.baseblock.effective_last_reorganized_timestamp = self.old_log_file.baseblock.effective_last_reorganized_timestamp
		self.baseblock.effective_last_written_timestamp = self.old_log_file.baseblock.effective_last_written_timestamp
		self.baseblock.effective_flags = self.old_log_file.baseblock.effective_flags

		self.create_writable_file_object()

		for dirty_page in self.old_log_file.dirty_pages(): # Apply dirty pages.
			self.file.write_binary(dirty_page.primary_file_offset, dirty_page.get_bytes())

		self.log_apply_count += 1
		self.build_cell_maps()

	def apply_new_log_file(self, log_file_object, callback = None):
		"""Apply a single transaction log file (new format) to a primary file.
		After a log entry has been applied, call an optional callback function.
		"""

		if self.log_apply_count >= 2:
			raise RecoveryException('No more than two log files can be applied')

		if not self.baseblock.is_file_dirty:
			raise RecoveryException('There is no need to apply the log file')

		self.new_log_file = NewLogFile(log_file_object)

		if self.last_sequence_number is not None and self.last_sequence_number >= self.new_log_file.baseblock.get_primary_sequence_number():
			raise RecoveryException('This log file cannot be applied')

		if self.baseblock.is_baseblock_valid and self.new_log_file.baseblock.get_primary_sequence_number() < self.baseblock.get_secondary_sequence_number():
			raise NotEligibleException('This log file cannot be applied')

		self.baseblock.effective_root_cell_offset = self.new_log_file.baseblock.effective_root_cell_offset
		self.baseblock.effective_version = self.new_log_file.baseblock.effective_version
		self.baseblock.use_old_cell_format = self.baseblock.effective_version in MINOR_VERSION_NUMBERS_FOR_OLD_CELL_FORMAT
		self.baseblock.effective_last_reorganized_timestamp = self.new_log_file.baseblock.effective_last_reorganized_timestamp
		self.baseblock.effective_last_written_timestamp = self.new_log_file.baseblock.effective_last_written_timestamp
		self.baseblock.effective_flags = self.new_log_file.baseblock.effective_flags

		self.create_writable_file_object()

		for log_entry in self.new_log_file.log_entries():
			self.last_sequence_number = log_entry.get_sequence_number()
			self.baseblock.effective_flags = LogEntryFlagsToBaseBlockFlags(log_entry.get_flags(), self.baseblock.effective_flags)
			self.baseblock.effective_hbins_data_size = log_entry.get_hbins_data_size()

			for dirty_page in log_entry.dirty_pages(): # Apply dirty pages.
				self.file.write_binary(dirty_page.primary_file_offset, dirty_page.get_bytes())

			if callback is not None:
				self.build_cell_maps()
				callback()

		self.log_apply_count += 1

		if callback is None:
			self.build_cell_maps()

	def apply_new_log_files(self, log_file_object_1, log_file_object_2, callback = None):
		"""Apply two transaction log files (new format) to a primary file.
		After a log entry has been applied, call an optional callback function.
		This method returns a list of transaction log files (file objects) applied.
		"""

		def is_starting_log(this_sequence_number, another_sequence_number):
			if this_sequence_number >= another_sequence_number:
				delta = this_sequence_number - another_sequence_number
				starting = False
			else:
				delta = another_sequence_number - this_sequence_number
				starting = True

			if c_uint32(delta).value <= 0x7FFFFFFF:
				return starting
			else:
				return not starting # Sequence numbers did overflow.


		new_log_file_1 = NewLogFile(log_file_object_1)
		sequence_number_1 = new_log_file_1.baseblock.get_primary_sequence_number()

		new_log_file_2 = NewLogFile(log_file_object_2)
		sequence_number_2 = new_log_file_2.baseblock.get_primary_sequence_number()

		if is_starting_log(sequence_number_1, sequence_number_2):
			first = log_file_object_1
			second = log_file_object_2
			second_baseblock = new_log_file_2.baseblock
		else:
			first = log_file_object_2
			second = log_file_object_1
			second_baseblock = new_log_file_1.baseblock

		if self.baseblock.is_baseblock_valid:
			try:
				self.apply_new_log_file(first, callback)
			except NotEligibleException:
				self.apply_new_log_file(second, callback)
				return [second]
			else:
				if self.last_sequence_number is not None and second_baseblock.get_primary_sequence_number() == c_uint32(self.last_sequence_number + 1).value:
					self.apply_new_log_file(second, callback)
					return [first, second]

				return [first]
		else:
			self.apply_new_log_file(second, callback) # This is how Windows works.
			return [second]

class PrimaryFileTruncated(object):
	"""This is a class for a truncated primary file, it provides methods to read the truncated file, to build the maps of cells, and to yield each cell.
	This class should be used as a replacement for the PrimaryFile class.
	"""

	file = None
	"""A RegistryFile object for a primary file."""

	baseblock = None
	"""A base block in a primary file (a BaseBlock object)."""

	cell_map_allocated = None
	"""A map of allocated cells."""

	cell_map_unallocated = None
	"""A map of unallocated cells."""

	cell_map_free = None
	"""A map of free (unallocated only) cells."""

	def __init__(self, file_object):
		self.file_object = file_object
		self.writable = False
		self.file = RegistryFile(file_object)

		self.baseblock = BaseBlock(self.file_object)
		if not self.baseblock.is_primary_file:
			raise NotSupportedException('Invalid file type')

		self.build_cell_maps()

	def hive_bins(self):
		"""This method yields HiveBin objects."""

		curr_pos = BASE_BLOCK_LENGTH_PRIMARY
		while curr_pos - BASE_BLOCK_LENGTH_PRIMARY < self.baseblock.effective_hbins_data_size:
			try:
				curr_hivebin = HiveBin(self.file_object, curr_pos, True, self.baseblock.use_old_cell_format)
			except (HiveBinException, ReadException):
				break # Since we expect a truncation point, stop here.

			yield curr_hivebin

			curr_pos += curr_hivebin.get_size()

	def build_cell_maps(self):
		"""Build the maps of allocated and unallocated cells."""

		self.cell_map_allocated = set()
		self.cell_map_unallocated = set()

		for hbin in self.hive_bins():
			for cell in hbin.cells:
				cell_file_offset = cell.file_offset
				if cell.is_allocated():
					self.cell_map_allocated.add(cell_file_offset)
				else:
					self.cell_map_unallocated.add(cell_file_offset)

		self.cell_map_free = self.cell_map_unallocated
		self.cell_map_referenced = set()

	def get_cell(self, cell_relative_offset):
		"""Get and return data from a cell. The cell must be in the map of allocated cells or in the map of unallocated cells."""

		if cell_relative_offset == CELL_OFFSET_NIL:
			raise CellOffsetException('Got CELL_OFFSET_NIL')

		cell_file_offset = BASE_BLOCK_LENGTH_PRIMARY + cell_relative_offset
		if cell_file_offset not in self.cell_map_allocated and cell_file_offset not in self.cell_map_unallocated:
			raise CellOffsetException('There is no valid cell starting at this offset (relative): {}'.format(cell_relative_offset))

		cell = HiveCell(self.file_object, cell_file_offset, self.baseblock.use_old_cell_format)
		return cell.get_cell_data()

	def get_cell_naive(self, cell_relative_offset):
		"""Get and return data from a cell naively."""

		if cell_relative_offset == CELL_OFFSET_NIL:
			raise CellOffsetException('Got CELL_OFFSET_NIL')

		cell_file_offset = BASE_BLOCK_LENGTH_PRIMARY + cell_relative_offset

		cell = HiveCell(self.file_object, cell_file_offset, self.baseblock.use_old_cell_format)

		size = cell.get_absolute_size()
		if size > CELL_SIZE_MAX_NAIVE:
			raise CellOffsetException('Got an obviously invalid offset (relative)')

		return cell.get_cell_data()

	def cells(self, yield_unallocated_cells = False):
		"""This method yields a HiveCell object for each cell."""

		for cell_file_offset in sorted(self.cell_map_allocated):
			cell = HiveCell(self.file_object, cell_file_offset, self.baseblock.use_old_cell_format)
			yield cell

		if yield_unallocated_cells:
			for cell_file_offset in sorted(self.cell_map_unallocated):
				cell = HiveCell(self.file_object, cell_file_offset, self.baseblock.use_old_cell_format)
				yield cell

def FragmentTranslator(file_object, effective_version = 5):
	"""This function is used to translate a hive bins fragment (a set of hive bins as a file object) to a truncated primary file (as a BytesIO object).
	The BytesIO object is then returned.
	"""

	reg_file = RegistryFile(file_object)

	signature = reg_file.read_binary(0, 4)
	if signature != b'hbin':
		raise HiveBinException('Invalid signature: {}'.format(signature))

	base_offset = reg_file.read_uint32(4)
	if base_offset > 0 and base_offset % HIVE_BIN_SIZE_ALIGNMENT != 0:
		raise HiveBinException('Invalid base offset: {}'.format(base_offset))

	fragment_size = reg_file.get_file_size()
	if fragment_size % HIVE_BIN_SIZE_ALIGNMENT == 0:
		fragment_size_aligned = fragment_size
	else:
		fragment_size_aligned = fragment_size + HIVE_BIN_SIZE_ALIGNMENT - fragment_size % HIVE_BIN_SIZE_ALIGNMENT

	allocation_size = BASE_BLOCK_LENGTH_PRIMARY + base_offset + fragment_size_aligned
	truncated_primary_file_object = BytesIO(b'\x00' * allocation_size)

	# Copy the fragment to the right location.
	file_object.seek(0)
	truncated_primary_file_object.seek(BASE_BLOCK_LENGTH_PRIMARY + base_offset)
	buf = file_object.read()
	truncated_primary_file_object.write(buf)

	# Now we need to create a dummy base block.
	reg_file = RegistryFile(truncated_primary_file_object)

	reg_file.write_binary(0, b'regf')
	reg_file.write_uint32(4, 1)
	reg_file.write_uint32(8, 1)
	reg_file.write_uint64(12, 0)
	reg_file.write_uint32(20, 1)
	reg_file.write_uint32(24, effective_version)
	reg_file.write_uint32(28, FILE_TYPE_PRIMARY)
	reg_file.write_uint32(32, FILE_FORMAT_DIRECT_MEMORY_LOAD)
	reg_file.write_uint32(36, CELL_OFFSET_NIL)
	reg_file.write_uint32(40, base_offset + fragment_size_aligned)
	reg_file.write_uint32(44, FILE_CLUSTERING_FACTOR)
	reg_file.write_binary(508, b'INVL')

	# Now we need to create dummy hive bins.
	pos = BASE_BLOCK_LENGTH_PRIMARY
	while pos < BASE_BLOCK_LENGTH_PRIMARY + base_offset:
		reg_file.write_binary(pos, b'hbin')
		reg_file.write_uint32(pos + 4, pos - BASE_BLOCK_LENGTH_PRIMARY)
		reg_file.write_uint32(pos + 8, HIVE_BIN_SIZE_ALIGNMENT)
		reg_file.write_uint32(pos + 32, HIVE_BIN_SIZE_ALIGNMENT - 32)

		if effective_version in MINOR_VERSION_NUMBERS_FOR_OLD_CELL_FORMAT:
			reg_file.write_uint32(pos + 36, CELL_OFFSET_NIL)

		pos += HIVE_BIN_SIZE_ALIGNMENT

	# We are done.
	return truncated_primary_file_object

def FragmentWithMarginTranslator(file_object, margin_size):
	"""This function is used to translate a hive bins fragment with a margin (as a file object) to a new hive bins fragment with that margin rebuilt to a new hive bin (as a BytesIO object).
	The BytesIO object is then returned. The 'margin_size' should be a positive integer (aligned to 8 bytes). The new cell format is assumed.
	"""

	if margin_size < 8 or margin_size % 8 != 0:
		raise ValueError('Invalid margin size')

	reg_file_old = RegistryFile(file_object)

	signature = reg_file_old.read_binary(margin_size, 4)
	if signature != b'hbin':
		raise HiveBinException('Invalid signature: {}'.format(signature))

	base_offset = reg_file_old.read_uint32(margin_size + 4)
	if base_offset > 0 and base_offset % HIVE_BIN_SIZE_ALIGNMENT != 0:
		raise HiveBinException('Invalid base offset: {}'.format(base_offset))

	# Read the margin and the fragment.
	file_object.seek(0)
	margin_buf = file_object.read(margin_size)
	fragment_buf = file_object.read()

	if len(margin_buf) != margin_size:
		raise ValueError('Invalid margin size, expected: {} bytes, read: {} bytes'.format(margin_size, len(margin_buf)))

	margin_size_effective = margin_size + 32 + 8 # The margin, plus the header of a hive bin, plus the smallest dummy cell possible.
	margin_size_effective_aligned = margin_size_effective + HIVE_BIN_SIZE_ALIGNMENT - margin_size_effective % HIVE_BIN_SIZE_ALIGNMENT

	if margin_size_effective_aligned > base_offset:
		raise ValueError('Margin data (aligned) is too large for this base offset: {} < {}'.format(base_offset, margin_size_effective_aligned))

	allocation_size = margin_size_effective_aligned + len(fragment_buf)
	new_fragment_object = BytesIO(b'\x00' * allocation_size)

	# Copy them to the right locations.
	new_fragment_object.seek(margin_size_effective_aligned)
	new_fragment_object.write(fragment_buf)
	new_fragment_object.seek(margin_size_effective_aligned - margin_size)
	new_fragment_object.write(margin_buf)

	reg_file_new = RegistryFile(new_fragment_object)

	# Write a new hive bin with a dummy cell.
	reg_file_new.write_binary(0, b'hbin')
	reg_file_new.write_uint32(4, base_offset - margin_size_effective_aligned)
	reg_file_new.write_uint32(8, margin_size_effective_aligned)
	reg_file_new.write_uint32(32, margin_size_effective_aligned - 32 - margin_size)

	# Write the 'RBLT' signature to the dummy cell.
	reg_file_new.write_binary(36, b'RBLT')

	# We are done.
	return new_fragment_object

def LogEntriesTranslator(file_object, effective_version = 5):
	"""This function is used to translate a fragment consisting of one or more log entries (as a file object) to a dummy transaction log file (as a BytesIO object).
	The BytesIO object is then returned.
	"""

	sector_size = 512

	reg_file = RegistryFile(file_object)

	signature = reg_file.read_binary(0, 4)
	if signature != b'HvLE':
		raise LogEntryException('Invalid signature: {}'.format(signature))

	first_sequence_number = reg_file.read_uint32(12)
	first_hbins_data_size = reg_file.read_uint32(16)

	log_entries_size = reg_file.get_file_size()
	if log_entries_size % sector_size != 0:
		raise LogEntryException('Invalid size: {}'.format(log_entries_size))

	allocation_size = BASE_BLOCK_LENGTH_LOG + log_entries_size
	dummy_log_file_object = BytesIO(b'\x00' * allocation_size)

	# Copy the log entries to the right location.
	file_object.seek(0)
	dummy_log_file_object.seek(BASE_BLOCK_LENGTH_LOG)
	buf = file_object.read()
	dummy_log_file_object.write(buf)

	# Now we need to create a dummy base block.
	reg_file = RegistryFile(dummy_log_file_object)

	reg_file.write_binary(0, b'regf')
	reg_file.write_uint32(4, first_sequence_number)
	reg_file.write_uint32(8, first_sequence_number)
	reg_file.write_uint64(12, 0)
	reg_file.write_uint32(20, 1)
	reg_file.write_uint32(24, effective_version)
	reg_file.write_uint32(28, FILE_TYPE_LOG_NEW)
	reg_file.write_uint32(32, FILE_FORMAT_DIRECT_MEMORY_LOAD)
	reg_file.write_uint32(36, CELL_OFFSET_NIL)
	reg_file.write_uint32(40, first_hbins_data_size)
	reg_file.write_uint32(44, FILE_CLUSTERING_FACTOR)

	# Now we need to update the checksum.
	baseblock = BaseBlock(dummy_log_file_object, True)
	baseblock.update_checksum()

	# We are done.
	return dummy_log_file_object
