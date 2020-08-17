# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module implements a low-level interface to parse registry structures (records, entities).

from __future__ import unicode_literals

from struct import unpack
from collections import namedtuple
from .RegistryFile import RegistryException

# Key node flags.
KEY_VOLATILE      = 0x0001
KEY_HIVE_EXIT     = 0x0002
KEY_HIVE_ENTRY    = 0x0004
KEY_NO_DELETE     = 0x0008
KEY_SYM_LINK      = 0x0010
KEY_COMP_NAME     = 0x0020
KEY_PREDEF_HANDLE = 0x0040
KEY_VIRT_SOURCE   = 0x0080
KEY_VIRT_TARGET   = 0x0100
KEY_VIRT_STORE    = 0x0200

# User flags for a key node.
KEY_FLAG_32BIT                = 0x1
KEY_FLAG_REFLECTED            = 0x2
KEY_FLAG_EXEMPT_REFLECTION    = 0x4
KEY_FLAG_OWNERSHIP_REFLECTION = 0x8

# Virtualization control flags for a key node.
REG_KEY_DONT_VIRTUALIZE  = 0x2
REG_KEY_DONT_SILENT_FAIL = 0x4
REG_KEY_RECURSE_FLAG     = 0x8

# Debug flags for a key node.
BREAK_ON_OPEN            = 0x01
BREAK_ON_DELETE          = 0x02
BREAK_ON_SECURITY_CHANGE = 0x04
BREAK_ON_CREATE_SUBKEY   = 0x08
BREAK_ON_DELETE_SUBKEY   = 0x10
BREAK_ON_SET_VALUE       = 0x20
BREAK_ON_DELETE_VALUE    = 0x40
BREAK_ON_KEY_VIRTUALIZE  = 0x80

# Layered key flags.
KEY_IS_TOMBSTONE       = 0x1 # This is a value (not a bit mask).
KEY_IS_SUPERSEDE_LOCAL = 0x2 # This is a value (not a bit mask).
KEY_IS_SUPERSEDE_TREE  = 0x3 # This is a value (not a bit mask).
KEY_INHERIT_CLASS      = 0x80 # This is a bit mask (in our implementation, this is another field in Windows).

# Key value flags.
VALUE_COMP_NAME = 0x0001
VALUE_TOMBSTONE = 0x0002

# Data types for a key value.
REG_NONE                       = 0x00000000
REG_SZ                         = 0x00000001
REG_EXPAND_SZ                  = 0x00000002
REG_BINARY                     = 0x00000003
REG_DWORD                      = 0x00000004
REG_DWORD_LITTLE_ENDIAN        = REG_DWORD
REG_DWORD_BIG_ENDIAN           = 0x00000005
REG_LINK                       = 0x00000006
REG_MULTI_SZ                   = 0x00000007
REG_RESOURCE_LIST              = 0x00000008
REG_FULL_RESOURCE_DESCRIPTOR   = 0x00000009
REG_RESOURCE_REQUIREMENTS_LIST = 0x0000000a
REG_QWORD                      = 0x0000000b
REG_QWORD_LITTLE_ENDIAN        = REG_QWORD

LeafElement = namedtuple('LeafElement', [ 'relative_offset', 'name_hint', 'name_hash' ])

class ParseException(RegistryException):
	"""This exception is raised when a registry record is invalid."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class MemoryBlock(object):
	"""This is a generic class for a memory block (cell data), it provides low-level methods for reading and parsing data.
	All methods are self-explanatory.
	"""

	def __init__(self, buf):
		self.buf = buf

	def read_binary(self, pos, length = None):
		if length is None:
			b = self.buf[pos : ]
			return b

		b = self.buf[pos : pos + length]
		if len(b) != length:
			raise ParseException('Cannot read data (expected: {} bytes, read: {} bytes)'.format(length, len(b)))

		return b

	def read_uint8(self, pos):
		b = self.read_binary(pos, 1)
		return unpack('<B', b)[0]

	def read_uint16(self, pos):
		b = self.read_binary(pos, 2)
		return unpack('<H', b)[0]

	def read_uint32(self, pos):
		b = self.read_binary(pos, 4)
		return unpack('<L', b)[0]

	def read_uint64(self, pos):
		b = self.read_binary(pos, 8)
		return unpack('<Q', b)[0]

	def get_size(self):
		return len(self.buf)

class IndexLeaf(MemoryBlock):
	"""This is a class for an index leaf, it provides methods to read this leaf.
	Most methods are self-explanatory.
	"""

	def __init__(self, buf):
		super(IndexLeaf, self).__init__(buf)

		signature = self.get_signature()
		if signature != b'li':
			raise ParseException('Invalid signature: {}'.format(signature))

		elements_count = self.get_elements_count()
		if elements_count == 0:
			raise ParseException('Empty index leaf')

	def get_signature(self):
		return self.read_binary(0, 2)

	def get_elements_count(self):
		return self.read_uint16(2)

	def elements(self):
		"""This method yields LeafElement tuples."""

		i = 0
		while i < self.get_elements_count():
			leaf_element = LeafElement(relative_offset = self.read_uint32(4 + i * 4), name_hint = None, name_hash = None)
			yield leaf_element
			i += 1

	def get_slack(self):
		return self.read_binary(4 + self.get_elements_count() * 4)

class FastLeaf(MemoryBlock):
	"""This is a class for a fast leaf, it provides methods to read this leaf.
	Most methods are self-explanatory.
	"""

	def __init__(self, buf):
		super(FastLeaf, self).__init__(buf)

		signature = self.get_signature()
		if signature != b'lf':
			raise ParseException('Invalid signature: {}'.format(signature))

		elements_count = self.get_elements_count()
		if elements_count == 0:
			raise ParseException('Empty fast leaf')

	def get_signature(self):
		return self.read_binary(0, 2)

	def get_elements_count(self):
		return self.read_uint16(2)

	def elements(self):
		"""This method yields LeafElement tuples."""

		i = 0
		while i < self.get_elements_count():
			leaf_element = LeafElement(relative_offset = self.read_uint32(4 + i * 8), name_hint = self.read_binary(4 + i * 8 + 4, 4), name_hash = None)
			yield leaf_element
			i += 1

	def get_slack(self):
		return self.read_binary(4 + self.get_elements_count() * 8)

class HashLeaf(MemoryBlock):
	"""This is a class for a hash leaf, it provides methods to read this leaf.
	Most methods are self-explanatory.
	"""

	def __init__(self, buf):
		super(HashLeaf, self).__init__(buf)

		signature = self.get_signature()
		if signature != b'lh':
			raise ParseException('Invalid signature: {}'.format(signature))

		elements_count = self.get_elements_count()
		if elements_count == 0:
			raise ParseException('Empty hash leaf')

	def get_signature(self):
		return self.read_binary(0, 2)

	def get_elements_count(self):
		return self.read_uint16(2)

	def elements(self):
		"""This method yields LeafElement tuples."""

		i = 0
		while i < self.get_elements_count():
			leaf_element = LeafElement(relative_offset = self.read_uint32(4 + i * 8), name_hash = self.read_uint32(4 + i * 8 + 4), name_hint = None)
			yield leaf_element
			i += 1

	def get_slack(self):
		return self.read_binary(4 + self.get_elements_count() * 8)

class IndexRoot(MemoryBlock):
	"""This is a class for an index root, it provides methods to read this list.
	Most methods are self-explanatory.
	"""

	def __init__(self, buf):
		super(IndexRoot, self).__init__(buf)

		signature = self.get_signature()
		if signature != b'ri':
			raise ParseException('Invalid signature: {}'.format(signature))

		elements_count = self.get_elements_count()
		if elements_count == 0:
			raise ParseException('Empty index root')

	def get_signature(self):
		return self.read_binary(0, 2)

	def get_elements_count(self):
		return self.read_uint16(2)

	def elements(self):
		"""This method yields leaf offsets."""

		i = 0
		while i < self.get_elements_count():
			yield self.read_uint32(4 + i * 4)
			i += 1

	def get_slack(self):
		return self.read_binary(4 + self.get_elements_count() * 4)

class KeyNode(MemoryBlock):
	"""This is a class for a key node, it provides methods to access various fields of the key node.
	All methods are self-explanatory.
	"""

	def __init__(self, buf):
		super(KeyNode, self).__init__(buf)

		signature = self.get_signature()
		if signature != b'nk':
			raise ParseException('Invalid signature: {}'.format(signature))

		if self.get_key_name_length() == 0:
			raise ParseException('Empty key name')

	def get_signature(self):
		return self.read_binary(0, 2)

	def get_flags(self):
		return self.read_uint16(2)

	def get_last_written_timestamp(self):
		return self.read_uint64(4)

	def get_spare_1(self):
		return self.read_uint32(12)

	def get_title_index(self):
		return self.read_uint32(12) # The same offset as above.

	def get_access_bits(self):
		return self.read_uint8(12) # The same offset as above.

	def get_layered_key_bit_fields(self):
		return self.read_uint8(13) # The same location as above.

	def get_spare_2(self):
		return self.read_uint16(14) # The same location as above.

	def get_parent(self):
		return self.read_uint32(16)

	def get_subkeys_count(self):
		return self.read_uint32(20)

	def get_volatile_subkeys_count(self):
		return self.read_uint32(24)

	def get_subkeys_list_offset(self):
		return self.read_uint32(28)

	def get_volatile_subkeys_list_offset(self):
		return self.read_uint32(32)

	def get_key_values_count(self):
		return self.read_uint32(36)

	def get_key_values_list_offset(self):
		return self.read_uint32(40)

	def get_key_security_offset(self):
		return self.read_uint32(44)

	def get_classname_offset(self):
		return self.read_uint32(48)

	def get_largest_subkey_name_length(self):
		return self.read_uint16(52)

	def get_virtualization_control_and_user_flags(self):
		return self.read_uint8(54)

	def get_user_flags_old(self):
		return self.get_flags() >> 12

	def get_user_flags_new(self):
		return self.get_virtualization_control_and_user_flags() & 0xF

	def get_virtualization_control_flags(self):
		return self.get_virtualization_control_and_user_flags() >> 4

	def get_debug(self):
		return self.read_uint8(55)

	def get_largest_subkey_classname_length(self):
		return self.read_uint32(56)

	def get_largest_value_name_length(self):
		return self.read_uint32(60)

	def get_largest_value_data_size(self):
		return self.read_uint32(64)

	def get_workvar(self):
		return self.read_uint32(68)

	def get_key_name_length(self):
		return self.read_uint16(72)

	def get_classname_length(self):
		return self.read_uint16(74)

	def get_key_name(self):
		"""Get and return a key name string (as raw bytes)."""

		return self.read_binary(76, self.get_key_name_length())

	def get_slack(self):
		return self.read_binary(76 + self.get_key_name_length())

class KeyValuesList(MemoryBlock):
	"""This is a class for a key values list, it provides methods to read this list."""

	def __init__(self, buf, elements_count):
		super(KeyValuesList, self).__init__(buf)

		self.elements_count = elements_count

	def elements(self):
		"""This method yields key value offsets."""

		i = 0
		while i < self.elements_count:
			yield self.read_uint32(i * 4)
			i += 1

	def remnant_elements(self):
		"""This method yields key value offsets (without any validation) from the slack space."""

		i = self.elements_count
		while i < self.get_size() // 4:
			yield self.read_uint32(i * 4)
			i += 1

	def get_slack(self):
		return self.read_binary(self.elements_count * 4)

class KeyValue(MemoryBlock):
	"""This is a class for a key value, it provides methods to access various fields of the key value.
	Most methods are self-explanatory.
	"""

	def __init__(self, buf):
		super(KeyValue, self).__init__(buf)

		signature = self.get_signature()
		if signature != b'vk':
			raise ParseException('Invalid signature: {}'.format(signature))

	def get_signature(self):
		return self.read_binary(0, 2)

	def get_value_name_length(self):
		return self.read_uint16(2)

	def get_data_size(self):
		return self.read_uint32(4)

	def get_data_size_real(self):
		"""Get and return a real size of data (the most significant bit is ignored)."""

		size = self.get_data_size()
		if size >= 0x80000000:
			size -= 0x80000000

		return size

	def is_data_inline(self):
		"""Return True if data is stored inline (in the data offset field)."""

		return self.get_data_size() >= 0x80000000

	def get_inline_data(self):
		return self.read_binary(8, 4)

	def get_data_offset(self):
		return self.read_uint32(8)

	def get_data_type(self):
		return self.read_uint32(12)

	def get_flags(self):
		return self.read_uint16(16)

	def get_spare(self):
		return self.read_uint16(18)

	def get_title_index(self):
		return self.read_uint32(16) # The same offset as above.

	def get_value_name(self):
		"""Get and return a value name string (as raw bytes)."""

		return self.read_binary(20, self.get_value_name_length())

	def get_slack(self):
		return self.read_binary(20 + self.get_value_name_length())

class KeySecurity(MemoryBlock):
	"""This is a class for a key security item, it provides methods to access various fields of the key security item.
	All methods are self-explanatory.
	"""

	def __init__(self, buf):
		super(KeySecurity, self).__init__(buf)

		signature = self.get_signature()
		if signature != b'sk':
			raise ParseException('Invalid signature: {}'.format(signature))

		security_descriptor_size = self.get_security_descriptor_size()
		if security_descriptor_size == 0:
			raise ParseException('Empty security descriptor')

	def get_signature(self):
		return self.read_binary(0, 2)

	def get_reserved(self):
		return self.read_uint16(2)

	def get_flink(self):
		return self.read_uint32(4)

	def get_blink(self):
		return self.read_uint32(8)

	def get_reference_count(self):
		return self.read_uint32(12)

	def get_security_descriptor_size(self):
		return self.read_uint32(16)

	def get_security_descriptor(self):
		"""Get and return a security descriptor (as raw bytes)."""

		return self.read_binary(20, self.get_security_descriptor_size())

	def get_slack(self):
		return self.read_binary(20 + self.get_security_descriptor_size())

class SegmentsList(MemoryBlock):
	"""This is a class for a segments list (big data), it provides a method to read this list."""

	def __init__(self, buf, elements_count):
		super(SegmentsList, self).__init__(buf)

		self.elements_count = elements_count

	def elements(self):
		"""This method yields segment offsets."""

		i = 0
		while i < self.elements_count:
			yield self.read_uint32(i * 4)
			i += 1

	def get_slack(self):
		return self.read_binary(self.elements_count * 4)

class BigData(MemoryBlock):
	"""This is a class for a big data record, it provides methods to access various fields of the big data record.
	All methods are self-explanatory.
	"""

	def __init__(self, buf):
		super(BigData, self).__init__(buf)

		signature = self.get_signature()
		if signature != b'db':
			raise ParseException('Invalid signature: {}'.format(signature))

		segments_count = self.get_segments_count()
		if segments_count < 2:
			raise ParseException('Invalid number of segments: {}'.format(segments_count))

	def get_signature(self):
		return self.read_binary(0, 2)

	def get_segments_count(self):
		return self.read_uint16(2)

	def get_segments_list_offset(self):
		return self.read_uint32(4)

	def get_slack(self):
		return self.read_binary(8)
