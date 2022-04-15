# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module implements an interface to recover deleted keys and values.

from __future__ import unicode_literals

from . import Registry, RegistryFile, RegistryRecords

MAX_PLAUSIBLE_SUBKEYS_COUNT = 10000
MAX_PLAUSIBLE_VALUES_COUNT  = 1000
MAX_PLAUSIBLE_NAME_LENGTH   = 1024
MAX_PLAUSIBLE_NULL_COUNT    = 5

def ValidateKey(Key):
	"""Check whether or not a key looks plausible. If not, an exception is raised."""

	key_name = Key.name()

	if len(key_name) > MAX_PLAUSIBLE_NAME_LENGTH:
		raise Registry.RegistryException('Implausible name length')

	if key_name.count('\x00') > MAX_PLAUSIBLE_NULL_COUNT:
		raise Registry.RegistryException('Implausible name')

	if Registry.unicode_replacement_character in key_name:
		raise Registry.RegistryException('Implausible name')

	if Key.subkeys_count() > MAX_PLAUSIBLE_SUBKEYS_COUNT or Key.key_node.get_volatile_subkeys_count() > MAX_PLAUSIBLE_SUBKEYS_COUNT:
		raise Registry.RegistryException('Implausible number of subkeys reported')

	if Key.values_count() > MAX_PLAUSIBLE_VALUES_COUNT:
		raise Registry.RegistryException('Implausible number of values reported')

	timestamp_year = Key.last_written_timestamp().year
	if timestamp_year < 1970 or timestamp_year > 2100:
		raise Registry.RegistryException('Implausible last written timestamp')

def ValidateValue(Value):
	"""Check whether or not a value looks plausible. If not, an exception is raised."""

	value_name = Value.name()

	if len(value_name) > MAX_PLAUSIBLE_NAME_LENGTH:
		raise Registry.RegistryException('Implausible name length')

	if value_name.count('\x00') > MAX_PLAUSIBLE_NULL_COUNT:
		raise Registry.RegistryException('Implausible name')

	if Registry.unicode_replacement_character in value_name:
		raise Registry.RegistryException('Implausible name')

	if Value.key_value.is_data_inline():
		if Value.key_value.get_data_size_real() > 4:
			raise Registry.RegistryException('Value data is too large to be stored inline')
	else:
		data_offset = Value.key_value.get_data_offset()
		if Value.key_value.get_data_size_real() > 0 and (data_offset < 8 or data_offset % 8 != 0):
			raise Registry.RegistryException('Data offset (relative) is unaligned')

class Scanner(object):
	"""This class is used to scan free cells (and other sources) for deleted keys and values."""

	hive = None
	"""A RegistryHive object."""

	def __init__(self, hive, scan_remnant_data = True, scan_slack_space = True, yield_remnant_bytes = False):
		"""Arguments:
		 - hive: a RegistryHive object;
		 - scan_remnant_data: when True, also scan the remnant data within a primary file;
		 - scan_slack_space: when True, also scan the slack space of cells;
		 - yield_remnant_bytes: when True, yield unknown (unassociated) data (as bytes).
		"""

		self.hive = hive
		self.scan_remnant_data = scan_remnant_data
		self.scan_slack_space = scan_slack_space
		self.yield_remnant_bytes = yield_remnant_bytes

	def virtual_cell(self):
		"""Get and return remnant data within a primary file as a virtual cell (if any, else return None)."""

		if not self.scan_remnant_data:
			return

		offset = RegistryFile.BASE_BLOCK_LENGTH_PRIMARY + self.hive.registry_file.baseblock.effective_hbins_data_size
		self.hive.registry_file.file_object.seek(offset)
		data = self.hive.registry_file.file_object.read()
		if len(data) == 0:
			return

		return data

	def process_cell(self, cell):
		"""Scan data of a cell for deleted keys and values, yield them as RegistryKey, RegistryValue objects, bytes.
		Note: only even offsets will be scanned.
		"""


		def process_bytes(data): # If remnant bytes start with a list, skip it and return further bytes (slack).
			try:
				l = RegistryRecords.IndexLeaf(data)
			except (Registry.RegistryException, UnicodeDecodeError):
				try:
					l = RegistryRecords.FastLeaf(data)
				except (Registry.RegistryException, UnicodeDecodeError):
					try:
						l = RegistryRecords.HashLeaf(data)
					except (Registry.RegistryException, UnicodeDecodeError):
						try:
							l = RegistryRecords.IndexRoot(data)
						except (Registry.RegistryException, UnicodeDecodeError):
							l = None

			if l is not None:
				return l.get_slack()

			return data

		unknown_data_start = 0
		unknown_data_end = 0

		pos = 0
		while pos < len(cell):
			if pos < len(cell) - 76: # A key node with at least one character in the name.
				two_bytes = cell[pos : pos + 2]
				if two_bytes == b'nk':
					candidate_nk = cell[pos : ]
					try:
						key = Registry.RegistryKey(self.hive.registry_file, candidate_nk, None, None, True, True)
						ValidateKey(key)
					except (Registry.RegistryException, UnicodeDecodeError, ValueError, OverflowError):
						pass
					else:
						yield key

						unknown_data_end = pos
						if unknown_data_end > unknown_data_start:
							# Yield unknown (remnant) data before the key node.
							yield process_bytes(cell[unknown_data_start : unknown_data_end])

						pos += 76 + key.key_node.get_key_name_length()
						if pos % 2 != 0:
							pos += 1

						unknown_data_start = pos
						unknown_data_end = pos

						continue

					pos += 2
					unknown_data_end = pos
					continue

			if pos <= len(cell) - 20: # A key value with no name (at least).
				two_bytes = cell[pos : pos + 2]
				if two_bytes == b'vk':
					candidate_vk = cell[pos : ]
					try:
						value = Registry.RegistryValue(self.hive.registry_file, candidate_vk, True)
						ValidateValue(value)
					except (Registry.RegistryException, UnicodeDecodeError):
						pass
					else:
						yield value

						unknown_data_end = pos
						if unknown_data_end > unknown_data_start:
							# Yield unknown (remnant) data before the key value.
							yield process_bytes(cell[unknown_data_start : unknown_data_end])

						pos += 20 + value.key_value.get_value_name_length()
						if pos % 2 != 0:
							pos += 1

						unknown_data_start = pos
						unknown_data_end = pos

						continue

					pos += 2
					unknown_data_end = pos
					continue

			pos += 2
			unknown_data_end = pos

		if pos > 0 and unknown_data_end > unknown_data_start:
			# Yield unknown (remnant) data after the last key node or key value.
			yield process_bytes(cell[unknown_data_start : unknown_data_end])

	def scan(self):
		"""This method yields RegistryKey objects for deleted keys, RegistryValue objects for deleted values, bytes for remnant (unassociated) data.
		A hive is required to have the free map built (or almost nothing will be recovered).
		"""

		for file_offset in sorted(self.hive.registry_file.cell_map_free):
			try:
				cell = self.hive.registry_file.get_cell_naive(file_offset - RegistryFile.BASE_BLOCK_LENGTH_PRIMARY)
			except Registry.RegistryException:
				continue

			for result in self.process_cell(cell):
				if type(result) is bytes and not self.yield_remnant_bytes:
					continue

				yield result

		virtual_cell = self.virtual_cell()
		if virtual_cell is not None:
			for result in self.process_cell(virtual_cell):
				if type(result) is bytes and not self.yield_remnant_bytes:
					continue

				yield result

		if self.scan_slack_space:
			for slack in self.hive.effective_slack:
				if len(slack) % 2 != 0:
					virtual_cell = slack[ 1 : ]
				else:
					virtual_cell = slack

				for result in self.process_cell(virtual_cell):
					if type(result) is bytes and not self.yield_remnant_bytes:
						continue

					yield result
