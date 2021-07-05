# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module implements a high-level interface.
# Most users should use this module to work with a registry hive.

from __future__ import unicode_literals, division

from .RegistryFile import RegistryException, BASE_BLOCK_LENGTH_PRIMARY
from . import RegistryFile, RegistryRecords, RegistryUnicode
from struct import unpack
from datetime import datetime, timedelta
from collections import namedtuple

ValueTypes = {
RegistryRecords.REG_NONE: 'REG_NONE',
RegistryRecords.REG_SZ: 'REG_SZ',
RegistryRecords.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
RegistryRecords.REG_BINARY: 'REG_BINARY',
RegistryRecords.REG_DWORD: 'REG_DWORD',
RegistryRecords.REG_DWORD_BIG_ENDIAN: 'REG_DWORD_BIG_ENDIAN',
RegistryRecords.REG_LINK: 'REG_LINK',
RegistryRecords.REG_MULTI_SZ: 'REG_MULTI_SZ',
RegistryRecords.REG_RESOURCE_LIST: 'REG_RESOURCE_LIST',
RegistryRecords.REG_FULL_RESOURCE_DESCRIPTOR: 'REG_FULL_RESOURCE_DESCRIPTOR',
RegistryRecords.REG_RESOURCE_REQUIREMENTS_LIST: 'REG_RESOURCE_REQUIREMENTS_LIST',
RegistryRecords.REG_QWORD: 'REG_QWORD'
}

HiveRoles = {
'SYSTEM': [ ( 'ControlSet001', 'ControlSet002', 'ControlSet003' ), 'Select' ],
'SOFTWARE': [ 'Microsoft', 'Classes', ( 'Secure', 'Policies' ) ],
'NTUSER/DEFAULT': [ 'Software', 'Control Panel', ( 'AppEvents', 'Keyboard Layout' ) ],
'SECURITY': [ 'Policy', 'RXACT' ],
'BCD': [ 'Description', 'Objects' ],
'COMPONENTS': [ 'Installers', 'CanonicalData' ],
'SAM': [ 'SAM' ],
'USRCLASS': [ 'Local Settings' ],
'AMCACHE': [ 'Root' ],
'SYSCACHE': [ 'DefaultObjectStore' ]
}

VALUE_FLAGS = { # This contains only those flags we want to display to a user.
RegistryRecords.VALUE_TOMBSTONE: 'VALUE_TOMBSTONE'
}

KEY_FLAGS = { # This contains only those flags we want to display to a user.
RegistryRecords.KEY_IS_TOMBSTONE: 'IsTombstone',
RegistryRecords.KEY_IS_SUPERSEDE_LOCAL: 'IsSupersedeLocal',
RegistryRecords.KEY_IS_SUPERSEDE_TREE: 'IsSupersedeTree',
}

KEY_FLAG_INHERIT_CLASS = 'InheritClass'
VALUE_FLAG_TOMBSTONE = 'IsTombstone'

AutoRecoveryResult = namedtuple('AutoRecoveryResult', [ 'recovered', 'is_new_log', 'file_objects' ])

class WalkException(RegistryException):
	"""This exception is raised when a walk error has occurred.
	A walk error is a generic error when traversing registry records (entities).
	"""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class AutoRecoveryException(RegistryException):
	"""This exception is raised when a primary file cannot be recovered in the 'auto' mode.
	In particular, when no recovery scheme has been found.
	"""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

def DecodeFiletime(Timestamp):
	"""Decode the FILETIME timestamp and return the datetime object."""

	return datetime(1601, 1, 1) + timedelta(microseconds = Timestamp / 10)

def DecodeUnicode(Buffer, RemoveGarbage = False, StrictDecode = False):
	"""Decode the Unicode (UTF-16LE) string and return it. Surrogate pairs are supported.
	When 'RemoveGarbage' is True, this function will attempt to sanitize a null-terminated Unicode string.
	When 'StrictDecode' is True, illegal characters will not be replaced.
	"""

	if StrictDecode:
		err_resolution = 'strict'
	else:
		err_resolution = 'replace'

	if RemoveGarbage and len(Buffer) > 2:
		# Windows is using null-terminated Unicode strings, so we want to remove garbage, if any, after the end of the string.
		pos = 0
		while pos < len(Buffer):
			two_bytes = Buffer[pos : pos + 2]
			if two_bytes == b'\x00\x00':
				return Buffer[ : pos + 2].decode('utf-16le', errors = err_resolution) # Include the null character to the output string.

			pos += 2

	return Buffer.decode('utf-16le', errors = err_resolution)

unicode_replacement_character = b'\xfd\xff'.decode('utf-16le')

def DecodeASCII(Buffer):
	"""Decode the ASCII (extended) string and return it."""

	return Buffer.decode('latin-1') # This is equal to adding a null byte after each character, and then running .decode('utf-16le').

def DecodeUnicodeMulti(Buffer, RemoveGarbage = False):
	"""Decode the Unicode (UTF-16LE) array of null-terminated strings and return it as is.
	When 'RemoveGarbage' is True, this function will attempt to sanitize a null-terminated Unicode array.
	"""

	if RemoveGarbage and len(Buffer) > 4:
		# We want to remove garbage, if any, after the end of the array (marker: 0x00 0x00 0x00 0x00).
		pos = 0
		while pos < len(Buffer):
			four_bytes = Buffer[pos : pos + 4]
			if four_bytes == b'\x00\x00\x00\x00':
				return DecodeUnicode(Buffer[ : pos + 4]) # Include the null characters to the output string.

			pos += 2

	return DecodeUnicode(Buffer)

def GuessHiveRole(file_object):
	"""Guess the role of a given hive (as a file object), return a string (for example, 'SYSTEM') or None.
	For a list of known hive roles, see the keys of the 'HiveRoles' dictionary.
	"""

	def collect_keys_normal(file_object):
		keys = []

		hive = RegistryHive(file_object)
		for subkey in hive.root_key().subkeys():
			keys.append(subkey.name().upper())

		return keys

	def collect_keys_truncated(file_object):
		keys = []

		hive = RegistryHiveTruncated(file_object)
		for item in hive.scan():
			if type(item) is not RegistryKey:
				continue

			key = item
			try:
				parent = key.parent()
				if parent is not None:
					if parent.parent() is None:
						keys.append(key.name().upper())
			except RegistryException:
				pass

		return keys

	try:
		keys = collect_keys_normal(file_object)
	except RegistryException:
		try:
			keys = collect_keys_truncated(file_object)
		except RegistryException:
			return

	if len(keys) == 0:
		return

	for hive_role in HiveRoles.keys():
		signs = HiveRoles[hive_role]
		matches = 0

		for sign in signs:
			if type(sign) is tuple:
				for sign_i in sign:
					if sign_i.upper() in keys:
						matches += 1
						break
			else:
				if sign.upper() in keys:
					matches += 1

		if len(signs) == matches:
			# Found a match.
			return hive_role

class RegistryHive(object):
	"""This is a high-level class for a registry hive."""

	registry_file = None
	"""A primary file of a hive (a RegistryFile.PrimaryFile object)."""

	log_entry_callback = None
	"""A callback function executed when a log entry has been applied."""

	effective_slack = None
	"""A set of data strings from different slack space locations to be used in the deleted data recovery."""

	def __init__(self, file_object, tolerate_minor_errors = True):
		self.registry_file = RegistryFile.PrimaryFile(file_object, tolerate_minor_errors)
		self.tolerate_minor_errors = tolerate_minor_errors
		self.effective_slack = set()

	def root_key(self):
		"""Get and return a root key node (a RegistryKey object)."""

		return RegistryKey(self.registry_file, self.registry_file.get_root_cell(), 0, self.registry_file.baseblock.effective_root_cell_offset, self.tolerate_minor_errors)

	def last_written_timestamp(self):
		"""Get, decode and return a last written timestamp (a datetime object)."""

		return DecodeFiletime(self.registry_file.baseblock.effective_last_written_timestamp)

	def last_reorganized_timestamp(self):
		"""Get, decode and return a last reorganized timestamp (a datetime object)."""

		timestamp = self.registry_file.baseblock.effective_last_reorganized_timestamp
		if timestamp is not None:
			return DecodeFiletime(timestamp)

	def offreg_serialization_timestamp(self):
		"""Get, decode and return a serialization timestamp set by the offreg.dll library."""

		timestamp = self.registry_file.baseblock.get_offreg_serialization_timestamp()
		if timestamp is not None and timestamp > 0:
			return DecodeFiletime(timestamp)

	def find_key(self, path):
		"""Find a key node by its path (without a name of a root key), return a key node (a RegistryKey object) or None, if not found."""

		if path == '\\' or len(path) == 0:
			return self.root_key()

		if path[0] == '\\':
			path = path[1 : ]

		current_key = self.root_key()
		path_components = path.split('\\')

		i = 0
		while i < len(path_components) and current_key is not None:
			current_key = current_key.subkey(path_components[i])
			i += 1

		return current_key

	def recover_new(self, file_object_log_or_log1, file_object_log2 = None):
		"""Recover a primary file using a single transaction log file or two transaction log files.
		When 'file_object_log2' is None, a single transaction log file is used.
		Transaction log files should be in the new format.
		This method return a list of transaction log files (file objects) applied.
		"""

		if file_object_log2 is None:
			self.registry_file.apply_new_log_file(file_object_log_or_log1, self.log_entry_callback)
			return [file_object_log_or_log1]
		else:
			return self.registry_file.apply_new_log_files(file_object_log_or_log1, file_object_log2, self.log_entry_callback)

	def recover_old(self, file_object_log):
		"""Recover a primary file using a single transaction log file.
		A transaction log file should be in the old format.
		"""

		self.registry_file.apply_old_log_file(file_object_log)

	def recover_auto(self, file_object_log, file_object_log1, file_object_log2):
		"""Recover a primary file using one, two or three candidate transaction log files (the 'auto' mode).
		The format of transaction log files (new or old) and the logging scheme (single-logging or dual-logging) are guessed.
		If a transaction log file with a corresponding extension (.LOG/.LOG1/.LOG2) is not present, use None as an argument for that file.
		If a primary file is not dirty, no exception is raised. A named tuple (AutoRecoveryResult) is returned.
		"""

		def try_log(file_object_log, log_class):
			if file_object_log is None:
				return

			try:
				log = log_class(file_object_log)
			except (RegistryFile.ReadException, RegistryFile.BaseBlockException, RegistryFile.FileSizeException, RegistryFile.NotSupportedException, RegistryFile.DirtyVectorException):
				return
			else:
				return log

		if not self.registry_file.baseblock.is_file_dirty:
			return AutoRecoveryResult(recovered = False, is_new_log = None, file_objects = None)

		log, log1, log2 = file_object_log, file_object_log1, file_object_log2
		use_log = log is not None

		if (log1 is not None and log2 is None) or (log1 is None and log2 is not None):
			raise AutoRecoveryException('No valid recovery scheme possible')

		if use_log and log1 is None and log2 is None:
			# This is the single-logging scheme.
			log_new = try_log(log, RegistryFile.NewLogFile)
			if log_new is not None:
				self.recover_new(log)
				return AutoRecoveryResult(recovered = True, is_new_log = True, file_objects = [log])

			log_old = try_log(log, RegistryFile.OldLogFile)
			if log_old is not None:
				self.recover_old(log)
				return AutoRecoveryResult(recovered = True, is_new_log = False, file_objects = [log])

		if use_log:
			log_new = try_log(log, RegistryFile.NewLogFile)
		log1_new = try_log(log1, RegistryFile.NewLogFile)
		log2_new = try_log(log2, RegistryFile.NewLogFile)

		if use_log:
			log_old = try_log(log, RegistryFile.OldLogFile)
		log1_old = try_log(log1, RegistryFile.OldLogFile)
		log2_old = try_log(log2, RegistryFile.OldLogFile)

		# We prefer the new format and the dual-logging scheme.
		if log1_new is not None and log2_new is not None:
			logs_applied = self.recover_new(log1, log2)
			return AutoRecoveryResult(recovered = True, is_new_log = True, file_objects = logs_applied)

		if log1_new is not None:
			self.recover_new(log1)
			return AutoRecoveryResult(recovered = True, is_new_log = True, file_objects = [log1])

		if log2_new is not None:
			self.recover_new(log2)
			return AutoRecoveryResult(recovered = True, is_new_log = True, file_objects = [log2])

		# Now, try the single-logging scheme for the new format.
		if use_log and log_new is not None:
			self.recover_new(log)
			return AutoRecoveryResult(recovered = True, is_new_log = True, file_objects = [log])

		# Now, switch to the old format (we still prefer the dual-logging scheme).
		if log1_old is not None and log2_old is not None:
			log1_timestamp = log1_old.baseblock.effective_last_written_timestamp
			log2_timestamp = log2_old.baseblock.effective_last_written_timestamp
			if log1_timestamp >= log2_timestamp: # Select the latest log.
				self.recover_old(log1)
				return AutoRecoveryResult(recovered = True, is_new_log = False, file_objects = [log1])
			else:
				self.recover_old(log2)
				return AutoRecoveryResult(recovered = True, is_new_log = False, file_objects = [log2])

		if log1_old is not None:
			self.recover_old(log1)
			return AutoRecoveryResult(recovered = True, is_new_log = False, file_objects = [log1])

		if log2_old is not None:
			self.recover_old(log2)
			return AutoRecoveryResult(recovered = True, is_new_log = False, file_objects = [log2])

		# Now, try the single-logging scheme.
		if use_log and log_old is not None:
			self.recover_old(log)
			return AutoRecoveryResult(recovered = True, is_new_log = False, file_objects = [log])

		# We failed.
		raise AutoRecoveryException('No obvious recovery scheme found')

	def save_recovered_hive(self, filepath):
		"""Save the recovered hive to a new primary file (using its path)."""

		self.registry_file.save_recovered_hive(filepath)

	def rollback_changes(self):
		"""Discard recovered data and use a primary file as is. The effective slack remains intact."""

		self.registry_file.discard_writable_file_object()

	def walk_everywhere(self):
		"""Visit and record each referenced cell, collect the slack space data. This will also ensure that a hive is consistent."""

		def process_key(key):
			security = key.security()
			if security is not None:
				security_descriptor = security.descriptor()

			classname = key.classname()

			for value in key.values():
				value_data_raw = value.data_raw()

			for subkey in key.subkeys():
				process_key(subkey)

			for slack in key.effective_slack:
				if len(slack) >= 4: # Skip the slack space data if it is less than 4 bytes.
					self.effective_slack.add(slack)

		self.registry_file.record_referenced_cells = True
		try:
			process_key(self.root_key())
		except RegistryException:
			self.registry_file.record_referenced_cells = False
			raise

		self.registry_file.record_referenced_cells = False

		self.registry_file.build_map_free()

	def are_layered_keys_supported(self):
		"""Check if layered keys are supported for this hive."""

		return self.registry_file.baseblock.get_flags() & RegistryFile.HIVE_FLAG_LAYERED_KEYS_SUPPORTED > 0

class RegistryKey(object):
	"""This is a high-level class for a registry key."""

	registry_file = None
	"""A primary file of a hive (a RegistryFile.PrimaryFile object)."""

	key_node = None
	"""A KeyNode object."""

	effective_slack = None
	"""A set of data strings from different slack space locations to be used in the deleted data recovery."""

	def __init__(self, primary_file, buf, layer, cell_relative_offset, tolerate_minor_errors = False, naive = False):
		"""When working with deleted registry keys or truncated hives, set 'naive' to True, 'cell_relative_offset' and 'layer' to None.
		For a root key, set 'layer' to 0 (increment 'layer' by one when going to subkeys of a current key and decrement it by one when going to a parent key).
		"""

		self.registry_file = primary_file
		self.naive = naive
		if not self.naive:
			self.get_cell = self.registry_file.get_cell
		else:
			self.get_cell = self.registry_file.get_cell_naive

		self.key_node = RegistryRecords.KeyNode(buf)
		self.cell_relative_offset = cell_relative_offset
		self.layer = layer
		self.tolerate_minor_errors = tolerate_minor_errors
		self.effective_slack = set()

	def last_written_timestamp(self):
		"""Get, decode and return a last written timestamp (a datetime object)."""

		return DecodeFiletime(self.key_node.get_last_written_timestamp())

	def access_bits(self):
		"""Get and return access bits."""

		if self.registry_file.baseblock.effective_version == 1:
			return

		return self.key_node.get_access_bits()

	def name(self):
		"""Get, decode and return a key name string."""

		name_buf = self.key_node.get_key_name()
		is_ascii = self.registry_file.baseblock.effective_version > 1 and self.key_node.get_flags() & RegistryRecords.KEY_COMP_NAME > 0
		if is_ascii:
			name = DecodeASCII(name_buf)
		else:
			name = DecodeUnicode(name_buf)

		if name.find('\\') != -1:
			if not self.naive:
				raise WalkException('Key node does not have a valid name, key path: {}'.format(self.path()))
			else:
				# Do not build the path, if we are trying to recover a key node.
				raise WalkException('Key node does not have a valid name')

		return name

	def classname(self):
		"""Get, decode and return a class name string."""

		classname_length = self.key_node.get_classname_length()
		if classname_length > 0:
			classname_buf = self.get_cell(self.key_node.get_classname_offset())
			return DecodeUnicode(classname_buf[ : classname_length])

	def parent(self):
		"""Get and return a parent key node (a RegistryKey object)."""

		if self.layer == 0:
			# This is the root key.
			return

		if self.layer is None and (self.key_node.get_flags() & RegistryRecords.KEY_HIVE_ENTRY > 0 or self.cell_relative_offset == self.registry_file.baseblock.effective_root_cell_offset):
			# This is the root key.
			return

		parent_offset = self.key_node.get_parent()
		parent_buf = self.get_cell(parent_offset)

		layer_up = None
		if self.layer is not None:
			layer_up = self.layer - 1

		parent_key_node = RegistryKey(self.registry_file, parent_buf, layer_up, parent_offset, self.tolerate_minor_errors, self.naive)

		return parent_key_node

	def path(self, show_root = False):
		"""Construct and return a path to a key node.
		When 'show_root' is True, a name of a root key node is included.
		"""

		path_components = [ self.name() ]

		if self.naive:
			track = set()
			track.add(self.key_node.get_parent())

		p = self.parent()
		while p is not None:
			if self.naive:
				p_parent = p.key_node.get_parent()
				if p_parent in track:
					raise WalkException('Invalid path when following parent keys')

				track.add(p_parent)

			path_components.append(p.name())
			p = p.parent()

		path_components.reverse()
		if not show_root:
			path_components = path_components[ 1 : ]

		return '\\'.join(path_components)

	def path_partial(self, show_root = False):
		"""Construct and return a path (possibly a partial one) to a key node.
		When 'show_root' is True, a name of a root key node is included.
		"""

		path_components = [ self.name() ]

		if self.naive:
			track = set()
			track.add(self.key_node.get_parent())

		try:
			p = self.parent()
			while p is not None:
				if self.naive:
					p_parent = p.key_node.get_parent()
					if p_parent in track:
						raise WalkException('Invalid path when following parent keys')

					track.add(p_parent)

				path_components.append(p.name())
				p = p.parent()
		except RegistryException:
			root_found = False
		else:
			root_found = True

		path_components.reverse()
		if root_found and not show_root:
			path_components = path_components[ 1 : ]

		return '\\'.join(path_components)

	def subkeys(self):
		"""This method yields subkeys (RegistryKey objects)."""

		subkeys_names = set()

		def process_leaf(leaf_buf):
			leaf_signature = leaf_buf[ : 2]

			if leaf_signature == b'li':
				leaf = RegistryRecords.IndexLeaf(leaf_buf)
			elif leaf_signature == b'lf':
				leaf = RegistryRecords.FastLeaf(leaf_buf)
			else: # b'lh'
				leaf = RegistryRecords.HashLeaf(leaf_buf)

			slack = leaf.get_slack()
			self.effective_slack.add(slack)

			layer_down = None
			if self.layer is not None:
				layer_down = self.layer + 1

			if type(leaf) is RegistryRecords.IndexLeaf:
				for leaf_element in leaf.elements():
					subkey_offset = leaf_element.relative_offset

					buf = self.get_cell(subkey_offset)
					subkey = RegistryKey(self.registry_file, buf, layer_down, subkey_offset, self.tolerate_minor_errors, self.naive)
					if self.cell_relative_offset is not None and subkey.key_node.get_parent() != self.cell_relative_offset:
						if not self.naive:
							raise WalkException('Key node does not point to a valid parent key node, key path: {}, name: {}'.format(self.path(), subkey.name()))
						else:
							# Do not build the path, if we are trying to recover a key node.
							raise WalkException('Key node does not point to a valid parent key node')

					yield subkey

			if type(leaf) is RegistryRecords.FastLeaf:
				for leaf_element in leaf.elements():
					subkey_offset = leaf_element.relative_offset

					buf = self.get_cell(subkey_offset)
					subkey = RegistryKey(self.registry_file, buf, layer_down, subkey_offset, self.tolerate_minor_errors, self.naive)
					if self.cell_relative_offset is not None and subkey.key_node.get_parent() != self.cell_relative_offset:
						if not self.naive:
							raise WalkException('Key node does not point to a valid parent key node, key path: {}, name: {}'.format(self.path(), subkey.name()))
						else:
							# Do not build the path, if we are trying to recover a key node.
							raise WalkException('Key node does not point to a valid parent key node')

					yield subkey

			if type(leaf) is RegistryRecords.HashLeaf:
				for leaf_element in leaf.elements():
					subkey_offset = leaf_element.relative_offset

					buf = self.get_cell(subkey_offset)
					subkey = RegistryKey(self.registry_file, buf, layer_down, subkey_offset, self.tolerate_minor_errors, self.naive)
					if self.cell_relative_offset is not None and subkey.key_node.get_parent() != self.cell_relative_offset:
						if not self.naive:
							raise WalkException('Key node does not point to a valid parent key node, key path: {}, name: {}'.format(self.path(), subkey.name()))
						else:
							# Do not build the path, if we are trying to recover a key node.
							raise WalkException('Key node does not point to a valid parent key node')

					yield subkey


		if self.key_node.get_subkeys_count() > 0:
			list_offset = self.key_node.get_subkeys_list_offset()
			list_buf = self.get_cell(list_offset)
			list_signature = list_buf[ : 2]

			prev_name = None

			if list_signature == b'ri':
				index_root = RegistryRecords.IndexRoot(list_buf)

				slack = index_root.get_slack()
				self.effective_slack.add(slack)

				for leaf_offset in index_root.elements():
					list_buf = self.get_cell(leaf_offset)
					for subkey in process_leaf(list_buf):
						curr_name = RegistryUnicode.Upper(subkey.name())
						if curr_name not in subkeys_names:
							subkeys_names.add(curr_name)
						else:
							if unicode_replacement_character not in curr_name:
								if not self.naive:
									raise WalkException('Duplicate subkey, key path: {}, name: {}'.format(self.path(), curr_name))
								else:
									# Do not build the path, if we are trying to recover a key node.
									raise WalkException('Duplicate subkey')

						if prev_name is not None and curr_name <= prev_name:
							if unicode_replacement_character not in curr_name and unicode_replacement_character not in prev_name:
								if not self.naive:
									raise WalkException('Wrong order of subkeys, key path: {}, offending name: {}'.format(self.path(), curr_name))
								else:
									# Do not build the path, if we are trying to recover a key node.
									raise WalkException('Wrong order of subkeys')

						prev_name = curr_name

						yield subkey
			else:
				for subkey in process_leaf(list_buf):
					curr_name = RegistryUnicode.Upper(subkey.name())
					if curr_name not in subkeys_names:
						subkeys_names.add(curr_name)
					else:
						if unicode_replacement_character not in curr_name:
							if not self.naive:
								raise WalkException('Duplicate subkey, key path: {}, name: {}'.format(self.path(), curr_name))
							else:
								# Do not build the path, if we are trying to recover a key node.
								raise WalkException('Duplicate subkey')

					if prev_name is not None and curr_name <= prev_name:
						if unicode_replacement_character not in curr_name and unicode_replacement_character not in prev_name:
							if not self.naive:
								raise WalkException('Wrong order of subkeys, key path: {}, offending name: {}'.format(self.path(), curr_name))
							else:
								# Do not build the path, if we are trying to recover a key node.
								raise WalkException('Wrong order of subkeys')

					prev_name = curr_name

					yield subkey

	def subkey(self, name):
		"""This method returns a subkey by its name (a RegistryKey object) or None, if not found."""

		name = name.upper()
		for curr_subkey in self.subkeys():
			curr_name = curr_subkey.name().upper()
			if name == curr_name:
				return curr_subkey

	def subkeys_count(self):
		"""Get and return a number of subkeys. Volatile subkeys are not counted."""

		return self.key_node.get_subkeys_count()

	def values(self):
		"""This method yields key values (RegistryValue objects)."""

		values_names = set()

		values_count = self.values_count()
		if values_count > 0:
			list_offset = self.key_node.get_key_values_list_offset()
			list_buf = self.get_cell(list_offset)

			values_list = RegistryRecords.KeyValuesList(list_buf, values_count)

			slack = values_list.get_slack()
			self.effective_slack.add(slack)

			for value_offset in values_list.elements():
				buf = self.get_cell(value_offset)
				curr_value = RegistryValue(self.registry_file, buf, self.naive)
				curr_value.cell_relative_offset = value_offset

				slack_list = curr_value.data_slack()
				for curr_slack in slack_list:
					self.effective_slack.add(curr_slack)

				curr_name = RegistryUnicode.Upper(curr_value.name())
				if curr_name not in values_names:
					values_names.add(curr_name)
				else:
					if unicode_replacement_character not in curr_name:
						if not self.naive:
							raise WalkException('Duplicate value name, key path: {}, value name: {}'.format(self.path(), curr_name))
						else:
							# Do not build the path, if we are trying to recover a key node.
							raise WalkException('Duplicate value name')

				yield curr_value

	def remnant_values(self):
		"""This method yields deleted key values (RegistryValue objects) that are still associated with the key.
		There is no similar method for subkeys.
		"""

		track = set()

		values_count = self.values_count()
		if values_count > 0:
			list_offset = self.key_node.get_key_values_list_offset()
			list_buf = self.get_cell(list_offset)

			values_list = RegistryRecords.KeyValuesList(list_buf, values_count)

			slack = values_list.get_slack()
			self.effective_slack.add(slack)

			for value_offset in values_list.elements():
				track.add(value_offset)

			for value_offset in values_list.remnant_elements():
				if value_offset < 8 or value_offset % 8 != 0:
					break

				if value_offset in track or value_offset + BASE_BLOCK_LENGTH_PRIMARY in self.registry_file.cell_map_referenced:
					continue

				try:
					buf = self.registry_file.get_cell_naive(value_offset)
					curr_value = RegistryValue(self.registry_file, buf, True)
					curr_value_name = curr_value.name()
				except (RegistryException, UnicodeDecodeError):
					track.add(value_offset)
					continue
				else:
					curr_value.cell_relative_offset = value_offset

				# We do not try to collect the data slack here.
				yield curr_value

				track.add(value_offset)

	def value(self, name = ''):
		"""This method returns a key value by its name (a RegistryValue object) or None, if not found.
		When 'name' is empty, a default value is returned (if any).
		Remnant values are ignored by this method.
		"""

		name = name.upper()
		for curr_value in self.values():
			curr_name = curr_value.name().upper()
			if name == curr_name:
				return curr_value

	def values_count(self):
		"""Get and return a number of key values."""

		if self.key_node.get_flags() & RegistryRecords.KEY_PREDEF_HANDLE > 0:
			return 0

		return self.key_node.get_key_values_count()

	def security(self):
		"""Get and return a key security item (a RegistrySecurity object)."""

		key_security_offset = self.key_node.get_key_security_offset()
		if key_security_offset != RegistryFile.CELL_OFFSET_NIL:
			buf = self.get_cell(key_security_offset)
			return RegistrySecurity(self.registry_file, buf)

	def flags_raw(self):
		"""Get and return layered key flags for this key (as an integer)."""

		return self.key_node.get_layered_key_bit_fields()

	def flags_str(self):
		"""Get and return layered key flags for this key as a string (or None, if no flags are set)."""

		flags = self.flags_raw()
		flags_str_list = []

		if flags & RegistryRecords.KEY_INHERIT_CLASS > 0:
			flags_str_list.append(KEY_FLAG_INHERIT_CLASS)
			flags = flags - RegistryRecords.KEY_INHERIT_CLASS

		for i in KEY_FLAGS.keys():
			if flags == i:
				flags_str_list.append(KEY_FLAGS[i])
				break

		if len(flags_str_list) == 0:
			return

		return ' | '.join(flags_str_list)

	def __str__(self):
		return 'RegistryKey, name: {}, subkeys: {}, values: {}'.format(self.name(), self.subkeys_count(), self.values_count())

class RegistrySecurity(object):
	"""This is a high-level class for a key security item."""

	registry_file = None
	"""A primary file of a hive (a RegistryFile.PrimaryFile object)."""

	key_security = None
	"""A KeySecurity object."""

	def __init__(self, primary_file, buf):
		self.registry_file = primary_file

		self.key_security = RegistryRecords.KeySecurity(buf)

	def descriptor(self):
		"""Get and return a security descriptor (as raw bytes)."""

		return self.key_security.get_security_descriptor()

class RegistryValue(object):
	"""This is a high-level class for a registry value."""

	registry_file = None
	"""A primary file of a hive (a RegistryFile.PrimaryFile object)."""

	key_value = None
	"""A KeyValue object."""

	def __init__(self, primary_file, buf, naive = False):
		"""When working with deleted registry values or truncated hives, set 'naive' to True."""

		self.registry_file = primary_file
		if not naive:
			self.get_cell = self.registry_file.get_cell
		else:
			self.get_cell = self.registry_file.get_cell_naive

		self.key_value = RegistryRecords.KeyValue(buf)
		self.cell_relative_offset = None # This is set externally.

	def name(self):
		"""Get, decode and return a value name string."""

		name_buf = self.key_value.get_value_name()
		is_ascii = self.registry_file.baseblock.effective_version > 1 and self.key_value.get_flags() & RegistryRecords.VALUE_COMP_NAME > 0
		if is_ascii:
			return DecodeASCII(name_buf)

		return DecodeUnicode(name_buf)

	def type_raw(self):
		"""Get and return a value type (as an integer)."""

		return self.key_value.get_data_type()

	def type_str(self):
		"""Get, decode and return a value type (as a string)."""

		value_type = self.key_value.get_data_type()
		if value_type in ValueTypes.keys():
			return ValueTypes[value_type]
		else:
			return hex(value_type)

	def data_size(self):
		"""Get and return a data size."""

		return self.key_value.get_data_size_real()

	def data_raw(self):
		"""Get and return data (as raw bytes)."""

		if self.key_value.get_data_size_real() == 0:
			return b''

		if self.key_value.is_data_inline():
			return self.key_value.get_inline_data()[ : self.key_value.get_data_size_real()]

		is_big_data = self.registry_file.baseblock.effective_version > 3 and self.key_value.get_data_size_real() > 16344
		if not is_big_data:
			return self.get_cell(self.key_value.get_data_offset())[ : self.key_value.get_data_size_real()]

		big_data_buf = self.get_cell(self.key_value.get_data_offset())
		big_data = RegistryRecords.BigData(big_data_buf)

		segments_list_offset = big_data.get_segments_list_offset()
		segments_count = big_data.get_segments_count()

		segments_list = RegistryRecords.SegmentsList(self.get_cell(segments_list_offset), segments_count)

		data = b''
		data_length = self.key_value.get_data_size_real()
		for segment_offset in segments_list.elements():
			buf = self.get_cell(segment_offset)

			if data_length > 16344:
				data_part = buf[ : 16344]
				if len(data_part) != 16344:
					raise WalkException('Invalid segment size: {} != 16344'.format(len(data_part)))

				data += data_part
				data_length -= 16344
			else:
				data += buf[ : data_length]
				break

		return data

	def data_slack(self):
		"""Get and return the data slack (as a list of raw bytes)."""

		if self.key_value.get_data_size_real() == 0 or self.key_value.is_data_inline():
			# No data slack in these cases.
			return []

		is_big_data = self.registry_file.baseblock.effective_version > 3 and self.key_value.get_data_size_real() > 16344
		if not is_big_data:
			slack = self.get_cell(self.key_value.get_data_offset())[self.key_value.get_data_size_real() : ]
			return [slack]

		slack_list = []

		big_data_buf = self.get_cell(self.key_value.get_data_offset())
		big_data = RegistryRecords.BigData(big_data_buf)

		slack_list.append(big_data.get_slack())

		segments_list_offset = big_data.get_segments_list_offset()
		segments_count = big_data.get_segments_count()

		segments_list = RegistryRecords.SegmentsList(self.get_cell(segments_list_offset), segments_count)

		slack_list.append(segments_list.get_slack())

		data_length = self.key_value.get_data_size_real()
		for segment_offset in segments_list.elements():
			buf = self.get_cell(segment_offset)

			if data_length > 16344:
				slack = buf[16344 : ]
				slack_list.append(slack)
				data_length -= 16344
			else:
				slack = buf[data_length : ]
				slack_list.append(slack)
				break

		return slack_list

	def data(self):
		"""Get, decode and return data (as an integer, a string, a list of strings, or raw bytes).
		A string may contain a terminating null character.
		"""

		data_raw = self.data_raw()
		data_length = len(data_raw)
		type_int = self.type_raw()

		if type_int == RegistryRecords.REG_DWORD and data_length == 4:
			return unpack('<L', data_raw)[0]

		if type_int == RegistryRecords.REG_DWORD_BIG_ENDIAN and data_length == 4:
			return unpack('>L', data_raw)[0]

		if type_int == RegistryRecords.REG_QWORD and data_length == 8:
			return unpack('<Q', data_raw)[0]

		if (type_int == RegistryRecords.REG_SZ or type_int == RegistryRecords.REG_EXPAND_SZ) and data_length % 2 == 0 and data_length > 1:
			return DecodeUnicode(data_raw, True)

		if type_int == RegistryRecords.REG_LINK and data_length % 2 == 0 and data_length > 1:
			return DecodeUnicode(data_raw, True)

		if type_int == RegistryRecords.REG_MULTI_SZ and data_length % 2 == 0 and data_length > 1:
			sz_list_data = DecodeUnicodeMulti(data_raw, True)
			if sz_list_data == '\x00':
				return []

			if len(sz_list_data) > 2 and sz_list_data[-1] == '\x00' and sz_list_data[-2] == '\x00':
				sz_list = sz_list_data[ : -1].split('\x00')

				i = 0
				while i < len(sz_list):
					sz_list[i] += '\x00' # Restore the terminating null characters.
					i += 1

				return sz_list

		return data_raw

	def flags_raw(self):
		"""Get and return flags for this value (as an integer). This method returns all flags, not just layered flags."""

		return self.key_value.get_flags()

	def flags_str(self):
		"""Get and return layered flags for this value as a string (or None, if no layered flags are set)."""

		flags = self.flags_raw()
		if flags & RegistryRecords.VALUE_TOMBSTONE > 0:
			return VALUE_FLAG_TOMBSTONE

		return

	def __str__(self):
		name = self.name()
		if len(name) > 0:
			return 'RegistryValue, name: {}, data type: {}, data size: {}'.format(name, self.type_str(), self.data_size())
		else:
			return 'RegistryValue, default value (no name), data type: {}, data size: {}'.format(self.type_str(), self.data_size())

class RegistryHiveTruncated(object):
	"""This is a high-level class for a truncated registry hive. This class should be used as a replacement for the RegistryHive class."""

	registry_file = None
	"""A primary file of a hive (a RegistryFile.PrimaryFileTruncated object)."""

	effective_slack = None
	"""A set of data strings from different slack space locations to be used in the deleted data recovery."""

	def __init__(self, file_object):
		self.registry_file = RegistryFile.PrimaryFileTruncated(file_object)
		self.effective_slack = set()

	def last_written_timestamp(self):
		"""Get, decode and return a last written timestamp (a datetime object)."""

		return DecodeFiletime(self.registry_file.baseblock.effective_last_written_timestamp)

	def last_reorganized_timestamp(self):
		"""Get, decode and return a last reorganized timestamp (a datetime object)."""

		timestamp = self.registry_file.baseblock.effective_last_reorganized_timestamp
		if timestamp is not None:
			return DecodeFiletime(timestamp)

	def offreg_serialization_timestamp(self):
		"""Get, decode and return a serialization timestamp set by the offreg.dll library."""

		timestamp = self.registry_file.baseblock.get_offreg_serialization_timestamp()
		if timestamp is not None and timestamp > 0:
			return DecodeFiletime(timestamp)

	def scan(self):
		"""This method yields RegistryKey objects for keys and RegistryValue objects for values. Also, this method will collect the slack space data."""

		for cell in self.registry_file.cells():
			try:
				cell_data = cell.get_cell_data()
			except RegistryException:
				continue

			if len(cell_data) > 76: # A key node with at least one character in the name.
				try:
					key = RegistryKey(self.registry_file, cell_data, None, None, True, True)
					key_name = key.name()
				except (RegistryException, UnicodeDecodeError):
					pass
				else:
					yield key
					continue

			if len(cell_data) >= 20: # A key value with no name (at least).
				try:
					value = RegistryValue(self.registry_file, cell_data, True)
					value_name = value.name()
				except (RegistryException, UnicodeDecodeError):
					pass
				else:
					yield value
					continue

			if len(cell_data) >= 8: # A subkeys list with at least one entry.
				try:
					l = RegistryRecords.IndexLeaf(cell_data)
				except (RegistryException, UnicodeDecodeError): # UnicodeDecodeError can be raised when using Python 2.
					try:
						l = RegistryRecords.FastLeaf(cell_data)
					except (RegistryException, UnicodeDecodeError):
						try:
							l = RegistryRecords.HashLeaf(cell_data)
						except (RegistryException, UnicodeDecodeError):
							try:
								l = RegistryRecords.IndexRoot(cell_data)
							except (RegistryException, UnicodeDecodeError):
								l = None # Not a subkeys list.

				if l is not None:
					slack = l.get_slack()

					if len(slack) >= 4: # Skip the slack space data if it is less than 4 bytes.
						self.effective_slack.add(slack)

	def are_layered_keys_supported(self):
		"""Check if layered keys are supported for this hive."""

		return self.registry_file.baseblock.get_flags() & RegistryFile.HIVE_FLAG_LAYERED_KEYS_SUPPORTED > 0

class StandaloneRegistryKey(object):
	"""This is a high-level class for a standalone registry key."""

	def __init__(self, key_node):
		self.key_node = key_node

	def last_written_timestamp(self):
		"""Get, decode and return a last written timestamp (a datetime object)."""

		return DecodeFiletime(self.key_node.get_last_written_timestamp())

	def access_bits(self):
		"""Get and return access bits."""

		return self.key_node.get_access_bits()

	def name(self):
		"""Get, decode and return a key name string."""

		name_buf = self.key_node.get_key_name()
		is_ascii = self.key_node.get_flags() & RegistryRecords.KEY_COMP_NAME > 0
		if is_ascii:
			name = DecodeASCII(name_buf)
		else:
			name = DecodeUnicode(name_buf)

		if name.find('\\') != -1:
			raise WalkException('Key node does not have a valid name')

		return name

	def subkeys_count(self):
		"""Get and return a number of subkeys. Volatile subkeys are not counted."""

		return self.key_node.get_subkeys_count()

	def values_count(self):
		"""Get and return a number of key values."""

		if self.key_node.get_flags() & RegistryRecords.KEY_PREDEF_HANDLE > 0:
			return 0

		return self.key_node.get_key_values_count()

	def __str__(self):
		return 'StandaloneRegistryKey, name: {}, subkeys: {}, values: {}'.format(self.name(), self.subkeys_count(), self.values_count())

class StandaloneRegistryValue(object):
	"""This is a high-level class for a standalone registry value."""

	def __init__(self, key_value):
		self.key_value = key_value

	def name(self):
		"""Get, decode and return a value name string."""

		name_buf = self.key_value.get_value_name()
		is_ascii = self.key_value.get_flags() & RegistryRecords.VALUE_COMP_NAME > 0
		if is_ascii:
			return DecodeASCII(name_buf)

		return DecodeUnicode(name_buf)

	def type_raw(self):
		"""Get and return a value type (as an integer)."""

		return self.key_value.get_data_type()

	def type_str(self):
		"""Get, decode and return a value type (as a string)."""

		value_type = self.key_value.get_data_type()
		if value_type in ValueTypes.keys():
			return ValueTypes[value_type]
		else:
			return hex(value_type)

	def data_size(self):
		"""Get and return a data size."""

		return self.key_value.get_data_size_real()

	def data_raw(self):
		"""Get and return data (as raw bytes or None, if unavailable)."""

		if self.key_value.get_data_size_real() == 0:
			return b''

		if self.key_value.is_data_inline():
			return self.key_value.get_inline_data()[ : self.key_value.get_data_size_real()]

		return

	def __str__(self):
		name = self.name()
		if len(name) > 0:
			return 'StandaloneRegistryValue, name: {}, data type: {}, data size: {}'.format(name, self.type_str(), self.data_size())
		else:
			return 'StandaloneRegistryValue, default value (no name), data type: {}, data size: {}'.format(self.type_str(), self.data_size())
