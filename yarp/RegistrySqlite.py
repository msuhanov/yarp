# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module implements an sqlite3 interface with advanced features.
# Unlike the Registry module, this interface provides a single class to work with a registry hive, a truncated registry hive, and a registry fragment.
# Python 3 only.

from . import Registry, RegistryFile, RegistryRecover, RegistryHelpers
import sqlite3
import os
from hashlib import sha256
from collections import namedtuple

Key = namedtuple('Key', [ 'rowid', 'is_deleted', 'name', 'classname', 'last_written_timestamp', 'access_bits', 'parent_key_id' ])
Value = namedtuple('Value', [ 'rowid', 'is_deleted', 'name', 'type', 'data', 'parent_key_id' ])
HiveInfo = namedtuple('HiveInfo', [ 'last_written_timestamp', 'last_reorganized_timestamp', 'recovered', 'truncated', 'rebuilt' ])

class YarpDB(object):
	"""This is an implementation of a registry hive to an sqlite3 database converter (and a simple interface to the database)."""

	db_cursor = None
	"""A database cursor."""

	schema_hive = ('CREATE TABLE `hive` ('
					'`id` INTEGER PRIMARY KEY,'
					'`last_written_timestamp` TEXT,'
					'`last_reorganized_timestamp` TEXT,'
					'`root_key_id` TEXT,'
					'`recovered` NUMERIC,'
					'`truncated` NUMERIC,'
					'`rebuilt` NUMERIC'
					')')
	"""Schema for the 'hive' table. Timestamps (here and in other places) are integers stored as text (FILETIME). Only one row is allowed in this table."""

	schema_keys = ('CREATE TABLE `keys` ('
					'`id` TEXT PRIMARY KEY,'
					'`is_deleted` NUMERIC,'
					'`name` TEXT,'
					'`classname` TEXT,'
					'`last_written_timestamp` TEXT,'
					'`access_bits` INTEGER,'
					'`parent_key_id` TEXT'
					')')
	"""Schema for the 'keys' table."""

	schema_values = ('CREATE TABLE `values` ('
					'`id` INTEGER PRIMARY KEY,'
					'`is_deleted` NUMERIC,'
					'`name` TEXT,'
					'`type` INTEGER,'
					'`data` BLOB,'
					'`parent_key_id` TEXT'
					')')
	"""Schema for the 'values' table."""

	def __init__(self, primary_or_fragment_path, sqlite_path, no_recovery = False):
		"""Create an sqlite3 database using 'sqlite_path', the database is filled with data from a registry file (primary) or a registry fragment specified by 'primary_or_fragment_path'.
		An existing database is cleared first. When 'no_recovery' is True, transaction log files are not used to recover a primary file.
		If 'primary_or_fragment_path' is None, open an existing database and use it.
		"""

		if primary_or_fragment_path is None and os.path.isfile(sqlite_path):
			# Use the existing database.
			self._primary = None
			self._hive = None
			self._log = None
			self._log1 = None
			self._log2 = None

			self._db_connection = sqlite3.connect(sqlite_path, check_same_thread = False)
			self.db_cursor = self._db_connection.cursor()

			return

		# Open the database, open the cursor.
		self._db_connection = sqlite3.connect(sqlite_path, check_same_thread = False)
		self.db_cursor = self._db_connection.cursor()

		# Open the primary file.
		self._primary = open(primary_or_fragment_path, 'rb')

		# Discover the transaction log files.
		log_files = RegistryHelpers.DiscoverLogFiles(primary_or_fragment_path)

		# Open the transaction log files.
		self._log = None
		if log_files.log_path is not None:
			self._log = open(log_files.log_path, 'rb')

		self._log1 = None
		if log_files.log1_path is not None:
			self._log1 = open(log_files.log1_path, 'rb')

		self._log2 = None
		if log_files.log2_path is not None:
			self._log2 = open(log_files.log2_path, 'rb')

		# Create the hive object.
		try:
			self._hive = Registry.RegistryHive(self._primary)
		except RegistryFile.NotSupportedException:
			raise
		except RegistryFile.BaseBlockException:
			temp_obj = self._primary
			self._primary = RegistryFile.FragmentTranslator(temp_obj)
			temp_obj.close()

			self._is_hive_truncated = True
			self._is_rebuilt = True
		except Registry.RegistryException:
			self._is_hive_truncated = True
			self._is_rebuilt = False
		else:
			self._is_hive_truncated = False
			self._is_rebuilt = False

		self._recovered = False
		self._db_clear()

		if not self._is_hive_truncated:
			# Recover the hive, if required.
			if not no_recovery:
				try:
					recovery_result = self._hive.recover_auto(self._log, self._log1, self._log2)
				except Registry.AutoRecoveryException:
					pass
				else:
					self._recovered = recovery_result.recovered

			try:
				self._hive.walk_everywhere()
			except (RegistryFile.CellOffsetException, RegistryFile.ReadException):
				if self._recovered:
					raise

				# This is an edge case: a truncated dirty hive.
				self._is_hive_truncated = True
				self._is_rebuilt = False
				self._hive = Registry.RegistryHiveTruncated(self._primary)

				self._db_init()

				self._db_process_deleted_data()
				self._db_process_partial_data()
				return

			self._db_init()

			self._db_process_deleted_data()
			self._db_process_data()
		else:
			# Create the truncated hive object.
			self._hive = Registry.RegistryHiveTruncated(self._primary)

			self._db_init()

			self._db_process_deleted_data()
			self._db_process_partial_data()

	def __enter__(self):
		return self

	def __exit__(self, *args):
		self.close()

	def close(self):
		"""Close the hive and backing files, commit and close the database."""

		# Close (unlink) the hive object.
		self._hive = None

		# Close the primary file.
		if self._primary is not None:
			self._primary.close()

		# Close the transaction log files.
		if self._log is not None:
			self._log.close()

		if self._log1 is not None:
			self._log1.close()

		if self._log2 is not None:
			self._log2.close()

		# Commit and close the database.
		self._db_connection.commit()
		self._db_connection.close()

	def _db_clear(self):
		"""Remove the tables and indices."""

		self.db_cursor.execute('DROP TABLE IF EXISTS `hive`')
		self.db_cursor.execute('DROP TABLE IF EXISTS `keys`')
		self.db_cursor.execute('DROP TABLE IF EXISTS `values`')

	def _db_init(self):
		"""Create the tables and indices. Set up basic data about the hive."""

		self.db_cursor.execute(self.schema_hive)

		self.db_cursor.execute(self.schema_keys)

		self.db_cursor.execute('CREATE INDEX `keys_idx_name` ON `keys`(`name`)')
		self.db_cursor.execute('CREATE INDEX `keys_idx_parent_key_id` ON `keys`(`parent_key_id`)')

		self.db_cursor.execute(self.schema_values)

		self.db_cursor.execute('CREATE INDEX `values_idx_name` ON `values`(`name`)')
		self.db_cursor.execute('CREATE INDEX `values_idx_parent_key_id` ON `values`(`parent_key_id`)')

		# Insert data about the hive.
		last_written_timestamp = str(self._hive.registry_file.baseblock.effective_last_written_timestamp)
		if self._hive.registry_file.baseblock.effective_last_reorganized_timestamp is None:
			last_reorganized_timestamp = None
		else:
			last_reorganized_timestamp = str(self._hive.registry_file.baseblock.effective_last_reorganized_timestamp)

		if self._recovered:
			recovered = 1
		else:
			recovered = 0

		if self._is_hive_truncated:
			truncated = 1
		else:
			truncated = 0

		if self._is_rebuilt:
			rebuilt = 1
		else:
			rebuilt = 0

		self.db_cursor.execute('INSERT INTO `hive` (`id`, `last_written_timestamp`, `last_reorganized_timestamp`, `root_key_id`, `recovered`, `truncated`, `rebuilt`) VALUES (?, ?, ?, ?, ?, ?, ?)',
			(0, last_written_timestamp, last_reorganized_timestamp, None, recovered, truncated, rebuilt))

		# Set up the value ID counter, etc.
		self._value_id = 0
		self._root_found = False

	def _db_key_to_id(self, key, is_deleted = 0):
		"""Calculate and return the ID for a key."""

		hasher = sha256()

		deleted_status = str(is_deleted).encode()
		hasher.update(deleted_status)

		key_node_data = key.key_node.read_binary(0, 76 + key.key_node.get_key_name_length())
		hasher.update(key_node_data)

		return hasher.hexdigest()

	def _db_value_to_id(self, value, is_deleted = 0):
		"""Calculate and return the ID for a value."""

		curr_id = self._value_id
		self._value_id += 1
		return curr_id

	def _db_is_reallocated_value(self, value):
		"""Check if a deleted value has been reallocated."""

		if value.cell_relative_offset is None:
			return False

		value_offset = value.cell_relative_offset + RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
		if not self._is_hive_truncated:
			return value_offset in self._hive.registry_file.cell_map_referenced
		else:
			return value_offset in self._hive.registry_file.cell_map_allocated

	def _db_is_reallocated_value_data(self, value):
		"""Check if deleted value data has been reallocated."""

		if value.key_value.is_data_inline():
			return False

		data_offset = value.key_value.get_data_offset() + RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
		if not self._is_hive_truncated:
			return data_offset in self._hive.registry_file.cell_map_referenced
		else:
			return data_offset in self._hive.registry_file.cell_map_allocated

	def _db_add_key(self, key, is_deleted = 0):
		"""Add a key and its values to the database."""

		key_id = self._db_key_to_id(key, is_deleted)

		name = key.name()

		try:
			classname = key.classname()
		except (Registry.RegistryException, UnicodeDecodeError):
			if (not self._is_hive_truncated) and (not is_deleted):
				raise

			classname = None

		last_written_timestamp = str(key.key_node.get_last_written_timestamp())
		access_bits = key.access_bits()

		try:
			parent_key = key.parent()
		except Registry.RegistryException:
			if (not self._is_hive_truncated) and (not is_deleted):
				raise

			parent_key_id = None
		else:
			if parent_key is not None:
				parent_key_offset = parent_key.cell_relative_offset + RegistryFile.BASE_BLOCK_LENGTH_PRIMARY
				if ((not self._is_hive_truncated) and parent_key_offset in self._hive.registry_file.cell_map_referenced) or \
					(self._is_hive_truncated and parent_key_offset in self._hive.registry_file.cell_map_allocated):
					parent_key_status = 0
				else:
					parent_key_status = 1

				parent_key_id = self._db_key_to_id(parent_key, parent_key_status)
			else:
				# This is the root key.
				parent_key_id = None
				if not self._root_found:
					self._root_found = True
					self.db_cursor.execute('UPDATE `hive` SET `root_key_id` = ? WHERE `id` = ?', (key_id, 0))
				else:
					# Two or more keys are marked as root, do not trust them.
					self.db_cursor.execute('UPDATE `hive` SET `root_key_id` = ? WHERE `id` = ?', (None, 0))

		self.db_cursor.execute('INSERT OR IGNORE INTO `keys` (`id`, `is_deleted`, `name`, `classname`, `last_written_timestamp`, `access_bits`, `parent_key_id`) VALUES (?, ?, ?, ?, ?, ?, ?)',
			(key_id, is_deleted, name, classname, last_written_timestamp, access_bits, parent_key_id))

		try:
			for value in key.values():
				if is_deleted and self._db_is_reallocated_value(value):
					continue

				self._db_add_value(value, key_id, is_deleted)
		except (Registry.RegistryException, UnicodeDecodeError):
			if (not self._is_hive_truncated) and (not is_deleted):
				raise

		try:
			for value in key.remnant_values():
				if self._db_is_reallocated_value(value):
					continue

				self._db_add_value(value, key_id, 1)
		except (Registry.RegistryException, UnicodeDecodeError):
			pass

	def _db_add_value(self, value, parent_key_id, is_deleted = 0):
		"""Add a value to the database."""

		value_id = self._db_value_to_id(value, is_deleted)

		name = value.name()
		type_raw = value.type_raw()
		try:
			data_raw = value.data_raw()
		except Registry.RegistryException:
			if (not self._is_hive_truncated) and (not is_deleted):
				raise

			data_raw = None

		if is_deleted and self._db_is_reallocated_value_data(value):
			data_raw = None

		self.db_cursor.execute('INSERT OR IGNORE INTO `values` (`id`, `is_deleted`, `name`, `type`, `data`, `parent_key_id`) VALUES (?, ?, ?, ?, ?, ?)',
			(value_id, is_deleted, name, type_raw, data_raw, parent_key_id))

	def _db_process_deleted_data(self):
		"""Add deleted keys and values from a normal hive or a truncated one to the database."""

		scanner = RegistryRecover.Scanner(self._hive)
		for item in scanner.scan():
			if type(item) is Registry.RegistryKey:
				self._db_add_key(item, 1)
			elif type(item) is Registry.RegistryValue:
				self._db_add_value(item, None, 1)

	def _db_process_partial_data(self):
		"""Add allocated keys and values from a truncated hive to the database."""

		for item in self._hive.scan():
			if type(item) is Registry.RegistryKey:
				self._db_add_key(item)
			elif type(item) is Registry.RegistryValue:
				self._db_add_value(item, None)

	def _db_process_data(self):
		"""Add allocated and referenced keys and values from a normal hive to the database."""

		def process_key(key):
			self._db_add_key(key)

			for subkey in key.subkeys():
				process_key(subkey)

		process_key(self._hive.root_key())

	def get_rowid(self, key_id):
		"""Convert a key ID to a row ID."""

		self.db_cursor.execute('SELECT `rowid` FROM `keys` WHERE `id` = ?', (key_id,))
		results = self.db_cursor.fetchall()
		for result in results:
			return result[0]

	def key(self, key_rowid):
		"""Get and return a key by its row ID (or None, if not found)."""

		self.db_cursor.execute('SELECT `rowid`, `is_deleted`, `name`, `classname`, `last_written_timestamp`, `access_bits`, `parent_key_id` FROM `keys` WHERE `rowid` = ?', (key_rowid,))
		results = self.db_cursor.fetchall()

		for result in results:
			return Key(rowid = result[0], is_deleted = result[1], name = result[2], classname = result[3], last_written_timestamp = int(result[4]), access_bits = result[5], parent_key_id = result[6])

	def subkeys(self, key_rowid):
		"""Get and yield subkeys of a key with a specific row ID."""

		self.db_cursor.execute('SELECT `id` FROM `keys` WHERE `rowid` = ?', (key_rowid,))
		p = self.db_cursor.fetchone()
		if p is not None:
			p = p[0]
			self.db_cursor.execute('SELECT `rowid`, `is_deleted`, `name`, `classname`, `last_written_timestamp`, `access_bits`, `parent_key_id` FROM `keys` WHERE `parent_key_id` = ? ORDER BY UPPER(`name`) ASC', (p,))
			results = self.db_cursor.fetchall()

			for result in results:
				yield Key(rowid = result[0], is_deleted = result[1], name = result[2], classname = result[3], last_written_timestamp = int(result[4]), access_bits = result[5], parent_key_id = result[6])

	def subkeys_unassociated(self):
		"""Get and yield unassociated subkeys."""

		root_key = self.root_key()
		if root_key is not None:
			p = root_key.rowid

			self.db_cursor.execute('SELECT `rowid`, `is_deleted`, `name`, `classname`, `last_written_timestamp`, `access_bits`, `parent_key_id` FROM `keys` WHERE `parent_key_id` IS NULL AND `rowid` != ? ORDER BY UPPER(`name`) ASC', (p,))
			results = self.db_cursor.fetchall()

			for result in results:
				yield Key(rowid = result[0], is_deleted = result[1], name = result[2], classname = result[3], last_written_timestamp = int(result[4]), access_bits = result[5], parent_key_id = result[6])
		else:
			self.db_cursor.execute('SELECT `rowid`, `is_deleted`, `name`, `classname`, `last_written_timestamp`, `access_bits`, `parent_key_id` FROM `keys` WHERE `parent_key_id` IS NULL ORDER BY UPPER(`name`) ASC')
			results = self.db_cursor.fetchall()

			for result in results:
				yield Key(rowid = result[0], is_deleted = result[1], name = result[2], classname = result[3], last_written_timestamp = int(result[4]), access_bits = result[5], parent_key_id = result[6])

	def value(self, value_rowid):
		"""Get and return a value by its row ID (or None, if not found)."""

		self.db_cursor.execute('SELECT `rowid`, `is_deleted`, `name`, `type`, `data`, `parent_key_id` FROM `values` WHERE `rowid` = ?', (value_rowid,))
		results = self.db_cursor.fetchall()

		for result in results:
			return Value(rowid = result[0], is_deleted = result[1], name = result[2], type = result[3], data = result[4], parent_key_id = result[5])

	def values(self, key_rowid):
		"""Get and yield values of a key with a specific row ID."""

		self.db_cursor.execute('SELECT `id` FROM `keys` WHERE `rowid` = ?', (key_rowid,))
		p = self.db_cursor.fetchone()
		if p is not None:
			p = p[0]
			self.db_cursor.execute('SELECT `rowid`, `is_deleted`, `name`, `type`, `data`, `parent_key_id` FROM `values` WHERE `parent_key_id` = ? ORDER BY UPPER(`name`) ASC', (p,))
			results = self.db_cursor.fetchall()

			for result in results:
				yield Value(rowid = result[0], is_deleted = result[1], name = result[2], type = result[3], data = result[4], parent_key_id = result[5])

	def values_deleted(self):
		"""Get and yield all deleted values."""

		self.db_cursor.execute('SELECT `rowid`, `is_deleted`, `name`, `type`, `data`, `parent_key_id` FROM `values` WHERE `parent_key_id` IS NULL ORDER BY UPPER(`name`) ASC')
		results = self.db_cursor.fetchall()

		for result in results:
			yield Value(rowid = result[0], is_deleted = result[1], name = result[2], type = result[3], data = result[4], parent_key_id = result[5])

	def root_key(self):
		"""Get and return a root key (or None, if not found)."""

		self.db_cursor.execute('SELECT `root_key_id` FROM `hive` WHERE `id` = ?', (0,))
		p = self.db_cursor.fetchone()[0]
		if p is None:
			return

		self.db_cursor.execute('SELECT `rowid` FROM `keys` WHERE `id` = ?', (p,))
		p = self.db_cursor.fetchone()
		if p is None:
			return

		p = p[0]
		if p is not None:
			return self.key(p)

	def info(self):
		"""Get and return information about a hive."""

		self.db_cursor.execute('SELECT `last_written_timestamp`, `last_reorganized_timestamp`, `recovered`, `truncated`, `rebuilt` FROM `hive` WHERE `id` = ?', (0,))
		results = self.db_cursor.fetchall()

		for result in results:
			if result[1] is None:
				ts_lr = None
			else:
				ts_lr = int(result[1])

			return HiveInfo(last_written_timestamp = int(result[0]), last_reorganized_timestamp = ts_lr, recovered = result[2], truncated = result[3], rebuilt = result[4])
