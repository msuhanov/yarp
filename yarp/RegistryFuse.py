# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module implements a FUSE interface.

from __future__ import unicode_literals

from . import Registry, RegistryFile, RegistryRecords, RegistryHelpers, RegistryUnicode
import llfuse
import os
import stat
import errno

CACHE_SUBKEYS_COUNT = 500 # If a key has more subkeys than this number, cache the subkeys.
XATTR_CLASSNAME = b'user.winreg.class'
XATTR_DATA_TYPE = b'user.winreg.type'

class YarpFS(llfuse.Operations):
	"""This is an implementation of a FUSE file system (llfuse) for a registry hive."""

	def __init__(self, primary_path, enable_cache = True, character_encoding = 'utf-8'):
		super(YarpFS, self).__init__()

		# Open the primary file.
		self._yarp_file = open(primary_path, 'rb')

		# Discover the transaction log files.
		log_files = RegistryHelpers.DiscoverLogFiles(primary_path)

		# Open the transaction log files.
		self._yarp_log = None
		if log_files.log_path is not None:
			self._yarp_log = open(log_files.log_path, 'rb')

		self._yarp_log1 = None
		if log_files.log1_path is not None:
			self._yarp_log1 = open(log_files.log1_path, 'rb')

		self._yarp_log2 = None
		if log_files.log2_path is not None:
			self._yarp_log2 = open(log_files.log2_path, 'rb')

		# Create the hive object.
		registry_hive = Registry.RegistryHive(self._yarp_file)

		# Recover the hive, if required.
		try:
			registry_hive.recover_auto(self._yarp_log, self._yarp_log1, self._yarp_log2)
		except Registry.AutoRecoveryException:
			pass

		self._yarp_conflicts = dict()

		# Set up the cache.
		self._yarp_cache = dict()
		self._enable_cache = enable_cache

		# Check if the hive is consistent and fill the conflicts set.
		self._yarp_validate_hive(registry_hive)

		# Pick the primary file object.
		self._yarp_primary = registry_hive.registry_file

		# Free the hive object, we do not need the high-level interface anymore.
		registry_hive = None

		# Set the encoding.
		self._yarp_encoding = character_encoding

		self.default_name = '(default)'
		"""A virtual name for a value with no name."""

		self.conflict_suffix_value = '_yarp_conflicting_value_name'
		"""A suffix to append to a value name if a name conflict has arisen."""

		self.conflict_suffix_key = '_yarp_conflicting_key_name'
		"""A suffix to append to a key name if a name conflict has arisen."""

		self.slash_replacement = '{yarp_slash_here}'
		"""A string used to replace a slash in a name."""

		self.null_replacement = '{yarp_null_byte_here}'
		"""A string used to replace a null byte in a name."""

	def _yarp_validate_hive(self, registry_hive):
		def process_key(key):
			classname = key.classname()

			v_set = set()
			for value in key.values():
				value_name = value.name()
				if value_name in v_set:
					raise Registry.WalkException('Invalid or unusual Unicode characters in names of values')

				v_set.add(value_name)
				value_data_raw = value.data_raw()

			do_cache = key.subkeys_count() > CACHE_SUBKEYS_COUNT

			sk_set = set()
			prev_sk_name = None
			for subkey in key.subkeys():
				sk_name = subkey.name()

				if (prev_sk_name is not None and RegistryUnicode.Upper(sk_name) <= RegistryUnicode.Upper(prev_sk_name)) or RegistryUnicode.Upper(sk_name) in sk_set:
					raise Registry.WalkException('Invalid or unusual Unicode characters in names of keys')

				sk_set.add(RegistryUnicode.Upper(sk_name))

				if sk_name in v_set:
					if key.cell_relative_offset in self._yarp_conflicts.keys():
						self._yarp_conflicts[key.cell_relative_offset].append(sk_name)
					else:
						self._yarp_conflicts[key.cell_relative_offset] = [sk_name]

				if self._enable_cache and do_cache:
					if key.cell_relative_offset in self._yarp_cache.keys():
						self._yarp_cache[key.cell_relative_offset][sk_name] = subkey.cell_relative_offset
					else:
						self._yarp_cache[key.cell_relative_offset] = { sk_name: subkey.cell_relative_offset }

				process_key(subkey)

				prev_sk_name = sk_name

		process_key(registry_hive.root_key())

	def _yarp_convert_timestamp(self, filetime):
		return filetime * 100 - 11644473600 * 1000000000

	def _yarp_is_key(self, cell_relative_offset):
		try:
			buf = self._yarp_get_cell(cell_relative_offset)
		except RegistryFile.CellOffsetException:
			return False

		return buf[ : 2] == b'nk'

	def _yarp_is_value(self, cell_relative_offset):
		try:
			buf = self._yarp_get_cell(cell_relative_offset)
		except RegistryFile.CellOffsetException:
			return False

		return buf[ : 2] == b'vk'

	def _yarp_is_virtual_inode(self, cell_relative_offset):
		try:
			cell_signature = self._yarp_get_cell(cell_relative_offset)[ : 2]
		except RegistryFile.CellOffsetException:
			return False

		return cell_signature == b'vk' or cell_signature == b'nk'

	def _yarp_get_leaf(self, list_data):
		signature = list_data[ : 2]
		if signature == b'li':
			return RegistryRecords.IndexLeaf(list_data)
		elif signature == b'lf':
			return RegistryRecords.FastLeaf(list_data)
		else: # b'lh'
			return RegistryRecords.HashLeaf(list_data)

	def _yarp_posixify_name(self, name, cell_relative_offset, is_value_name):
		if is_value_name:
			conflict_suffix = self.conflict_suffix_value
		else:
			conflict_suffix = self.conflict_suffix_key

		if name == '': # Only a value name can be empty.
			return self.default_name

		if name == self.default_name or name == '.' or name == '..':
			# A conflict:
			# - an existing name is equal to the virtual name of a value with no name;
			# - an existing name is reserved ('.' and '..').
			return name + conflict_suffix

		if cell_relative_offset in self._yarp_conflicts.keys() and name in self._yarp_conflicts[cell_relative_offset]:
			# A conflict: a key and a value share the same name. Change the value name.
			if is_value_name:
				name += conflict_suffix

		if '/' in name:
			name = name.replace('/', self.slash_replacement)
		if '\x00' in name:
			name = name.replace('\x00', self.null_replacement)

		return name

	def _yarp_deposixify_name(self, name):
		record_type = 0 # 0: unknown; 1: key; 2: value.

		if name == self.default_name: # This is an empty name.
			record_type = 2
			return ('', record_type)

		# Remove the conflict suffix, if present.
		if name.endswith(self.conflict_suffix_value):
			name = name[ : -len(self.conflict_suffix_value)]
			record_type = 2
		elif name.endswith(self.conflict_suffix_key):
			name = name[ : -len(self.conflict_suffix_key)]
			record_type = 1

		# Undo the replacement strings.
		if self.slash_replacement in name:
			name = name.replace(self.slash_replacement, '/')
		if self.null_replacement in name:
			name = name.replace(self.null_replacement, '\x00')

		return (name, record_type)

	def _yarp_get_cell(self, cell_relative_offset):
		if cell_relative_offset != llfuse.ROOT_INODE:
			return self._yarp_get_cell_worker(cell_relative_offset)

		return self._yarp_get_cell_worker(self._yarp_root_cell_offset)

	def _yarp_parse(self, cell_relative_offset, skip = 0):
		if not self._yarp_is_key(cell_relative_offset):
			raise llfuse.FUSEError(errno.EBADF)

		buf = self._yarp_get_cell(cell_relative_offset)
		key_node = RegistryRecords.KeyNode(buf)

		skipped = 0

		# Parse subkeys.
		if key_node.get_subkeys_count() > 0:
			list_offset = key_node.get_subkeys_list_offset()
			list_buf = self._yarp_get_cell(list_offset)
			if list_buf[ : 2] == b'ri':
				ri_list = RegistryRecords.IndexRoot(list_buf)
				for list_offset_2 in ri_list.elements():
					list_buf_2 = self._yarp_get_cell(list_offset_2)
					subkeys_list = self._yarp_get_leaf(list_buf_2)

					subkeys_cnt = subkeys_list.get_elements_count()
					if skipped + subkeys_cnt <= skip:
						skipped += subkeys_cnt
						continue

					for element in subkeys_list.elements():
						if skipped < skip:
							skipped += 1
							continue

						relative_offset = element.relative_offset

						subkey = RegistryRecords.KeyNode(self._yarp_get_cell(relative_offset))
						if self._yarp_version > 1 and subkey.get_flags() & RegistryRecords.KEY_COMP_NAME > 0:
							curr_name = Registry.DecodeASCII(subkey.get_key_name())
						else:
							curr_name = Registry.DecodeUnicode(subkey.get_key_name())

						curr_name = self._yarp_posixify_name(curr_name, cell_relative_offset, False)
						yield (curr_name, self._yarp_construct_attr(relative_offset))
			else:
				subkeys_list = self._yarp_get_leaf(list_buf)
				for element in subkeys_list.elements():
					if skipped < skip:
						skipped += 1
						continue

					relative_offset = element.relative_offset

					subkey = RegistryRecords.KeyNode(self._yarp_get_cell(relative_offset))
					if self._yarp_version > 1 and subkey.get_flags() & RegistryRecords.KEY_COMP_NAME > 0:
						curr_name = Registry.DecodeASCII(subkey.get_key_name())
					else:
						curr_name = Registry.DecodeUnicode(subkey.get_key_name())

					curr_name = self._yarp_posixify_name(curr_name, cell_relative_offset, False)
					yield (curr_name, self._yarp_construct_attr(relative_offset))

		# Parse values.
		values_count = key_node.get_key_values_count()

		if values_count > 0 and key_node.get_flags() & RegistryRecords.KEY_PREDEF_HANDLE == 0:
			list_offset = key_node.get_key_values_list_offset()
			list_buf = self._yarp_get_cell(list_offset)
			values_list = RegistryRecords.KeyValuesList(list_buf, values_count)
			for relative_offset in values_list.elements():
				if skipped < skip:
					skipped += 1
					continue

				value = RegistryRecords.KeyValue(self._yarp_get_cell(relative_offset))
				if self._yarp_version > 1 and value.get_flags() & RegistryRecords.VALUE_COMP_NAME > 0:
					curr_name = Registry.DecodeASCII(value.get_value_name())
				else:
					curr_name = Registry.DecodeUnicode(value.get_value_name())

				curr_name = self._yarp_posixify_name(curr_name, cell_relative_offset, True)
				yield (curr_name, self._yarp_construct_attr(relative_offset))

	def _yarp_lookup_by_name(self, cell_relative_offset, name):
		if not self._yarp_is_key(cell_relative_offset):
			raise llfuse.FUSEError(errno.EBADF)

		buf = self._yarp_get_cell(cell_relative_offset)
		key_node = RegistryRecords.KeyNode(buf)

		# Handle the following special cases.
		if name == '.':
			return self._yarp_construct_attr(cell_relative_offset)

		if name == '..':
			if cell_relative_offset != self._yarp_root_cell_offset and cell_relative_offset != llfuse.ROOT_INODE:
				return self._yarp_construct_attr(key_node.get_parent())
			else:
				raise llfuse.FUSEError(errno.ENOENT)

		# The usual case.
		name, record_type = self._yarp_deposixify_name(name)
		name_upper = RegistryUnicode.Upper(name)

		# Check the cache first.
		if self._enable_cache and cell_relative_offset in self._yarp_cache.keys() and name in self._yarp_cache[cell_relative_offset].keys():
			cached_offset = self._yarp_cache[cell_relative_offset][name]
			return self._yarp_construct_attr(cached_offset)

		# Search in subkeys.
		if key_node.get_subkeys_count() > 0 and (record_type == 0 or record_type == 1):
			subkeys_offsets = []

			list_offset = key_node.get_subkeys_list_offset()
			list_buf = self._yarp_get_cell(list_offset)
			if list_buf[ : 2] == b'ri':
				ri_list = RegistryRecords.IndexRoot(list_buf)
				for list_offset_2 in ri_list.elements():
					list_buf_2 = self._yarp_get_cell(list_offset_2)
					subkeys_list = self._yarp_get_leaf(list_buf_2)

					for element in subkeys_list.elements():
						subkeys_offsets.append(element.relative_offset)
			else:
				subkeys_list = self._yarp_get_leaf(list_buf)
				for element in subkeys_list.elements():
					subkeys_offsets.append(element.relative_offset)

			# The binary search.
			lo = 0
			hi = len(subkeys_offsets)
			while lo < hi:
				mid = (lo + hi) // 2

				relative_offset = subkeys_offsets[mid]
				subkey = RegistryRecords.KeyNode(self._yarp_get_cell(relative_offset))
				if self._yarp_version > 1 and subkey.get_flags() & RegistryRecords.KEY_COMP_NAME > 0:
					curr_name = Registry.DecodeASCII(subkey.get_key_name())
				else:
					curr_name = Registry.DecodeUnicode(subkey.get_key_name())

				if RegistryUnicode.Upper(curr_name) < name_upper:
					lo = mid + 1
				else:
					hi = mid

			if lo != len(subkeys_offsets):
				relative_offset = subkeys_offsets[lo]
				subkey = RegistryRecords.KeyNode(self._yarp_get_cell(relative_offset))
				if self._yarp_version > 1 and subkey.get_flags() & RegistryRecords.KEY_COMP_NAME > 0:
					curr_name = Registry.DecodeASCII(subkey.get_key_name())
				else:
					curr_name = Registry.DecodeUnicode(subkey.get_key_name())

				if curr_name == name:
					return self._yarp_construct_attr(relative_offset)

		# Search in values.
		values_count = key_node.get_key_values_count()

		if values_count > 0 and key_node.get_flags() & RegistryRecords.KEY_PREDEF_HANDLE == 0 and (record_type == 0 or record_type == 2):
			list_offset = key_node.get_key_values_list_offset()
			list_buf = self._yarp_get_cell(list_offset)
			values_list = RegistryRecords.KeyValuesList(list_buf, values_count)
			for relative_offset in values_list.elements():
				value = RegistryRecords.KeyValue(self._yarp_get_cell(relative_offset))
				if self._yarp_version > 1 and value.get_flags() & RegistryRecords.VALUE_COMP_NAME > 0:
					curr_name = Registry.DecodeASCII(value.get_value_name())
				else:
					curr_name = Registry.DecodeUnicode(value.get_value_name())

				if curr_name == name:
					return self._yarp_construct_attr(relative_offset)

		raise llfuse.FUSEError(errno.ENOENT)

	def _yarp_parse_data(self, cell_relative_offset):
		if not self._yarp_is_value(cell_relative_offset):
			raise llfuse.FUSEError(errno.EBADF)

		buf = self._yarp_get_cell(cell_relative_offset)
		key_value = RegistryRecords.KeyValue(buf)

		if key_value.get_data_size_real() == 0:
			return b''

		if key_value.is_data_inline():
			return key_value.get_inline_data()[ : key_value.get_data_size_real()]

		is_big_data = self._yarp_version > 3 and key_value.get_data_size_real() > 16344
		if not is_big_data:
			return self._yarp_get_cell(key_value.get_data_offset())[ : key_value.get_data_size_real()]

		big_data_buf = self._yarp_get_cell(key_value.get_data_offset())
		big_data = RegistryRecords.BigData(big_data_buf)

		segments_list_offset = big_data.get_segments_list_offset()
		segments_count = big_data.get_segments_count()

		segments_list = RegistryRecords.SegmentsList(self._yarp_get_cell(segments_list_offset), segments_count)

		data = b''
		data_length = key_value.get_data_size_real()
		for segment_offset in segments_list.elements():
			buf = self._yarp_get_cell(segment_offset)

			if data_length > 16344:
				data_part = buf[ : 16344]
				data += data_part
				data_length -= 16344
			else:
				data += buf[ : data_length]
				break

		return data

	def _yarp_parse_classname(self, cell_relative_offset):
		if not self._yarp_is_key(cell_relative_offset):
			raise llfuse.FUSEError(errno.EBADF)

		buf = self._yarp_get_cell(cell_relative_offset)
		key_node = RegistryRecords.KeyNode(buf)

		classname_length = key_node.get_classname_length()
		if classname_length == 0:
			return b''

		buf_classname = self._yarp_get_cell(key_node.get_classname_offset())
		return buf_classname[ : classname_length]

	def _yarp_parse_data_type(self, cell_relative_offset):
		if not self._yarp_is_value(cell_relative_offset):
			raise llfuse.FUSEError(errno.EBADF)

		buf = self._yarp_get_cell(cell_relative_offset)
		key_value = RegistryRecords.KeyValue(buf)

		data_type = key_value.get_data_type()
		if data_type in Registry.ValueTypes.keys():
			data_type_str = Registry.ValueTypes[data_type]
		else:
			data_type_str = hex(data_type)

		return data_type_str.encode(self._yarp_encoding)

	def _yarp_construct_attr(self, cell_relative_offset):
		if not self._yarp_is_virtual_inode(cell_relative_offset):
			raise llfuse.FUSEError(errno.EBADF)

		attr = llfuse.EntryAttributes()

		attr.st_ino = cell_relative_offset
		attr.generation = 0

		attr.entry_timeout = 300
		attr.attr_timeout = 300

		attr.st_nlink = 1

		if self._yarp_is_key(cell_relative_offset):
			attr.st_mode = (stat.S_IFDIR | 0o755)
			attr.st_size = 4096

			buf = self._yarp_get_cell(cell_relative_offset)
			key_node = RegistryRecords.KeyNode(buf)

			ts_filetime = key_node.get_last_written_timestamp()
			try:
				attr.st_mtime_ns = self._yarp_convert_timestamp(ts_filetime)
			except (ValueError, OverflowError):
				attr.st_mtime_ns = 0
		else:
			attr.st_mode = (stat.S_IFREG | 0o644)
			attr.st_mtime_ns = 0

			buf = self._yarp_get_cell(cell_relative_offset)
			key_value = RegistryRecords.KeyValue(buf)

			attr.st_size = key_value.get_data_size_real()

		attr.st_uid = os.getuid()
		attr.st_gid = os.getgid()

		attr.st_atime_ns = 0
		attr.st_ctime_ns = 0

		attr.st_rdev = 0
		attr.st_blksize = 512
		attr.st_blocks = (attr.st_size + 512 - 1) // 512

		return attr

	def _yarp_cell_relative_offset_to_handle(self, cell_relative_offset):
		self._yarp_cell_relative_offsets.append(cell_relative_offset)
		return cell_relative_offset

	def _yarp_handle_to_cell_relative_offset(self, handle):
		if handle not in self._yarp_cell_relative_offsets:
			raise llfuse.FUSEError(errno.EBADF)

		return handle

	def _yarp_release_handle(self, handle):
		cell_relative_offset = self._yarp_handle_to_cell_relative_offset(handle)
		self._yarp_cell_relative_offsets.remove(cell_relative_offset)

	def init(self):
		# Pick the effective version.
		self._yarp_version = self._yarp_primary.baseblock.effective_version

		# Pick the root cell offset.
		self._yarp_root_cell_offset = self._yarp_primary.baseblock.effective_root_cell_offset

		# Pick the get_cell() method.
		self._yarp_get_cell_worker = self._yarp_primary.get_cell

		# Create a list for cell relative offsets (to track handles).
		self._yarp_cell_relative_offsets = []

	def destroy(self):
		# Close the primary file.
		self._yarp_file.close()

		# Close the transaction log files.
		if self._yarp_log is not None:
			self._yarp_log.close()

		if self._yarp_log1 is not None:
			self._yarp_log1.close()

		if self._yarp_log2 is not None:
			self._yarp_log2.close()

	def access(self, inode, mode, ctx):
		return True

	def getattr(self, inode, ctx):
		return self._yarp_construct_attr(inode)

	def open(self, inode, flags, ctx):
		flags_writable = os.O_WRONLY | os.O_RDWR | os.O_APPEND
		if flags & flags_writable > 0:
			raise llfuse.FUSEError(errno.EROFS)

		return self._yarp_cell_relative_offset_to_handle(inode)

	def opendir(self, inode, ctx):
		return self._yarp_cell_relative_offset_to_handle(inode)

	def lookup(self, parent_inode, name, ctx):
		name = name.decode(self._yarp_encoding)
		return self._yarp_lookup_by_name(parent_inode, name)

	def read(self, fh, off, size):
		data = self._yarp_parse_data(self._yarp_handle_to_cell_relative_offset(fh))
		return data[off : off + size]

	def readdir(self, fh, off):
		cell_relative_offset = self._yarp_handle_to_cell_relative_offset(fh)

		i = off
		for name, attr in self._yarp_parse(cell_relative_offset, off):
			yield (name.encode(self._yarp_encoding), attr, i + 1)
			i += 1

	def release(self, fh):
		self._yarp_release_handle(fh)

	def releasedir(self, fh):
		self._yarp_release_handle(fh)

	def listxattr(self, inode, ctx):
		if not self._yarp_is_virtual_inode(inode):
			raise llfuse.FUSEError(errno.EBADF)

		if self._yarp_is_key(inode):
			yield XATTR_CLASSNAME
		else:
			yield XATTR_DATA_TYPE

	def getxattr(self, inode, name, ctx):
		if not self._yarp_is_virtual_inode(inode):
			raise llfuse.FUSEError(errno.EBADF)

		is_key = self._yarp_is_key(inode)
		if is_key and name == XATTR_CLASSNAME:
			return self._yarp_parse_classname(inode)

		if (not is_key) and name == XATTR_DATA_TYPE:
			return self._yarp_parse_data_type(inode)

		raise llfuse.FUSEError(llfuse.ENOATTR)

	def statfs(self, ctx):
		stat = llfuse.StatvfsData()

		stat.f_bsize = 512
		stat.f_frsize = 512

		# We use dummy values here.
		stat.f_blocks = 0
		stat.f_bfree = 0
		stat.f_bavail = 0
		stat.f_files = 0
		stat.f_ffree = 0
		stat.f_favail = 0

		return stat

	def create(self, parent_inode, name, mode, flags, ctx):
		raise llfuse.FUSEError(errno.EROFS)

	def fsync(self, fh, datasync):
		raise llfuse.FUSEError(errno.EROFS)

	def fsyncdir(self, fh, datasync):
		raise llfuse.FUSEError(errno.EROFS)

	def link(self, inode, new_parent_inode, new_name, ctx):
		raise llfuse.FUSEError(errno.EROFS)

	def mkdir(self, parent_inode, name, mode, ctx):
		raise llfuse.FUSEError(errno.EROFS)

	def mknod(self, parent_inode, name, mode, rdev, ctx):
		raise llfuse.FUSEError(errno.EROFS)

	def removexattr(self, inode, name, ctx):
		raise llfuse.FUSEError(errno.EROFS)

	def rename(self, parent_inode_old, name_old, parent_inode_new, name_new, ctx):
		raise llfuse.FUSEError(errno.EROFS)

	def rmdir(self, parent_inode, name, ctx):
		raise llfuse.FUSEError(errno.EROFS)

	def setattr(self, inode, attr, fields, fh, ctx):
		raise llfuse.FUSEError(errno.EROFS)

	def setxattr(self, inode, name, value, ctx):
		raise llfuse.FUSEError(errno.EROFS)

	def symlink(self, parent_inode, name, target, ctx):
		raise llfuse.FUSEError(errno.EROFS)

	def unlink(self, parent_inode, name, ctx):
		raise llfuse.FUSEError(errno.EROFS)

	def write(self, fh, off, buf):
		raise llfuse.FUSEError(errno.EROFS)
