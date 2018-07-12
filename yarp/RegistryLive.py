#!/usr/bin/env python3
# (c) Maxim Suhanov
#
# This extra module implements an interface to acquire and open registry hives from a live (running) system.
# Python 3 only. The code may work with Python 2, but this is not supported by the author.

import ctypes

__revision__ = 2 # This value will be incremented each time this module is updated.

# Definitions: constants and structures
_TOKEN_ADJUST_PRIVILEGES = 0x20
_SE_PRIVILEGE_ENABLED = 0x2
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_CREATE_ALWAYS = 2
_FILE_ATTRIBUTE_NORMAL = 0x80
_FILE_ATTRIBUTE_TEMPORARY = 0x100
_FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
_FILE_SHARE_READ = 1
_FILE_SHARE_WRITE = 2
_FILE_SHARE_DELETE = 4
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_KEY_READ = 0x20019
_KEY_WOW64_64KEY = 0x100
_STATUS_INVALID_PARAMETER = ctypes.c_int32(0xC000000D).value
_REG_NO_COMPRESSION = 4

_INVALID_SET_FILE_POINTER = 0xFFFFFFFF

_HKEY_USERS = 0x80000003
_HKEY_LOCAL_MACHINE = 0x80000002

class _LUID(ctypes.Structure):
	_fields_ = [ ('LowPart', ctypes.c_uint32), ('HighPart', ctypes.c_int32) ]

class _LUID_AND_ATTRIBUTES(ctypes.Structure):
	_fields_ = [ ('Luid', _LUID), ('Attributes', ctypes.c_uint32) ]

class _TOKEN_PRIVILEGES_5(ctypes.Structure): # This defines 5 array elements.
	_fields_ = [ ('PrivilegeCount', ctypes.c_uint32), ('Privilege0', _LUID_AND_ATTRIBUTES),
		('Privilege1', _LUID_AND_ATTRIBUTES), ('Privilege2', _LUID_AND_ATTRIBUTES),
		('Privilege3', _LUID_AND_ATTRIBUTES), ('Privilege4', _LUID_AND_ATTRIBUTES) ]

# Definitions: functions (API)
ctypes.windll.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
ctypes.windll.kernel32.GetCurrentProcess.argtypes = []

ctypes.windll.advapi32.LookupPrivilegeValueW.restype = ctypes.c_int32
ctypes.windll.advapi32.LookupPrivilegeValueW.argtypes = [  ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p ]

ctypes.windll.advapi32.OpenProcessToken.restype = ctypes.c_int32
ctypes.windll.advapi32.OpenProcessToken.argtypes = [ ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p ]

ctypes.windll.advapi32.AdjustTokenPrivileges.restype = ctypes.c_int32
ctypes.windll.advapi32.AdjustTokenPrivileges.argtypes = [ ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p ]

ctypes.windll.kernel32.GetLastError.restype = ctypes.c_uint32
ctypes.windll.kernel32.GetLastError.argtypes = []

ctypes.windll.kernel32.CloseHandle.restype = ctypes.c_int32
ctypes.windll.kernel32.CloseHandle.argtypes = [ ctypes.c_void_p ]

ctypes.windll.kernel32.CreateFileW.restype = ctypes.c_void_p
ctypes.windll.kernel32.CreateFileW.argtypes = [ ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p ]

ctypes.windll.advapi32.RegOpenKeyExW.restype = ctypes.c_int32
ctypes.windll.advapi32.RegOpenKeyExW.argtypes = [ ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p ]

ctypes.windll.advapi32.RegCloseKey.restype = ctypes.c_int32
ctypes.windll.advapi32.RegCloseKey.argtypes = [ ctypes.c_void_p ]

ctypes.windll.advapi32.RegOpenCurrentUser.restype = ctypes.c_int32
ctypes.windll.advapi32.RegOpenCurrentUser.argtypes = [ ctypes.c_uint32, ctypes.c_void_p ]

_APP_HIVES_SUPPORTED = hasattr(ctypes.windll.advapi32, 'RegLoadAppKeyW')
if _APP_HIVES_SUPPORTED:
	ctypes.windll.advapi32.RegLoadAppKeyW.restype = ctypes.c_int32
	ctypes.windll.advapi32.RegLoadAppKeyW.argtypes = [ ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32 ]

ctypes.windll.ntdll.NtSaveKeyEx.restype = ctypes.c_int32
ctypes.windll.ntdll.NtSaveKeyEx.argtypes = [ ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32 ]

ctypes.windll.kernel32.GetTempFileNameA.restype = ctypes.c_uint32
ctypes.windll.kernel32.GetTempFileNameA.argtypes = [ ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_void_p ]

ctypes.windll.kernel32.SetFilePointer.restype = ctypes.c_uint32
ctypes.windll.kernel32.SetFilePointer.argtypes = [ ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32 ]

ctypes.windll.kernel32.ReadFile.restype = ctypes.c_int32
ctypes.windll.kernel32.ReadFile.argtypes = [ ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p ]
# End of definitions

class NTFileLikeObject(object):
	"""This class implements a read-only file-like object for a given file handle (as returned by the CreateFile() routine)."""

	def __init__(self, handle):
		self.handle = handle
		self.max_size = self.seek(0, 2)
		self.seek(0, 0)

	def seek(self, offset, whence = 0):
		offset = ctypes.windll.kernel32.SetFilePointer(self.handle, offset, None, whence)
		if offset == _INVALID_SET_FILE_POINTER:
			raise OSError('The SetFilePointer() routine failed')

		return offset

	def tell(self):
		return self.seek(0, 1)

	def read(self, size = None):
		if size is None or size < 0:
			size = self.max_size - self.tell()

		if size <= 0: # Nothing to read.
			return b''

		buffer = ctypes.create_string_buffer(size)
		size_out = ctypes.c_uint32()

		result = ctypes.windll.kernel32.ReadFile(self.handle, ctypes.byref(buffer), size, ctypes.byref(size_out), None)
		if result == 0:
			last_error = ctypes.windll.kernel32.GetLastError()
			raise OSError('The ReadFile() routine failed with this status: {}'.format(last_error))

		return buffer.raw[ : size_out.value]

	def close(self):
		ctypes.windll.kernel32.CloseHandle(self.handle)

class RegistryHivesLive(object):
	"""This class is used to acquire and open hives from a live (running) system."""

	def __init__(self):
		self._src_handle = None
		self._dst_handle = None

		self._hkcu_handle = None

		# Acquire the backup privilege.
		self._lookup_process_handle_and_backup_privilege()
		self._acquire_backup_privilege()

	def _lookup_process_handle_and_backup_privilege(self):
		"""Get the handle of the current process, get the LUID value for the 'SeBackupPrivilege' privilege."""

		self._proc = ctypes.windll.kernel32.GetCurrentProcess()

		self._backup_luid = _LUID()
		result = ctypes.windll.advapi32.LookupPrivilegeValueW(None, 'SeBackupPrivilege', ctypes.byref(self._backup_luid))
		if result == 0:
			raise OSError('The LookupPrivilegeValueW() routine failed to resolve the \'SeBackupPrivilege\' name')

	def _acquire_backup_privilege(self):
		"""Acquire the 'SeBackupPrivilege' privilege for the current process."""

		handle = ctypes.c_void_p()

		result = ctypes.windll.advapi32.OpenProcessToken(self._proc, _TOKEN_ADJUST_PRIVILEGES, ctypes.byref(handle))
		if result == 0:
			raise OSError('The OpenProcessToken() routine failed to provide the TOKEN_ADJUST_PRIVILEGES access')

		tp = _TOKEN_PRIVILEGES_5()
		tp.PrivilegeCount = 1
		tp.Privilege0 = _LUID_AND_ATTRIBUTES()
		tp.Privilege0.Luid = self._backup_luid
		tp.Privilege0.Attributes = _SE_PRIVILEGE_ENABLED

		result_1 = ctypes.windll.advapi32.AdjustTokenPrivileges(handle, False, ctypes.byref(tp), 0, None, None)
		result_2 = ctypes.windll.kernel32.GetLastError()
		if result_1 == 0 or result_2 != 0:
			ctypes.windll.kernel32.CloseHandle(handle)
			raise OSError('The AdjustTokenPrivileges() routine failed to set the backup privilege')

		ctypes.windll.kernel32.CloseHandle(handle)

	def _create_destination_handle(self, FilePath):
		"""Create a file for the exported hive. When 'FilePath' is None, create a temporary file (in a current directory).
		This method returns a path to that file.
		"""

		if FilePath is None:
			file_attr = _FILE_ATTRIBUTE_TEMPORARY | _FILE_FLAG_DELETE_ON_CLOSE
			FilePath = self._temp_file()
		else:
			file_attr = _FILE_ATTRIBUTE_NORMAL

		handle = ctypes.windll.kernel32.CreateFileW(FilePath, _GENERIC_READ | _GENERIC_WRITE, _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE, None, _CREATE_ALWAYS, file_attr, None)
		if handle == _INVALID_HANDLE_VALUE:
			raise OSError('The CreateFileW() routine failed to create a file')

		self._dst_handle = handle
		return FilePath

	def _close_destination_handle(self):
		"""Close a file for the exported hive."""

		ctypes.windll.kernel32.CloseHandle(self._dst_handle)
		self._dst_handle = None

	def _open_root_key(self, PredefinedKey, KeyPath, WOW64 = False):
		"""Open the root key of a hive."""

		handle = ctypes.c_void_p()

		if not WOW64:
			access_rights = _KEY_READ
		else:
			access_rights = _KEY_READ | _KEY_WOW64_64KEY

		result = ctypes.windll.advapi32.RegOpenKeyExW(PredefinedKey, KeyPath, 0, access_rights, ctypes.byref(handle))
		if result != 0:
			raise OSError('The RegOpenKeyExW() failed to open a key')

		self._src_handle = handle

	def _load_application_hive(self, HivePath):
		"""Load an application hive."""

		if not _APP_HIVES_SUPPORTED:
			raise OSError('Application hives are not supported on this system')

		handle = ctypes.c_void_p()
		result = ctypes.windll.advapi32.RegLoadAppKeyW(HivePath, ctypes.byref(handle), _KEY_READ, 0, 0)
		if result != 0:
			raise OSError('The RegLoadAppKeyW() routine failed to load a hive')

		self._src_handle = handle

	def _close_root_key(self):
		"""Close the root key of a hive."""

		ctypes.windll.advapi32.RegCloseKey(self._src_handle)
		self._src_handle = None

	def open_hive_by_key(self, RegistryPath, FilePath = None):
		"""Export and then open a hive using its registry path.
		If 'FilePath' is not None, use this path to save an exported hive (as a file).
		If 'FilePath' is None, create a temporary file to store an exported hive (in a current directory).
		This method returns a file-like object for an exported hive.
		"""

		if self._src_handle is not None:
			self._close_root_key()

		if self._dst_handle is not None:
			self._dst_handle = None

		PredefinedKey, KeyPath = self._resolve_path(RegistryPath)

		FilePath = self._create_destination_handle(FilePath)
		try:
			self._open_root_key(PredefinedKey, KeyPath)
		except Exception:
			self._close_destination_handle()
			raise

		result = ctypes.windll.ntdll.NtSaveKeyEx(self._src_handle, self._dst_handle, _REG_NO_COMPRESSION)
		if result == _STATUS_INVALID_PARAMETER: # We are running under the Wow64 subsystem.
			self._close_root_key()
			try:
				self._open_root_key(PredefinedKey, KeyPath, True)
			except Exception:
				self._close_destination_handle()
				raise

			result = ctypes.windll.ntdll.NtSaveKeyEx(self._src_handle, self._dst_handle, _REG_NO_COMPRESSION)

		if result != 0:
			self._close_root_key()
			self._close_destination_handle()
			raise OSError('The NtSaveKeyEx() routine failed with this status: {}'.format(hex(result)))

		self._close_root_key()

		f = NTFileLikeObject(self._dst_handle)
		return f

	def open_apphive_by_file(self, AppHivePath, FilePath = None):
		"""Export and then open an application hive using its file system path.
		If 'FilePath' is not None, use this path to save an exported hive (as a file).
		If 'FilePath' is None, create a temporary file to store an exported hive (in a current directory).
		This method returns a file-like object for an exported hive.
		"""

		if self._src_handle is not None:
			self._close_root_key()

		if self._dst_handle is not None:
			self._dst_handle = None

		FilePath = self._create_destination_handle(FilePath)
		try:
			self._load_application_hive(AppHivePath)
		except Exception:
			self._close_destination_handle()
			raise

		result = ctypes.windll.ntdll.NtSaveKeyEx(self._src_handle, self._dst_handle, _REG_NO_COMPRESSION)
		if result != 0:
			self._close_root_key()
			self._close_destination_handle()
			raise OSError('The NtSaveKeyEx() routine failed with this status: {}'.format(hex(result)))

		self._close_root_key()

		f = NTFileLikeObject(self._dst_handle)
		return f

	def _resolve_predefined_key(self, PredefinedKeyStr):
		"""Convert a predefined key (as a string) to an integer."""

		predef_str = PredefinedKeyStr.upper()

		if predef_str == 'HKU' or predef_str == 'HKEY_USERS':
			return _HKEY_USERS

		if predef_str == 'HKCU' or predef_str == 'HKEY_CURRENT_USER':
			if self._hkcu_handle is None:
				handle = ctypes.c_void_p()
				result = ctypes.windll.advapi32.RegOpenCurrentUser(_KEY_READ, ctypes.byref(handle))
				if result != 0:
					raise OSError('The RegOpenCurrentUser() failed to open a root key')

				self._hkcu_handle = handle

			return self._hkcu_handle

		if predef_str == 'HKLM' or predef_str == 'HKEY_LOCAL_MACHINE':
			return _HKEY_LOCAL_MACHINE

		raise ValueError('Cannot resolve this predefined key or it is not supported: {}'.format(PredefinedKeyStr))

	def _resolve_path(self, PathStr):
		"""Resolve a registry path (as a string), return a tuple (predefined_key, key_path)."""

		path_components = PathStr.split('\\')
		if len(path_components) == 0:
			raise ValueError('The registry path specified contains no path components')

		predefined_key = self._resolve_predefined_key(path_components[0])
		key_path = '\\'.join(path_components[1 : ])

		return (predefined_key, key_path)

	def _temp_file(self):
		"""Get and return a path for a temporary file."""

		buffer = ctypes.create_string_buffer(513)
		result = ctypes.windll.kernel32.GetTempFileNameA(b'.', b'hiv', 0, ctypes.byref(buffer))
		if result == 0:
			raise OSError('The GetTempFileNameA() routine failed to create a temporary file')

		tempfile = buffer.value.decode()

		return tempfile

def _RunTests():
	"""Run the tests (assertions must be enabled)."""

	if not __debug__:
		print('Assertions disabled')

	live_hives = RegistryHivesLive()

	def test_hive(key_path):
		f = live_hives.open_hive_by_key(key_path)

		assert f.read(4) == b'regf'
		assert f.read(4) == f.read(4)

		f.seek(-13, 2)
		assert len(f.read()) == 13

		f.seek(0, 2)
		assert f.read() == b''
		f.seek(15, 2)
		assert f.read() == b''

		f.close()

	def test_apphive(file_path):
		f = live_hives.open_hive_by_key(key_path)

		assert f.read(4) == b'regf'
		assert f.read(4) == f.read(4)

		f.seek(-4, 2)
		assert len(f.read()) == 4

		f.seek(0, 2)
		assert f.read() == b''
		f.seek(15, 2)
		assert f.read() == b''

		f.close()

	for key_path in [ 'HKEY_LOCAL_MACHINE\\SOFTWARE', 'HKLM\\SYSTEM', 'HKLM\\SAM', 'HKCU', 'HKEY_CURRENT_USER\\', 'HKU\\.DEFAULT', 'HKEY_USERS\\.DEFAULT' ]:
		test_hive(key_path)

	for file_path in [ 'C:\\WINDOWS\\APPCOMPAT\\PROGRAMS\\AMCACHE.HVE' ]:
		import os.path

		if os.path.isfile(file_path):
			test_apphive(file_path)

	print('Done')

if __name__ == '__main__':
	_RunTests()
