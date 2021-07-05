# coding: utf-8

# yarp: yet another registry parser
# (c) Maxim Suhanov

import pytest
import sys
import tarfile
from io import BytesIO
from os import path, remove
from hashlib import md5
from yarp import Registry, RegistryFile, RegistryRecords, RegistryRecover, RegistryCarve, RegistrySqlite, RegistryHelpers, RegistryUnicode

HIVES_DIR = 'hives_for_tests'
RECORDS_DIR = 'records_for_tests'

hive_empty = path.join(HIVES_DIR, 'EmptyHive')
hive_bigdata = path.join(HIVES_DIR, 'BigDataHive')
hive_many_subkeys = path.join(HIVES_DIR, 'ManySubkeysHive')
hive_garbage = path.join(HIVES_DIR, 'GarbageHive')
hive_duplicate_subkeys = path.join(HIVES_DIR, 'DuplicateSubkeysHive')

hive_dirty_new1 = path.join(HIVES_DIR, 'NewDirtyHive1', 'NewDirtyHive')
hive_dirty_new1_log1 = path.join(HIVES_DIR, 'NewDirtyHive1', 'NewDirtyHive.LOG1')
hive_dirty_new1_log2 = path.join(HIVES_DIR, 'NewDirtyHive1', 'NewDirtyHive.LOG2')
hive_dirty_new1_recovered = path.join(HIVES_DIR, 'NewDirtyHive1', 'RecoveredHive_Windows10')

hive_dirty_new2 = path.join(HIVES_DIR, 'NewDirtyHive2', 'NewDirtyHive')
hive_dirty_new2_log1 = path.join(HIVES_DIR, 'NewDirtyHive2', 'NewDirtyHive.LOG1')
hive_dirty_new2_log2 = path.join(HIVES_DIR, 'NewDirtyHive2', 'NewDirtyHive.LOG2')

hive_dirty_old = path.join(HIVES_DIR, 'OldDirtyHive', 'OldDirtyHive')
hive_dirty_old_log = path.join(HIVES_DIR, 'OldDirtyHive', 'OldDirtyHive.LOG1')
hive_dirty_old_recovered = path.join(HIVES_DIR, 'OldDirtyHive', 'RecoveredHive_Windows7')

hive_unicode = path.join(HIVES_DIR, 'UnicodeHive')
hive_extended_ascii = path.join(HIVES_DIR, 'ExtendedASCIIHive')
hive_upcase = path.join(HIVES_DIR, 'UpcaseHive')
hive_pair = path.join(HIVES_DIR, 'PairHive')
hive_truncated_pair1 = path.join(HIVES_DIR, 'TruncatedPairHive')
hive_truncated_pair2 = path.join(HIVES_DIR, 'TruncatedPairHive2')
hive_invalid_parent = path.join(HIVES_DIR, 'InvalidParentHive')
hive_bad_list = path.join(HIVES_DIR, 'BadListHive')
hive_bad_subkey = path.join(HIVES_DIR, 'BadSubkeyHive')

hive_bad_baseblock = path.join(HIVES_DIR, 'BadBaseBlockHive', 'BadBaseBlockHive')
hive_bad_baseblock_log1 = path.join(HIVES_DIR, 'BadBaseBlockHive', 'BadBaseBlockHive.LOG1')
hive_bad_baseblock_log2 = path.join(HIVES_DIR, 'BadBaseBlockHive', 'BadBaseBlockHive.LOG2')

hive_bad_log1 = path.join(HIVES_DIR, 'BadLogHive1', 'BadLogHive')
hive_bad_log1_log1 = path.join(HIVES_DIR, 'BadLogHive1', 'BadLogHive.LOG1')
hive_bad_log1_log2 = path.join(HIVES_DIR, 'BadLogHive1', 'BadLogHive.LOG2')

hive_bad_log2 = path.join(HIVES_DIR, 'BadLogHive2', 'BadLogHive')
hive_bad_log2_log1 = path.join(HIVES_DIR, 'BadLogHive2', 'BadLogHive.LOG1')
hive_bad_log2_log2 = path.join(HIVES_DIR, 'BadLogHive2', 'BadLogHive.LOG2')

hive_bad_log3 = path.join(HIVES_DIR, 'BadLogHive3', 'BadLogHive')
hive_bad_log3_log1 = path.join(HIVES_DIR, 'BadLogHive3', 'BadLogHive.LOG1')
hive_bad_log3_log2 = path.join(HIVES_DIR, 'BadLogHive3', 'BadLogHive.LOG2')

hive_bogus_keynames = path.join(HIVES_DIR, 'BogusKeyNamesHive')
hive_new_flags = path.join(HIVES_DIR, 'NewFlagsHive')
hive_multisz = path.join(HIVES_DIR, 'MultiSzHive')
hive_strings = path.join(HIVES_DIR, 'StringValuesHive')
hive_wrong_order = path.join(HIVES_DIR, 'WrongOrderHive')
hive_truncated_name = path.join(HIVES_DIR, 'TruncatedNameHive')
hive_healed = path.join(HIVES_DIR, 'HealedHive')
hive_deleted_data = path.join(HIVES_DIR, 'DeletedDataHive')
hive_deleted_data_truncated = path.join(HIVES_DIR, 'DeletedDataHiveTruncated')
hive_deleted_tree = path.join(HIVES_DIR, 'DeletedTreeHive')
hive_comp = path.join(HIVES_DIR, 'CompHive')
hive_remnants = path.join(HIVES_DIR, 'RemnantsHive')
hive_truncated = path.join(HIVES_DIR, 'TruncatedHive')
hive_effective_size = path.join(HIVES_DIR, 'EffectiveSizeHive')
hive_deleted_tree_no_root_flag = path.join(HIVES_DIR, 'DeletedTreeNoRootFlagHive')
hive_deleted_tree_partial_path = path.join(HIVES_DIR, 'DeletedTreePartialPathHive')
hive_slack = path.join(HIVES_DIR, 'SlackHive')
hive_truncated_dirty = path.join(HIVES_DIR, 'TruncatedDirtyHive')
hive_values_order = path.join(HIVES_DIR, 'ValuesOrderHive')

log_with_remnant_data = path.join(HIVES_DIR, 'OldLogWithRemnantData')

delta_hive = path.join(HIVES_DIR, 'System_Delta')

hive_carving0 = path.join(HIVES_DIR, 'Carving', '0')
hive_carving512 = path.join(HIVES_DIR, 'Carving', '512')
hive_carving_fragments = path.join(HIVES_DIR, 'Carving', 'HiveAndFragments')

hive_carving_margin0_1 = path.join(HIVES_DIR, 'Carving', 'Margin0_1')
hive_carving_margin0_2 = path.join(HIVES_DIR, 'Carving', 'Margin0_2')
hive_carving_margin512_1 = path.join(HIVES_DIR, 'Carving', 'Margin512_1')
hive_carving_margin512_2 = path.join(HIVES_DIR, 'Carving', 'Margin512_2')
hive_carving_margin3584 = path.join(HIVES_DIR, 'Carving', 'Margin3584')
hive_carving_margin_mixed = path.join(HIVES_DIR, 'Carving', 'MarginMixed')

hive_carving_compressed = path.join(HIVES_DIR, 'Carving', 'NTFSCompressed')
hive_carving_compressed_noslack = path.join(HIVES_DIR, 'Carving', 'NTFSCompressedNoSlack')
hive_carving_compressed_noslack_1024 = path.join(HIVES_DIR, 'Carving', 'NTFSCompressedNoSlackCluster1024')

hive_memcarving_0 = path.join(HIVES_DIR, 'MemoryCarving', 'Fragment_0')
hive_memcarving_1 = path.join(HIVES_DIR, 'MemoryCarving', 'Fragment_1')
hive_memcarving_3 = path.join(HIVES_DIR, 'MemoryCarving', 'Fragment_3')
hive_memcarving_2fragments = path.join(HIVES_DIR, 'MemoryCarving', 'TwoFragments')
hive_memcarving_2fragments_gap = path.join(HIVES_DIR, 'MemoryCarving', 'TwoFragmentsWithGap')
hive_memcarving_2fragments_gap2 = path.join(HIVES_DIR, 'MemoryCarving', 'TwoFragmentsWithGap2')
hive_memcarving_hbin_compressed = path.join(HIVES_DIR, 'MemoryCarving', 'HiveBinCompressed')

log_carving_bootcamp = path.join(HIVES_DIR, 'Carving', 'bootcamp_unallocated_decrypted_nogarbage_sparse.tgz')
log_carving_bootcamp_raw = path.join(HIVES_DIR, 'Carving', 'bootcamp_unallocated_decrypted_nogarbage_sparse.raw')

hive_recon_2 = path.join(HIVES_DIR, 'Carving', 'FragRecon', 'FragmentReconstruction2')
hive_recon_3 = path.join(HIVES_DIR, 'Carving', 'FragRecon', 'FragmentReconstruction3')
hive_recon_4 = path.join(HIVES_DIR, 'Carving', 'FragRecon', 'FragmentReconstruction4')
hive_recon_2plus1 = path.join(HIVES_DIR, 'Carving', 'FragRecon', 'FragmentReconstruction2plus1')
hive_recon_2and4 = path.join(HIVES_DIR, 'Carving', 'FragRecon', 'FragmentReconstruction2and4')

hive_marg_recon_1 = path.join(HIVES_DIR, 'Carving', 'MarginRebuild', 'Rebuild512_4096')
hive_marg_recon_2 = path.join(HIVES_DIR, 'Carving', 'MarginRebuild', 'Rebuild512_24576')
hive_marg_recon_3 = path.join(HIVES_DIR, 'Carving', 'MarginRebuild', 'Rebuild3584_4096')

hive_sqlite = path.join(HIVES_DIR, 'SqliteHive')
hive_reallocvalue_sqlite = path.join(HIVES_DIR, 'ReallocValueHive')
hive_reallocvaluedata_sqlite = path.join(HIVES_DIR, 'ReallocValueDataHive')
hive_dupname_sqlite = path.join(HIVES_DIR, 'DupNameHive')
hive_offreg_sqlite = path.join(HIVES_DIR, 'OffHive')

hive_two_owners = path.join(HIVES_DIR, 'TwoOwnersHive')

fragment_sqlite = path.join(HIVES_DIR, 'SqliteFragment')
fragment_sqlite_db = path.join(HIVES_DIR, 'SqliteFragment.sqlite')
fragment_invalid_parent = path.join(HIVES_DIR, 'InvalidParentFragment')

truncated_hbin = path.join(HIVES_DIR, 'TruncatedHiveBin')

log_discovery = [
	path.join(HIVES_DIR, 'Discovery', '1', 'aa'),
	path.join(HIVES_DIR, 'Discovery', '2', 'AA'),
	path.join(HIVES_DIR, 'Discovery', '3', 'AA'),
	path.join(HIVES_DIR, 'Discovery', '4', 'AA'),
	path.join(HIVES_DIR, 'Discovery', '5', 'aa')
]

record_nk = path.join(RECORDS_DIR, 'dummy_nk')
record_vk = path.join(RECORDS_DIR, 'dummy_vk')
record_sk = path.join(RECORDS_DIR, 'dummy_sk')
record_li = path.join(RECORDS_DIR, 'dummy_li')
record_lf = path.join(RECORDS_DIR, 'dummy_lf')
record_lh = path.join(RECORDS_DIR, 'dummy_lh')
record_ri = path.join(RECORDS_DIR, 'dummy_ri')
record_list = path.join(RECORDS_DIR, 'dummy_list')
record_db = path.join(RECORDS_DIR, 'dummy_db')

def test_empty():
	with open(hive_empty, 'rb') as f:
		hive = Registry.RegistryHive(f)

		assert hive.root_key().subkeys_count() == 0
		for key in hive.root_key().subkeys():
			assert False

		assert hive.root_key().path() == ''
		assert hive.root_key().path(True) != ''

		timestamp = hive.last_written_timestamp()
		assert timestamp.year == 2017
		assert timestamp.month == 3
		assert timestamp.day == 4
		assert timestamp.hour == 16
		assert timestamp.minute == 37
		assert timestamp.second == 31

		timestamp = hive.last_reorganized_timestamp()
		assert timestamp is None

def test_bigdata():
	with open(hive_bigdata, 'rb') as f:
		hive = Registry.RegistryHive(f)

		key = hive.root_key().subkey('key_with_bigdata')
		assert key.values_count() == 2

		value = key.value()
		assert hive.registry_file.get_cell(value.key_value.get_data_offset())[ : 2] == b'db'

		data = value.data()
		assert len(data) == 16345
		for c in data.decode('windows-1252'):
			assert c == '1'

		value = key.value('V')
		assert hive.registry_file.get_cell(value.key_value.get_data_offset())[ : 2] == b'db'

		data = value.data()
		assert len(data) == 81725
		for c in data.decode('windows-1252'):
			assert c == '2'

		assert key.value('doesnt_exist') is None

def test_many_subkeys():
	with open(hive_many_subkeys, 'rb') as f:
		hive = Registry.RegistryHive(f)

		key = hive.find_key('key_with_many_subkeys')
		assert key.subkeys_count() == 5000

		assert hive.registry_file.get_cell(key.key_node.get_subkeys_list_offset())[ : 2] == b'ri'

		allowed_range = range(1, 5000 + 1)
		for subkey in key.subkeys():
			assert int(subkey.name()) in allowed_range

		key = hive.find_key('key_with_MAny_subkeys\\2119\\find_me')
		assert key.path() == 'key_with_many_subkeys\\2119\\find_me'
		assert key.path_partial() == key.path()

		key = hive.find_key('\\key_with_maNY_sUBkeys\\2119\\Find_me')
		assert key.path() == 'key_with_many_subkeys\\2119\\find_me'
		assert key.path_partial() == key.path()

		key = hive.find_key('key_with_many_subkeys\\2119\\find_me')
		assert key.path() == 'key_with_many_subkeys\\2119\\find_me'
		assert key.path_partial() == key.path()

		key = hive.find_key('key_with_many_subkeys\\3000')
		assert key is not None

		key = hive.find_key('key_with_many_subkeys\\3000\\doesnt_exist')
		assert key is None

		key = hive.find_key('key_with_many_subkeys\\doesnt_exist\\doesnt_exist')
		assert key is None

def test_garbage():
	with open(hive_garbage, 'rb') as f:
		hive = Registry.RegistryHive(f)

		assert hive.registry_file.baseblock.get_hbins_data_size() == hive.registry_file.baseblock.effective_hbins_data_size == 4096

		cnt = 0
		for hive_bin in hive.registry_file.hive_bins():
			cnt += 1

		assert cnt == 1

def test_duplicate_subkeys():
	with open(hive_duplicate_subkeys, 'rb') as f:
		hive = Registry.RegistryHive(f)

		with pytest.raises(Registry.WalkException):
			key = hive.root_key().subkey('key_with_many_subkeys')

			assert key is not None

			for subkey in key.subkeys():
				pass

@pytest.mark.parametrize('reverse', [False, True])
def test_dirty_new1(reverse):

	def log_entry_counter():
		log_entry_counter.c += 1

	with open(hive_dirty_new1, 'rb') as primary, open(hive_dirty_new1_log1, 'rb') as log1, open(hive_dirty_new1_log2, 'rb') as log2:
		hive = Registry.RegistryHive(primary)

		key_1 = hive.find_key('Key1')
		key_21 = hive.find_key('Key2\\Key2_1')
		key_22 = hive.find_key('Key2\\Key2_2')
		assert key_1 is not None
		assert key_21 is not None
		assert key_22 is not None

		key_bad = hive.find_key('Key2\\Key2_2\\doesnt_exist')
		assert key_bad is None

		value = key_1.value()
		value_data = value.data()
		assert len(value_data) == 6001
		for c in value_data[ : -1]:
			assert c == '1'

		assert value_data[-1] == '\x00'

		assert len(hive.find_key('KEY2').value('v').data()) == 9
		assert hive.find_key('key2').value('V').data() == 'testTEST\x00'

		assert hive.registry_file.log_apply_count == 0

		hive.log_entry_callback = log_entry_counter
		log_entry_counter.c = 0

		if not reverse:
			t = hive.recover_new(log1, log2)
		else:
			t = hive.recover_new(log2, log1)

		assert t == [log1, log2] or t == [log2, log1]
		assert log_entry_counter.c == 4

		assert hive.registry_file.log_apply_count == 2

		hive.registry_file.file_object.seek(4096)
		recovered_data_1 = hive.registry_file.file_object.read()
		md5_1 = md5(recovered_data_1).hexdigest()

		with open(hive_dirty_new1_recovered, 'rb') as f:
			f.seek(4096)
			recovered_data_2 = f.read()
			md5_2 = md5(recovered_data_2).hexdigest()

		assert md5_1 == md5_2

		key_1 = hive.find_key('Key1')
		key_21 = hive.find_key('Key2\\Key2_1')
		key_22 = hive.find_key('key2\\key2_2')
		assert key_1 is None
		assert key_21 is None
		assert key_22 is None

		key_3 = hive.find_key('Key3')
		key_31 = hive.find_key('Key3\\Key3_1')
		key_32 = hive.find_key('Key3\\Key3_2')
		key_33 = hive.find_key('key3\\key3_3')
		assert key_3 is not None
		assert key_31 is not None
		assert key_32 is not None
		assert key_33 is not None

		key_bad = hive.find_key('Key3\\Key3_2\\doesnt_exist')
		assert key_bad is None

		value = key_3.value()
		value_data = value.data()
		assert len(value_data) == 1441
		for c in value_data[ : -1]:
			assert c == '1'

		assert value_data[-1] == '\x00'

def test_dirty_new2():
	with open(hive_dirty_new2, 'rb') as primary, open(hive_dirty_new2_log1, 'rb') as log1, open(hive_dirty_new2_log2, 'rb') as log2:
		hive = Registry.RegistryHive(primary)

		assert hive.registry_file.baseblock.validate_checksum()
		assert hive.registry_file.log_apply_count == 0
		t = hive.recover_new(log1, log2)
		assert hive.registry_file.log_apply_count == 1
		assert hive.registry_file.last_sequence_number == 5
		assert t == [log2]

def test_dirty_old():
	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)

		key_1 = hive.find_key('\\key_with_many_subkeys\\1')
		assert key_1 is not None

		key_5000_1 = hive.find_key('key_with_many_subkeys\\5000\\find_me_in_log')
		assert key_5000_1 is None

		value_4500 = hive.find_key('key_with_many_subkeys\\4500').value('v')
		assert value_4500 is None

		hive.recover_old(log)

		key_1 = hive.find_key('\\key_with_many_subkeys\\1')
		assert key_1 is None

		key_5000_1 = hive.find_key('key_with_many_subkeys\\5000\\find_me_in_log')
		assert key_5000_1 is not None
		timestamp_1 = key_5000_1.last_written_timestamp()

		value_4500 = hive.find_key('key_with_many_subkeys\\4500').value('V')
		assert value_4500 is not None

		assert value_4500.data() == [ 'a\x00', 'bb\x00', 'ccc\x00', '\x00' ]

		with open(hive_dirty_old_recovered, 'rb') as recovered:
			hive_r = Registry.RegistryHive(recovered)

			key_5000_1_r = hive_r.find_key('key_with_many_subkeys\\5000\\find_me_in_log')
			timestamp_2 = key_5000_1_r.last_written_timestamp()

			value_4500_r = hive_r.find_key('key_with_many_subkeys\\4500').value('v')

			assert timestamp_1 == timestamp_2
			assert value_4500.data() == value_4500_r.data()

def test_dirty_old_rollback_changes():
	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)

		hive.recover_old(log)
		assert hive.registry_file.log_apply_count == 1
		hive.rollback_changes()
		assert hive.registry_file.log_apply_count == 0

		key_1 = hive.find_key('\\key_with_many_subkeys\\1')
		assert key_1 is not None

		key_5000_1 = hive.find_key('key_with_many_subkeys\\5000\\find_me_in_log')
		assert key_5000_1 is None

		value_4500 = hive.find_key('key_with_many_subkeys\\4500').value('v')
		assert value_4500 is None

def test_recovery_not_required():
	with open(hive_dirty_old_recovered, 'rb') as recovered:
		hive = Registry.RegistryHive(recovered)
		dummy = BytesIO()

		with pytest.raises(RegistryFile.RecoveryException):
			hive.recover_old(dummy)

		with pytest.raises(RegistryFile.RecoveryException):
			hive.recover_new(dummy)

def test_unicode():
	with open(hive_unicode, 'rb') as f:
		hive = Registry.RegistryHive(f)

		key = hive.find_key(u'ПриВет\\КлюЧ')
		assert key is not None
		assert key.path() == u'Привет\\Ключ'
		assert key.path_partial() == key.path()

		key = hive.find_key(u'\\ПриВет\\КлюЧ')
		assert key is not None
		assert key.path() == u'Привет\\Ключ'
		assert key.path_partial() == key.path()

		key = hive.find_key(u'привет')
		assert key is not None
		assert key.path().lower() == u'привет'
		assert key.path_partial() == key.path()

		key = hive.find_key(u'\\привеТ')
		assert key is not None
		assert key.path() == u'Привет'
		assert key.path_partial() == key.path()

def test_extended_ascii():
	with open(hive_extended_ascii, 'rb') as f:
		hive = Registry.RegistryHive(f)

		key = hive.find_key(u'ëigenaardig')
		assert key is not None
		assert key.key_node.get_flags() & RegistryRecords.KEY_COMP_NAME > 0
		assert key.path() == u'ëigenaardig'
		assert key.path_partial() == key.path()

		value = key.value(u'ëigenaardig')
		assert value.key_value.get_flags() & RegistryRecords.VALUE_COMP_NAME > 0
		assert value.data() == u'ëigenaardig\x00'

def test_upcase():
	with open(hive_upcase, 'rb') as f:
		hive = Registry.RegistryHive(f)
		hive.walk_everywhere()

		subkeys = [ 'ss1', 'SS3', b'\xdf\x00'.decode('utf-16le') + '2' ]
		for i in hive.root_key().subkeys():
			assert i.name() == subkeys.pop(0)

		assert len(subkeys) == 0

	with open(hive_pair, 'rb') as f:
		hive = Registry.RegistryHive(f)
		hive.walk_everywhere()

		subkeys = [ 'ss1', 'SS3', b'\x01\xd8\x00\xdc'.decode('utf-16le') ]
		for i in hive.root_key().subkeys():
			assert i.name() == subkeys.pop(0)

		assert len(subkeys) == 0


	with open(hive_truncated_pair1, 'rb') as f:
		hive = Registry.RegistryHive(f)
		hive.walk_everywhere()

		subkeys = [ 'ss1', 'SS3', b'\xfd\xff'.decode('utf-16le') ]
		for i in hive.root_key().subkeys():
			assert i.name() == subkeys.pop(0)

		assert len(subkeys) == 0
		assert hive.find_key(b'\xfd\xff'.decode('utf-16le')) is not None

	with open(hive_truncated_pair2, 'rb') as f:
		hive = Registry.RegistryHive(f)
		hive.walk_everywhere()

		subkeys = [ 'key1', 'key2', 'key3', 'key' + b'\xfd\xff'.decode('utf-16le'), 'key' + b'\xfd\xff'.decode('utf-16le') ]
		for i in hive.root_key().subkeys():
			assert i.name() == subkeys.pop(0)

		assert len(subkeys) == 0
		assert hive.find_key('key' + b'\xfd\xff'.decode('utf-16le')) is not None

def test_autorecovery():
	def convert_tuple(t):
		assert t.recovered
		file_objects = t.file_objects
		assert len(file_objects) < 3 and len(file_objects) > 0
		if len(file_objects) == 1:
			return (t.is_new_log, t.file_objects[0])
		else:
			return (t.is_new_log, t.file_objects[0], t.file_objects[1])

	dummy = BytesIO()

	with open(hive_dirty_new1, 'rb') as primary, open(hive_dirty_new1_log1, 'rb') as log1, open(hive_dirty_new1_log2, 'rb') as log2:
		hive = Registry.RegistryHive(primary)
		t = hive.recover_auto(dummy, log1, log2)
		t = convert_tuple(t)
		assert hive.registry_file.log_apply_count == 2
		assert len(t) == 3
		assert t[0]
		assert t[1] == log1 and t[2] == log2

	with open(hive_dirty_new1, 'rb') as primary, open(hive_dirty_new1_log1, 'rb') as log1, open(hive_dirty_new1_log2, 'rb') as log2:
		hive = Registry.RegistryHive(primary)
		t = hive.recover_auto(None, log1, log2)
		t = convert_tuple(t)
		assert hive.registry_file.log_apply_count == 2
		assert len(t) == 3
		assert t[0]
		assert t[1] == log1 and t[2] == log2

	with open(hive_dirty_new2, 'rb') as primary, open(hive_dirty_new2_log1, 'rb') as log1, open(hive_dirty_new2_log2, 'rb') as log2:
		hive = Registry.RegistryHive(primary)
		t = hive.recover_auto(dummy, log1, log2)
		t = convert_tuple(t)
		assert hive.registry_file.log_apply_count == 1
		assert len(t) == 2
		assert t[0]
		assert t[1] == log2

	with open(hive_dirty_new2, 'rb') as primary, open(hive_dirty_new2_log1, 'rb') as log1, open(hive_dirty_new2_log2, 'rb') as log2:
		hive = Registry.RegistryHive(primary)
		t = hive.recover_auto(None, log1, log2)
		t = convert_tuple(t)
		assert hive.registry_file.log_apply_count == 1
		assert len(t) == 2
		assert t[0]
		assert t[1] == log2

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		t = hive.recover_auto(log, dummy, dummy)
		t = convert_tuple(t)
		assert hive.registry_file.log_apply_count == 1
		assert len(t) == 2
		assert not t[0]
		assert t[1] == log

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		t = hive.recover_auto(dummy, log, dummy)
		t = convert_tuple(t)
		assert hive.registry_file.log_apply_count == 1
		assert len(t) == 2
		assert not t[0]
		assert t[1] == log

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		t = hive.recover_auto(dummy, dummy, log)
		t = convert_tuple(t)
		assert hive.registry_file.log_apply_count == 1
		assert len(t) == 2
		assert not t[0]
		assert t[1] == log

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		t = hive.recover_auto(dummy, log, log)
		t = convert_tuple(t)
		assert hive.registry_file.log_apply_count == 1
		assert len(t) == 2
		assert not t[0]
		assert t[1] == log

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		t = hive.recover_auto(log, log, log)
		t = convert_tuple(t)
		assert hive.registry_file.log_apply_count == 1
		assert len(t) == 2
		assert not t[0]
		assert t[1] == log

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		t = hive.recover_auto(None, dummy, log)
		t = convert_tuple(t)
		assert hive.registry_file.log_apply_count == 1
		assert len(t) == 2
		assert not t[0]
		assert t[1] == log

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		t = hive.recover_auto(log, None, None)
		t = convert_tuple(t)
		assert hive.registry_file.log_apply_count == 1
		assert len(t) == 2
		assert not t[0]
		assert t[1] == log

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		with pytest.raises(Registry.AutoRecoveryException):
			hive.recover_auto(dummy, dummy, dummy)

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		with pytest.raises(Registry.AutoRecoveryException):
			hive.recover_auto(dummy, log, None)

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		with pytest.raises(Registry.AutoRecoveryException):
			hive.recover_auto(dummy, None, log)

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		with pytest.raises(Registry.AutoRecoveryException):
			hive.recover_auto(None, None, log)

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		with pytest.raises(Registry.AutoRecoveryException):
			hive.recover_auto(log, None, log)

def test_invalid_parent():
	with open(hive_invalid_parent, 'rb') as primary:
		hive = Registry.RegistryHive(primary)
		with pytest.raises(Registry.WalkException):
			for subkey_1 in hive.root_key().subkeys():
				for subkey_2 in subkey_1.subkeys():
					pass
def test_bad_list():
	with open(hive_bad_list, 'rb') as primary:
		hive = Registry.RegistryHive(primary)
		with pytest.raises(Registry.WalkException):
			for subkey_1 in hive.root_key().subkeys():
				for subkey_2 in subkey_1.subkeys():
					pass

def test_bad_subkey():
	with open(hive_bad_subkey, 'rb') as primary:
		hive = Registry.RegistryHive(primary)
		with pytest.raises(Registry.WalkException):
			for subkey_1 in hive.root_key().subkeys():
				for subkey_2 in subkey_1.subkeys():
					pass

def test_access_bits():
	with open(hive_dirty_new1, 'rb') as primary:
		hive = Registry.RegistryHive(primary)
		key = hive.find_key('\\key2\\key2_2')
		assert key.access_bits() == 2

def test_bad_baseblock():
	with open(hive_bad_baseblock, 'rb') as primary, open(hive_bad_baseblock_log1, 'rb') as log1, open(hive_bad_baseblock_log2, 'rb') as log2:
		hive = Registry.RegistryHive(primary)

		assert hive.registry_file.log_apply_count == 0
		assert hive.registry_file.baseblock.effective_version == 1

		with pytest.raises(RegistryFile.CellOffsetException):
			hive.find_key('key_with_many_subkeys')

		t = hive.recover_auto(None, log1, log2)

		assert hive.registry_file.log_apply_count == 1
		assert hive.registry_file.baseblock.effective_version == 3
		assert not t.is_new_log
		assert t.file_objects == [log1]
		assert hive.find_key('key_with_many_subkeys') is not None

def test_bad_log1():
	with open(hive_bad_log1, 'rb') as primary, open(hive_bad_log1_log1, 'rb') as log1, open(hive_bad_log1_log2, 'rb') as log2:
		hive = Registry.RegistryHive(primary)
		with pytest.raises(Registry.AutoRecoveryException):
			hive.recover_auto(None, log1, log2)
def test_bad_log2():
	with open(hive_bad_log2, 'rb') as primary, open(hive_bad_log2_log1, 'rb') as log1, open(hive_bad_log2_log2, 'rb') as log2:
		hive = Registry.RegistryHive(primary)
		with pytest.raises(Registry.AutoRecoveryException):
			hive.recover_auto(None, log1, log2)

def test_bad_log3():
	with open(hive_bad_log3, 'rb') as primary, open(hive_bad_log3_log1, 'rb') as log1, open(hive_bad_log3_log2, 'rb') as log2:
		hive = Registry.RegistryHive(primary)
		with pytest.raises(Registry.AutoRecoveryException):
			hive.recover_auto(None, log1, log2)
def test_writable():
	with open(hive_empty, 'rb') as primary:
		hive = Registry.RegistryHive(primary)

		assert not hive.registry_file.writable
		hive.registry_file.create_writable_file_object()
		assert hive.registry_file.writable
		hive.registry_file.discard_writable_file_object()

		assert not hive.registry_file.writable
		hive.registry_file.create_writable_file_object()
		assert hive.registry_file.writable
		hive.registry_file.create_writable_file_object()
		assert hive.registry_file.writable
		hive.registry_file.discard_writable_file_object()
		assert not hive.registry_file.writable
		hive.registry_file.discard_writable_file_object()
		hive.registry_file.discard_writable_file_object()
		hive.registry_file.discard_writable_file_object()
		hive.registry_file.discard_writable_file_object()
		assert not hive.registry_file.writable

def test_bogus_keynames():
	with open(hive_bogus_keynames, 'rb') as primary:
		hive = Registry.RegistryHive(primary)
		for k in hive.root_key().subkeys():
			assert k.name() == 'testnew\r\nne' or k.name() == 'testnu\x00l'

		assert hive.find_key('testnew\r\nne') is not None
		assert hive.find_key('testnu\x00l') is not None

def test_new_flags():
	with open(hive_new_flags, 'rb') as primary:
		hive = Registry.RegistryHive(primary)

		key_1 = hive.find_key('1')
		assert key_1 is not None
		key_2 = hive.find_key('1\\2')
		assert key_2 is not None

		assert key_1.key_node.get_virtualization_control_flags() == 0
		assert key_1.key_node.get_user_flags_new() == 0
		assert key_2.key_node.get_virtualization_control_flags() == 0
		assert key_2.key_node.get_user_flags_new() == RegistryRecords.KEY_FLAG_32BIT
		assert key_2.key_node.get_user_flags_old() == 0

def test_multisz():
	with open(hive_multisz, 'rb') as primary:
		hive = Registry.RegistryHive(primary)
		key = hive.find_key('key')
		value_1 = key.value('1')
		value_2 = key.value('2')
		assert key.value() is None

		assert value_1.data() == []
		l = value_2.data()
		assert len(l) == 3 and l[0] == u'привет\x00' and l[1] == u'как дела?\x00' and l[2] == '\x00'

def test_strings():
	with open(hive_strings, 'rb') as primary:
		hive = Registry.RegistryHive(primary)
		key = hive.find_key('key')

		assert key.value().data() == u'test тест\x00'
		assert key.value('1').data() == b'test'
		assert key.value('2').data() == u'test тест\x00'
		assert key.value('3').data() == u'test тест \x00'

def test_unicode_garbage():
	s = b'a\x00b\x00\x00\x00c\x00d\x00'
	assert Registry.DecodeUnicode(s, True) == u'ab\x00'
	assert Registry.DecodeUnicode(s, False) == u'ab\x00cd'

	s = b'a\x00b\x00\x00\x00c\x00d\x00e'
	assert Registry.DecodeUnicode(s, True) == u'ab\x00'
	assert Registry.DecodeUnicode(s, False) == u'ab\x00cd' + b'\xfd\xff'.decode('utf-16le')

	s = b'a\x00\x00\x00b\x00\x00\x00\x00\x00'
	assert Registry.DecodeUnicodeMulti(s, True) == u'a\x00b\x00\x00'

def test_unicode_illegal():
	assert Registry.DecodeUnicode(b'\x74\x00\x00\xD8\x61\x00') == u't' + b'\xfd\xff'.decode('utf-16le') + 'a'
	assert Registry.DecodeUnicode(b'\x00\xD8') == b'\xfd\xff'.decode('utf-16le')

def test_unicode_upcase():
	assert RegistryUnicode.Upper('яЯzZ123' + b'=\xd8\x03\xde'.decode('utf-16le')) == 'ЯЯZZ123' + b'=\xd8\x03\xde'.decode('utf-16le')

def test_security():
	with open(hive_unicode, 'rb') as f:
		hive = Registry.RegistryHive(f)
		sec = hive.root_key().security()
		assert len(sec.descriptor()) == 144

def test_wrong_order():
	with open(hive_wrong_order, 'rb') as f:
		hive = Registry.RegistryHive(f)

		c = 0
		with pytest.raises(Registry.WalkException):
			for subkey in hive.find_key('1').subkeys():
				c += 1

		assert c == 1

		with pytest.raises(Registry.WalkException):
			for subkey in hive.find_key('2').subkeys():
				c += 1

		assert c == 4

def test_truncated_name():
	with open(hive_truncated_name, 'rb') as f:
		hive = Registry.RegistryHive(f)

		with pytest.raises(RegistryRecords.ParseException):
			for subkey in hive.root_key().subkeys():
				pass

@pytest.mark.parametrize('walk_everywhere', [True, False])
def test_unreferenced(walk_everywhere):
	with open(hive_healed, 'rb') as f:
		hive = Registry.RegistryHive(f)

		if walk_everywhere:
			hive.walk_everywhere()
			assert len(hive.registry_file.cell_map_allocated - hive.registry_file.cell_map_referenced) == 5
		else:
			hive.registry_file.build_map_free()
			assert len(hive.registry_file.cell_map_referenced) == 0
			assert len(hive.registry_file.cell_map_free) == len(hive.registry_file.cell_map_unallocated)

	with open(hive_bigdata, 'rb') as f:
		hive = Registry.RegistryHive(f)

		if walk_everywhere:
			hive.walk_everywhere()
			assert len(hive.registry_file.cell_map_allocated - hive.registry_file.cell_map_referenced) == 0
		else:
			hive.registry_file.build_map_free()
			assert len(hive.registry_file.cell_map_referenced) == 0
			assert len(hive.registry_file.cell_map_free) == len(hive.registry_file.cell_map_unallocated)

def test_deleted():
	with open(hive_deleted_data, 'rb') as f:
		hive = Registry.RegistryHive(f)

		hive.walk_everywhere()

		scanner = RegistryRecover.Scanner(hive)
		cnt_key_values = 0
		cnt_key_nodes = 0
		for i in scanner.scan():
			if type(i) is Registry.RegistryValue:
				cnt_key_values += 1

				assert i.type_raw() == RegistryRecords.REG_SZ

				if i.name() == 'v2':
					assert i.data() == '456\x00'
				elif i.name() == 'v':
					assert i.data() == '123456\x00'
				else:
					assert False

			elif type(i) is Registry.RegistryKey:
				cnt_key_nodes += 1

				assert i.name() == '456'

				c = 0
				for v in i.values():
					c += 1
					assert v.name() == 'v'
					assert v.type_raw() == RegistryRecords.REG_SZ
					assert v.data() == '123456\x00'

				assert c == 1

		assert cnt_key_values == 2
		assert cnt_key_nodes == 1

	with open(hive_deleted_tree, 'rb') as f:
		hive = Registry.RegistryHive(f)

		hive.walk_everywhere()

		scanner = RegistryRecover.Scanner(hive)
		c = 0
		for i in scanner.scan():
			assert type(i) is Registry.RegistryKey
			assert i.path() in [ '1\\2\\3', '1\\2\\3\\4', '1\\2\\3\\4\\5', '1\\2\\3\\4\\New Key #1' ]
			assert i.path_partial() == i.path()
			c += 1

		assert c == 4

	with open(hive_healed, 'rb') as f:
		hive = Registry.RegistryHive(f)

		hive.walk_everywhere()

		scanner = RegistryRecover.Scanner(hive)
		for i in scanner.scan():
			if type(i) is Registry.RegistryKey:
				assert i.name() == 'cccc'
				for v in i.values():
					assert v.name() == '123'
					assert v.type_raw() == RegistryRecords.REG_SZ
					assert v.data() == 'test\x00'

			elif type(i) is Registry.RegistryValue:
				assert i.name() == '123'
				assert i.type_raw() == RegistryRecords.REG_SZ
				assert i.data() == 'test\x00'

def test_comp():
	with open(hive_comp, 'rb') as f:
		hive = Registry.RegistryHive(f)
		hive.walk_everywhere()

@pytest.mark.parametrize('recover_fragments', [False, True])
def test_carving(recover_fragments):
	with open(hive_carving0, 'rb') as f:
		carver = RegistryCarve.Carver(f)
		for i in carver.carve(recover_fragments):
			assert i.offset == 0
			assert i.size == 8192
			assert i.hbins_data_size == 4096
			assert not i.truncated
			assert i.truncation_scenario == 0

	with open(hive_carving512, 'rb') as f:
		carver = RegistryCarve.Carver(f)
		for i in carver.carve(recover_fragments):
			assert i.offset == 512
			assert i.size == 8192
			assert i.hbins_data_size == 4096
			assert not i.truncated
			assert i.truncation_scenario == 0

	if not recover_fragments:
		return

	with open(hive_carving_fragments, 'rb') as f:
		carver = RegistryCarve.Carver(f)

		c = 0
		for i in carver.carve(True):
			if c == 0:
				assert type(i) is RegistryCarve.CarveResultFragment
				assert i.offset == 0
				assert i.size == 512
				assert i.hbin_start == 0

				f.seek(i.offset)
				src_buf = f.read(i.size)
				src_obj = BytesIO(src_buf)
				dst_obj = RegistryFile.FragmentTranslator(src_obj)
				dst_buf = dst_obj.getvalue()[ 4096 + i.hbin_start : 4096 + i.hbin_start + i.size ]

				assert src_buf == dst_buf

				tmp_hive = Registry.RegistryHiveTruncated(dst_obj)
			elif c == 1:
				assert type(i) is RegistryCarve.CarveResult
				assert i.offset == 512
				assert i.size == 147456
				assert i.hbins_data_size == 143360
				assert not i.truncated
				assert i.truncation_scenario == 0
			elif c == 2:
				assert type(i) is RegistryCarve.CarveResultFragment
				assert i.offset == 147968
				assert i.size == 12288
				assert i.hbin_start == 0

				f.seek(i.offset)
				src_buf = f.read(i.size)
				src_obj = BytesIO(src_buf)
				dst_obj = RegistryFile.FragmentTranslator(src_obj)
				dst_buf = dst_obj.getvalue()[ 4096 + i.hbin_start : 4096 + i.hbin_start + i.size ]

				assert src_buf == dst_buf

				tmp_hive = Registry.RegistryHiveTruncated(dst_obj)
			elif c == 3:
				assert type(i) is RegistryCarve.CarveResultFragment
				assert i.offset == 262144
				assert i.size == 512
				assert i.hbin_start == 8192

				f.seek(i.offset)
				src_buf = f.read(i.size)
				src_obj = BytesIO(src_buf)
				dst_obj = RegistryFile.FragmentTranslator(src_obj)
				dst_buf = dst_obj.getvalue()[ 4096 + i.hbin_start : 4096 + i.hbin_start + i.size ]

				assert src_buf == dst_buf

				tmp_hive = Registry.RegistryHiveTruncated(dst_obj)
			else:
				assert False

			c += 1

	with open(hive_carving_margin0_1, 'rb') as f:
		carver = RegistryCarve.Carver(f)

		c = 0
		for i in carver.carve(True, True, True):
			assert type(i) is RegistryCarve.CarveResultFragment
			assert i.suggested_margin == 0 and i.suggested_margin_rounded == 0

			f.seek(i.size - i.suggested_margin)
			src_buf = f.read(i.size + i.suggested_margin)
			src_obj = BytesIO(src_buf)
			with pytest.raises(ValueError):
				RegistryFile.FragmentWithMarginTranslator(src_obj, i.suggested_margin)

			c += 1

		assert c == 2

	with open(hive_carving_margin0_2, 'rb') as f:
		carver = RegistryCarve.Carver(f)

		c = 0
		for i in carver.carve(True, True, True):
			assert type(i) is RegistryCarve.CarveResultFragment
			assert i.suggested_margin == 0 and i.suggested_margin_rounded == 0

			f.seek(i.offset - i.suggested_margin)
			src_buf = f.read(i.size + i.suggested_margin)
			src_obj = BytesIO(src_buf)
			with pytest.raises(ValueError):
				RegistryFile.FragmentWithMarginTranslator(src_obj, i.suggested_margin)

			c += 1

		assert c == 1

	with open(hive_carving_margin512_1, 'rb') as f:
		carver = RegistryCarve.Carver(f)

		c = 0
		for i in carver.carve(True, True, True):
			assert type(i) is RegistryCarve.CarveResultFragment
			assert i.suggested_margin == 456 and i.suggested_margin_rounded == 512

			f.seek(i.offset - i.suggested_margin)
			src_buf = f.read(i.size + i.suggested_margin)
			src_obj = BytesIO(src_buf)
			dst_obj = RegistryFile.FragmentWithMarginTranslator(src_obj, i.suggested_margin)
			dst_buf = dst_obj.getvalue()[ 4096 : 4096 + i.size ]

			assert src_buf[ i.suggested_margin : ] == dst_buf

			c += 1

		assert c == 1

	with open(hive_carving_margin512_2, 'rb') as f:
		carver = RegistryCarve.Carver(f)

		c = 0
		for i in carver.carve(True, True, True):
			assert type(i) is RegistryCarve.CarveResultFragment
			assert i.suggested_margin == 512 and i.suggested_margin_rounded == 512

			f.seek(i.offset - i.suggested_margin)
			src_buf = f.read(i.size + i.suggested_margin)
			src_obj = BytesIO(src_buf)
			dst_obj = RegistryFile.FragmentWithMarginTranslator(src_obj, i.suggested_margin)
			dst_buf = dst_obj.getvalue()[ 4096 : 4096 + i.size ]

			assert src_buf[ i.suggested_margin : ] == dst_buf

			c += 1

		assert c == 1

	with open(hive_carving_margin3584, 'rb') as f:
		carver = RegistryCarve.Carver(f)

		c = 0
		for i in carver.carve(True, True, True):
			assert type(i) is RegistryCarve.CarveResultFragment
			assert i.suggested_margin == 3560 and i.suggested_margin_rounded == 3584

			f.seek(i.offset - i.suggested_margin)
			src_buf = f.read(i.size + i.suggested_margin)
			src_obj = BytesIO(src_buf)
			dst_obj = RegistryFile.FragmentWithMarginTranslator(src_obj, i.suggested_margin)
			dst_buf = dst_obj.getvalue()[ 4096 : 4096 + i.size ]

			assert src_buf[ i.suggested_margin : ] == dst_buf

			c += 1

		assert c == 1

	with open(hive_carving_margin_mixed, 'rb') as f:
		margins = [ 456, 0, 0, 3560 ]
		margins_rounded = [ 512, 0, 0, 3584 ]

		carver = RegistryCarve.Carver(f)

		c = 0
		for i in carver.carve(True, True, True):
			assert type(i) is RegistryCarve.CarveResultFragment
			assert i.suggested_margin == margins.pop(0)
			assert i.suggested_margin_rounded == margins_rounded.pop(0)

			if i.suggested_margin > 0:
				f.seek(i.offset - i.suggested_margin)
				src_buf = f.read(i.size + i.suggested_margin)
				src_obj = BytesIO(src_buf)
				dst_obj = RegistryFile.FragmentWithMarginTranslator(src_obj, i.suggested_margin)
				dst_buf = dst_obj.getvalue()[ 4096 : 4096 + i.size ]

				assert src_buf[ i.suggested_margin : ] == dst_buf

			c += 1

		assert c == 4

@pytest.mark.parametrize('recover_fragments', [False, True])
def test_compressed_carving(recover_fragments):
	with open(hive_carving_compressed, 'rb') as f:
		carver = RegistryCarve.Carver(f)

		for i in carver.carve(recover_fragments, False):
			assert False

		c = 0
		for i in carver.carve(recover_fragments, True):
			if type(i) is RegistryCarve.CarveResultCompressed:
				assert i.offset == 0
				assert len(i.buffer_decompressed) > 0

				assert md5(i.buffer_decompressed[:143360]).hexdigest() == '424efa25eaa1183dfe9a332ee04f07e1'

			elif type(i) is RegistryCarve.CarveResultFragmentCompressed:
				assert i.offset == 135168
				assert len(i.buffer_decompressed) > 0

				assert md5(i.buffer_decompressed[:8192]).hexdigest() == '9ce06fccb5872991a1cc93fdb76d4d33'

			else:
				assert False

			c += 1

		if recover_fragments:
			assert c == 2
		else:
			assert c == 1

	with open(hive_carving_compressed_noslack, 'rb') as f:
		carver = RegistryCarve.Carver(f)

		for i in carver.carve(recover_fragments, False):
			assert False

		c = 0
		for i in carver.carve(recover_fragments, True):
			if type(i) is RegistryCarve.CarveResultCompressed:
				assert i.offset == 0
				assert len(i.buffer_decompressed) > 0

				assert md5(i.buffer_decompressed[:143360]).hexdigest() == '424efa25eaa1183dfe9a332ee04f07e1'

			elif type(i) is RegistryCarve.CarveResultFragmentCompressed:
				assert i.offset == 81920
				assert len(i.buffer_decompressed) > 0

				assert md5(i.buffer_decompressed[:8192]).hexdigest() == '9ce06fccb5872991a1cc93fdb76d4d33'

			else:
				assert False

			c += 1

		if recover_fragments:
			assert c == 2
		else:
			assert c == 1

	with open(hive_carving_compressed_noslack_1024, 'rb') as f:
		old_cluster_size = RegistryHelpers.NTFS_CLUSTER_SIZE
		old_compression_unit_size = RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE

		RegistryHelpers.NTFS_CLUSTER_SIZE = 1024
		RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE = 16 * 1024

		carver = RegistryCarve.Carver(f)

		for i in carver.carve(recover_fragments, False):
			assert False

		c = 0
		for i in carver.carve(recover_fragments, True):
			if type(i) is RegistryCarve.CarveResultCompressed:
				assert i.offset == 512
				assert len(i.buffer_decompressed) > 0

				assert md5(i.buffer_decompressed[:143360]).hexdigest() == '424efa25eaa1183dfe9a332ee04f07e1'

			elif type(i) is RegistryCarve.CarveResultFragmentCompressed:
				assert i.offset == 102912
				assert len(i.buffer_decompressed) > 0

				assert md5(i.buffer_decompressed[:8192]).hexdigest() == '9ce06fccb5872991a1cc93fdb76d4d33'

			else:
				assert False

			c += 1

		if recover_fragments:
			assert c == 2
		else:
			assert c == 1

		RegistryHelpers.NTFS_CLUSTER_SIZE = old_cluster_size
		RegistryHelpers.NTFS_COMPRESSION_UNIT_SIZE = old_compression_unit_size

def test_remnants():
	with open(hive_remnants, 'rb') as f:
		hive = Registry.RegistryHive(f)

		hive.walk_everywhere()

		scanner = RegistryRecover.Scanner(hive)

		c = 0
		for i in scanner.scan():
			assert type(i) is Registry.RegistryValue
			assert i.name() == ''
			assert i.type_raw() == RegistryRecords.REG_DWORD
			assert i.data() == 1
			c += 1

		assert c == 1

def test_truncated():
	with open(hive_truncated, 'rb') as f:
		hive = Registry.RegistryHiveTruncated(f)

		for i in hive.scan():
			assert type(i) is Registry.RegistryKey
			assert i.name() in [ '{6214ff27-7b1b-41a3-9ae4-5fb851ffed63}', 'key_with_many_subkeys' ] or int(i.name()) > 0

def test_effective_hbins_data_size():
	with open(hive_effective_size, 'rb') as f:
		hive = Registry.RegistryHive(f)

		assert hive.registry_file.baseblock.effective_hbins_data_size == 487424
		assert hive.registry_file.baseblock.get_hbins_data_size() != hive.registry_file.baseblock.effective_hbins_data_size

def test_log_discovery():
	for i in range(len(log_discovery)):
		p = log_discovery[i]
		a = RegistryHelpers.DiscoverLogFiles(p)

		assert a is not None

		if i == 0:
			assert path.normcase(path.basename(a.log_path)) == path.normcase('aa.LOG')
			assert path.normcase(path.basename(a.log1_path)) == path.normcase('aa.LOG1')
			assert path.normcase(path.basename(a.log2_path)) == path.normcase('aa.LOG2')
		elif i == 1:
			assert a.log_path is None
			assert path.normcase(path.basename(a.log1_path)) == path.normcase('aa.LOG1')
			assert path.normcase(path.basename(a.log2_path)) == path.normcase('aa.LOG2')
		elif i == 2:
			assert path.normcase(path.basename(a.log_path)) == path.normcase('aa.log')
			assert path.normcase(path.basename(a.log1_path)) == path.normcase('aa.log1')
			assert a.log2_path is None
		elif i == 3:
			assert path.normcase(path.basename(a.log_path)) == path.normcase('aa.LOG')

			# These properties should be None if the file system is case-sensitive.
			assert a.log1_path is None or path.normcase(path.basename(a.log1_path)) == path.normcase('aa.log1')
			assert a.log2_path is None or path.normcase(path.basename(a.log2_path)) == path.normcase('aa.log2')
		elif i == 4:
			assert a.log_path is None
			assert a.log1_path is None
			assert a.log2_path is None
		else:
			assert False

def test_deleted_tree_no_root_flag():
	with open(hive_deleted_tree_no_root_flag, 'rb') as f:
		hive = Registry.RegistryHive(f)

		assert hive.root_key().key_node.get_flags() & RegistryRecords.KEY_HIVE_ENTRY == 0
		hive.walk_everywhere()

		scanner = RegistryRecover.Scanner(hive)
		c = 0
		for i in scanner.scan():
			assert type(i) is Registry.RegistryKey
			assert i.path() in [ '1\\2\\3', '1\\2\\3\\4', '1\\2\\3\\4\\5', '1\\2\\3\\4\\New Key #1' ]
			assert i.path_partial() == i.path()
			c += 1

		assert c == 4

def test_deleted_tree_partial_path():
	with open(hive_deleted_tree_partial_path, 'rb') as f:
		hive = Registry.RegistryHive(f)

		hive.walk_everywhere()

		scanner = RegistryRecover.Scanner(hive)
		c = 0
		for i in scanner.scan():
			assert type(i) is Registry.RegistryKey
			assert i.path_partial() in [ '3', '3\\4', '3\\4\\5', '3\\4\\New Key #1' ]
			c += 1

		assert c == 4

def test_flags_converter():
	cases = [
		{'log_entry_flags': 0, 'baseblock_flags': 0, 'result': 0},
		{'log_entry_flags': 1, 'baseblock_flags': 0, 'result': 1},
		{'log_entry_flags': 1, 'baseblock_flags': 1, 'result': 1},
		{'log_entry_flags': 0, 'baseblock_flags': 1, 'result': 0},
		{'log_entry_flags': 0, 'baseblock_flags': 3, 'result': 2},
		{'log_entry_flags': 1, 'baseblock_flags': 3, 'result': 3},
		{'log_entry_flags': 1, 'baseblock_flags': 2, 'result': 3}
	]

	for case in cases:
		assert RegistryFile.LogEntryFlagsToBaseBlockFlags(case['log_entry_flags'], case['baseblock_flags']) == case['result']

def test_hive_save():
	def check_saved_hive(filepath):
		with open(filepath, 'rb') as recovered:
			hive_recovered = Registry.RegistryHive(recovered)
			assert not hive_recovered.registry_file.baseblock.is_file_dirty
			hive_recovered.walk_everywhere()

	tmp_file = path.join(HIVES_DIR, 'temphive_delete_me')

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		with pytest.raises(RegistryFile.NotSupportedException):
			hive.registry_file.save_recovered_hive(tmp_file)

	with open(hive_dirty_old, 'rb') as primary, open(hive_dirty_old_log, 'rb') as log:
		hive = Registry.RegistryHive(primary)
		hive.recover_old(log)
		hive.registry_file.save_recovered_hive(tmp_file)
		check_saved_hive(tmp_file)

	with open(hive_dirty_new1, 'rb') as primary, open(hive_dirty_new1_log1, 'rb') as log1, open(hive_dirty_new1_log2, 'rb') as log2:
		hive = Registry.RegistryHive(primary)
		hive.recover_new(log1, log2)
		hive.registry_file.save_recovered_hive(tmp_file)
		check_saved_hive(tmp_file)

	with open(hive_dirty_new2, 'rb') as primary, open(hive_dirty_new2_log1, 'rb') as log1, open(hive_dirty_new2_log2, 'rb') as log2:
		hive = Registry.RegistryHive(primary)
		hive.recover_new(log1, log2)
		hive.registry_file.save_recovered_hive(tmp_file)
		check_saved_hive(tmp_file)

	with open(hive_bad_baseblock, 'rb') as primary, open(hive_bad_baseblock_log1, 'rb') as log1, open(hive_bad_baseblock_log2, 'rb') as log2:
		hive = Registry.RegistryHive(primary)
		hive.recover_auto(None, log1, log2)
		hive.registry_file.save_recovered_hive(tmp_file)
		check_saved_hive(tmp_file)

	remove(tmp_file)

def test_slack():
	with open(record_nk, 'rb') as f:
		buf = f.read()
		r = RegistryRecords.KeyNode(buf)
		assert r.get_slack() == b'SLCK'

	with open(record_vk, 'rb') as f:
		buf = f.read()
		r = RegistryRecords.KeyValue(buf)
		assert r.get_slack() == b'SLCK'

	with open(record_sk, 'rb') as f:
		buf = f.read()
		r = RegistryRecords.KeySecurity(buf)
		assert r.get_slack() == b'SLCK'

	with open(record_li, 'rb') as f:
		buf = f.read()
		r = RegistryRecords.IndexLeaf(buf)
		assert r.get_slack() == b'SLCK'

	with open(record_lh, 'rb') as f:
		buf = f.read()
		r = RegistryRecords.HashLeaf(buf)
		assert r.get_slack() == b'SLCK'

	with open(record_lf, 'rb') as f:
		buf = f.read()
		r = RegistryRecords.FastLeaf(buf)
		assert r.get_slack() == b'SLCK'

	with open(record_ri, 'rb') as f:
		buf = f.read()
		r = RegistryRecords.IndexRoot(buf)
		assert r.get_slack() == b'SLCK'

	with open(record_list, 'rb') as f:
		buf = f.read()
		r = RegistryRecords.KeyValuesList(buf, 3)
		assert r.get_slack() == b'SLCK'

		c = 0
		for element in r.elements():
			c += 1

		assert c == 3

		c = 0
		for element in r.remnant_elements():
			c += 1
			assert element == 1262701651 # b'SLCK'

		assert c == 1

		r = RegistryRecords.SegmentsList(buf, 3)
		assert r.get_slack() == b'SLCK'

	with open(record_db, 'rb') as f:
		buf = f.read()
		r = RegistryRecords.BigData(buf)
		assert r.get_slack() == b'SLCK'

def test_hive_slack():
	with open(hive_slack, 'rb') as f:
		hive = Registry.RegistryHive(f)

		assert len(hive.effective_slack) == 0
		hive.walk_everywhere()
		assert len(hive.effective_slack) > 0
		assert b'SLCK' in hive.effective_slack

		hive = Registry.RegistryHiveTruncated(f)
		assert len(hive.effective_slack) == 0

		for i in hive.scan():
			pass

		assert len(hive.effective_slack) > 0
		assert b'SLCK' in hive.effective_slack

def test_data_slack():
	with open(hive_bigdata, 'rb') as f:
		hive = Registry.RegistryHive(f)

		value = hive.root_key().subkey('key_with_bigdata').value()
		slack_list = value.data_slack()

		assert len(slack_list) == 4
		for slack in slack_list:
			assert len(slack) == 4 or len(slack) == 16347
			for c in slack.decode('windows-1252'):
				assert c == '\x00'

	with open(hive_strings, 'rb') as primary:
		hive = Registry.RegistryHive(primary)
		value = hive.find_key('key').value('3')

		assert value.data_slack() == [ b'w Valu' ]

def test_invalid_ri():
	buf = b'ri\x00\x00'
	with pytest.raises(RegistryRecords.ParseException):
		ri = RegistryRecords.IndexRoot(buf)

	buf = b'ri\x00\x00\x00\x00'
	with pytest.raises(RegistryRecords.ParseException):
		ri = RegistryRecords.IndexRoot(buf)

	buf = b'ri\x01\x00\x00'
	with pytest.raises(RegistryRecords.ParseException):
		ri = RegistryRecords.IndexRoot(buf)
		for i in ri.elements():
			assert False

	buf = b'ri\x01\x00\x00\x00\x00\x00'
	ri = RegistryRecords.IndexRoot(buf)
	for i in ri.elements():
		pass

def test_deleted_value_assoc():
	with open(hive_deleted_data, 'rb') as f:
		hive = Registry.RegistryHive(f)

		hive.walk_everywhere()

		key = hive.find_key('123')

		c = 0
		for value in key.remnant_values():
			assert value.name() == 'v2'
			assert value.type_raw() == RegistryRecords.REG_SZ
			assert value.data() == '456\x00'
			c += 1

		assert c == 1

def test_old_log_with_remnant_data():
	with open(log_with_remnant_data, 'rb') as f:
		h = RegistryFile.OldLogFile(f)

		remnant_data_1 = h.get_remnant_data()
		remnant_data_2 = h.get_remnant_data()
		assert remnant_data_1 == remnant_data_2 == b'remn'

		f.seek(1024)
		remnant_data_expected_when_unused = f.read()
		remnant_data_1 = h.get_remnant_data(True)
		remnant_data_2 = h.get_remnant_data(True)
		assert remnant_data_1 == remnant_data_2 == remnant_data_expected_when_unused

	with open(hive_dirty_old_log, 'rb') as f:
		h = RegistryFile.OldLogFile(f)

		remnant_data_1 = h.get_remnant_data()
		remnant_data_2 = h.get_remnant_data()
		assert remnant_data_1 == remnant_data_2 == b''

def test_new_log_with_remnant_data():
	with open(hive_dirty_new2_log1, 'rb') as f:
		h = RegistryFile.NewLogFile(f)

		remnant_data_1 = h.get_remnant_data()
		remnant_data_2 = h.get_remnant_data()
		assert remnant_data_1 == remnant_data_2 == b''

	with open(hive_dirty_new2_log2, 'rb') as f:
		h = RegistryFile.NewLogFile(f)

		remnant_data_1 = h.get_remnant_data()
		remnant_data_2 = h.get_remnant_data()
		assert remnant_data_1 == remnant_data_2 == b'\x00' * 24576

	with open(hive_dirty_new2_log2, 'rb') as f:
		h = RegistryFile.NewLogFile(f)

		remnant_data_1 = h.get_remnant_data(True)
		remnant_data_2 = h.get_remnant_data(True)

		f.seek(512)
		remnant_data_expected_when_unused = f.read()
		assert remnant_data_1 == remnant_data_2 == remnant_data_expected_when_unused

def test_remnant_log_entries():
	with open(hive_dirty_new2_log2, 'rb') as f:
		h = RegistryFile.NewLogFile(f)

		for i in h.remnant_log_entries(False):
			assert False

		c = 0
		for i in h.remnant_log_entries(True):
			assert i.get_sequence_number() in [ 3, 4, 5 ]
			c += 1

		assert c == 3

def test_new_log_rebuild():
	with open(hive_dirty_new2_log2, 'rb') as f:
		log = RegistryFile.NewLogFile(f)

		b = log.rebuild_primary_file_using_remnant_log_entries(True)
		h = Registry.RegistryHive(b)
		h.walk_everywhere()

	with open(hive_dirty_new2_log2, 'rb') as f:
		log = RegistryFile.NewLogFile(f)

		b = log.rebuild_primary_file_using_remnant_log_entries(False)
		assert b is None

	with open(hive_dirty_new2_log2, 'rb') as f:
		log = RegistryFile.NewLogFile(f)

		assert log.list_remnant_log_entries(True) == [ 3, 4, 5 ]
		assert log.list_remnant_log_entries(False) == []

def test_sqlite():
	if sys.version_info.major != 3:
		pytest.skip()

	with RegistrySqlite.YarpDB(hive_sqlite, ':memory:') as h:
		assert h.info().recovered == 0
		assert h.info().truncated == 0
		assert h.info().rebuilt == 0

		doesnt_exist = 9999999999

		assert h.key(doesnt_exist) is None
		assert h.value(doesnt_exist) is None

		for i in h.subkeys(doesnt_exist):
			assert False

		for i in h.values(doesnt_exist):
			assert False

		root = h.root_key()

		assert not root.is_deleted
		assert root.name == '{dedef10d-30ff-45b5-9d44-b3fa249ecd49}'
		assert root.classname is None
		assert root.last_written_timestamp == 131491245452005837
		assert root.access_bits == 0

		assert h.get_rowid(doesnt_exist) is None

		c = 0
		for subkey in h.subkeys(root.rowid):
			c += 1

			assert (subkey.name == 'A1' and subkey.last_written_timestamp == 131491247867995634) or (subkey.name == 'A2' and subkey.last_written_timestamp == 131491246443034697)
			assert subkey.classname is None
			assert subkey.access_bits == 0
			assert not subkey.is_deleted
			assert h.get_rowid(subkey.parent_key_id) == root.rowid

			if subkey.name == 'A1':
				a1 = subkey.rowid
			else:
				a2 = subkey.rowid

		assert c == 2

		c = 0
		for subkey in h.subkeys(a2):
			c += 1

		assert c == 0

		c = 0
		for value in h.values(a2):
			c += 1

			assert value.name == 'A2'
			assert value.type == 1
			assert value.data == b'A\x00A\x00A\x002\x00\x00\x00'
			assert not value.is_deleted
			assert h.get_rowid(value.parent_key_id) == a2

		assert c == 1

		c = 0
		for value in h.values(a1):
			c += 1

			assert value.name == 'AAA1'
			assert value.type == 1
			assert value.data == b'\x00\x00'
			assert not value.is_deleted

		assert c == 1

		c = 0
		for subkey in h.subkeys(a1):
			c += 1

			assert (subkey.name == 'B1' and subkey.is_deleted and subkey.last_written_timestamp == 131491247867995634) or (subkey.name == 'B2' and (not subkey.is_deleted) and subkey.last_written_timestamp == 131491247948396025)
			assert subkey.classname is None
			assert subkey.access_bits == 0

			if subkey.name == 'B1':
				b1 = subkey.rowid
			else:
				b2 = subkey.rowid

		assert c == 2

		c = 0
		for value in h.values(b1):
			c += 1

			assert value.name == 'B1'
			assert value.type == 1
			assert value.data == b'B\x00B\x00B\x001\x00\x00\x00'
			assert value.is_deleted

		assert c == 1

		c = 0
		for value in h.values(b2):
			c += 1

			assert (value.name == 'B2' and value.data == b'B\x00B\x00B\x002\x00\x00\x00' and not value.is_deleted) or (value.name == 'B2_' and value.data == b'B\x00B\x00B\x002\x00_\x00\x00\x00' and value.is_deleted)
			assert value.type == 1

		assert c == 2

		c = 0
		for subkey in h.subkeys(b2):
			c += 1

		assert c == 0

		c = 0
		for subkey in h.subkeys(b1):
			c += 1

			assert subkey.name == 'C'
			assert subkey.last_written_timestamp == 131491247867995634
			assert subkey.is_deleted
			assert subkey.classname is None
			assert subkey.access_bits == 0

			c_rowid = subkey.rowid

		assert c == 1

		c = 0
		for value in h.values(c_rowid):
			c += 1

			assert (value.name == 'C1' and value.data == b'C\x00C\x00C\x001\x00\x00\x00') or (value.name == 'C2' and value.data == b'C\x00C\x00C\x002\x00\x00\x00')
			assert value.type == 1
			assert value.is_deleted

		assert c == 2

		c = 0
		for subkey in h.subkeys(c_rowid):
			c += 1

			assert subkey.name == 'D'
			assert subkey.last_written_timestamp == 131491245736608915
			assert subkey.is_deleted
			assert subkey.classname is None
			assert subkey.access_bits == 0

			d = subkey.rowid

		assert c == 1

		c = 0
		for subkey in h.subkeys(d):
			c += 1

		assert c == 0

		c = 0
		for value in h.values(d):
			c += 1

			assert value.name == 'D'
			assert value.type == 1
			assert value.data == b'D\x00D\x00D\x00\x00\x00'
			assert value.is_deleted

		assert c == 1

		i = h.info()
		assert i.last_written_timestamp == 131491247980046415
		assert i.last_reorganized_timestamp is None

		c = 0
		for subkey in h.subkeys_unassociated():
			c += 1

		assert c == 0

		c = 0
		for value in h.values_unassociated():
			c += 1

			assert value.is_deleted
			assert value.type == 1
			assert value.name in [ 'C2', 'D', 'Новый параметр #1', 'C1', 'B1', 'B2_' ]

		assert c == 6

	with RegistrySqlite.YarpDB(hive_deleted_tree_partial_path, ':memory:') as h:
		assert h.info().recovered == 0
		assert h.info().truncated == 0
		assert h.info().rebuilt == 0

		doesnt_exist = 9999999999

		assert h.key(doesnt_exist) is None
		assert h.value(doesnt_exist) is None

		for i in h.subkeys(doesnt_exist):
			assert False

		for i in h.values(doesnt_exist):
			assert False

		root = h.root_key()

		assert not root.is_deleted
		assert root.name == '{d253c44d-aea4-4117-bb6c-34bb4803b13e}'
		assert root.classname is None
		assert root.last_written_timestamp == 131345184827581997
		assert root.access_bits == 0

		c = 0
		for subkey in h.subkeys(root.rowid):
			c += 1

			assert not subkey.is_deleted
			assert subkey.name == '1'
			assert subkey.classname is None
			assert subkey.last_written_timestamp == 131345184847726253
			assert subkey.access_bits == 0

			cc = 0
			for subkey2 in h.subkeys(subkey.rowid):
				cc += 1

				assert not subkey2.is_deleted
				assert subkey2.name == '2'
				assert subkey2.classname is None
				assert subkey2.last_written_timestamp == 131345184953072285
				assert subkey2.access_bits == 0

			assert cc == 1

		assert c == 1

		c = 0
		for value in h.values_unassociated():
			c += 1

		assert c == 0

		c = 0
		for subkey in h.subkeys_unassociated():
			c += 1

			assert subkey.is_deleted
			assert subkey.name == '3'
			assert subkey.classname is None
			assert subkey.last_written_timestamp == 131345184953072285
			assert subkey.access_bits == 0

			rowid = subkey.rowid

		assert c == 1

		c = 0
		for subkey in h.subkeys(rowid):
			c += 1

			assert subkey.is_deleted
			assert subkey.name == '4'
			assert subkey.classname is None
			assert subkey.last_written_timestamp == 131345184953072285
			assert subkey.access_bits == 0

			rowid = subkey.rowid

		assert c == 1

		c = 0
		for subkey in h.subkeys(rowid):
			c += 1

			assert (subkey.name == '5' and subkey.last_written_timestamp == 131345184913496045) or (subkey.name == 'New Key #1' and subkey.last_written_timestamp == 131345184906594029)
			assert subkey.is_deleted
			assert subkey.classname is None
			assert subkey.access_bits == 0

		assert c == 2

	with RegistrySqlite.YarpDB(hive_reallocvalue_sqlite, ':memory:', True) as h:
		assert h.info().recovered == 0
		assert h.info().truncated == 0
		assert h.info().rebuilt == 0

		doesnt_exist = 9999999999

		assert h.key(doesnt_exist) is None
		assert h.value(doesnt_exist) is None

		for i in h.subkeys(doesnt_exist):
			assert False

		for i in h.values(doesnt_exist):
			assert False

		root = h.root_key()

		assert not root.is_deleted

		c = 0
		for subkey in h.subkeys(root.rowid):
			c += 1

			if subkey.name == '1':
				assert not subkey.is_deleted

				cc = 0
				for value in h.values(subkey.rowid):
					cc += 1

					assert value.name == ''
					assert value.data == b'1\x001\x001\x001\x00\x00\x00'
					assert not value.is_deleted

				assert cc == 1
			elif subkey.name == '2':
				assert subkey.is_deleted

				for value in h.values(subkey.rowid):
					assert False
			else:
				assert False

		assert c == 2

		c = 0
		for value in h.values_unassociated():
			c += 1

			assert value.name == ''
			assert value.type == 1
			assert value.data == b'2\x002\x002\x002\x00\x00\x00'
			assert value.is_deleted

		assert c == 1

	with RegistrySqlite.YarpDB(hive_truncated_dirty, ':memory:', True) as h:
		assert h.info().recovered == 0
		assert h.info().truncated == 1
		assert h.info().rebuilt == 0

		doesnt_exist = 9999999999

		assert h.key(doesnt_exist) is None
		assert h.value(doesnt_exist) is None

		for i in h.subkeys(doesnt_exist):
			assert False

		for i in h.values(doesnt_exist):
			assert False

	with RegistrySqlite.YarpDB(hive_truncated_dirty, ':memory:') as h:
		assert h.info().recovered == 0
		assert h.info().truncated == 1
		assert h.info().rebuilt == 0

		root_rowid = h.root_key().rowid
		for i in h.values(root_rowid):
			assert False

		c = 0
		for i in h.subkeys(root_rowid):
			c += 1

			assert i.name == 'key_with_many_subkeys'
			rowid = i.rowid

		assert c == 1

		for i in h.values(rowid):
			assert False

		prev_name_i = None
		for i in h.values(rowid):
			for j in h.values(i.rowid):
				assert False

			for j in h.subkeys(i.rowid):
				assert False

			assert int(i.name) > 0
			if prev_name_i is not None:
				assert int(i.name) > prev_name_i

			doesnt_exist = 9999999999

			assert h.key(doesnt_exist) is None
			assert h.value(doesnt_exist) is None

			for i in h.subkeys(doesnt_exist):
				assert False

			for i in h.values(doesnt_exist):
				assert False

			prev_name_i = int(i.name)

	with RegistrySqlite.YarpDB(hive_reallocvaluedata_sqlite, ':memory:') as h:
		hi = h.info()
		assert hi.recovered == 0
		assert hi.truncated == 0
		assert hi.rebuilt == 0
		assert hi.last_written_timestamp == 131495536863659453
		assert hi.last_reorganized_timestamp is None
		assert hi.offreg_serialization_timestamp is None

		root = h.root_key()

		assert not root.is_deleted

		c = 0
		for subkey in h.subkeys(root.rowid):
			c += 1

			if subkey.name == '1':
				assert not subkey.is_deleted

				cc = 0
				for value in h.values(subkey.rowid):
					cc += 1

					assert value.name == ''
					assert value.data == b'1\x001\x001\x001\x00\x00\x00'
					assert not value.is_deleted

				assert cc == 1
			elif subkey.name == '2':
				assert subkey.is_deleted

				cc = 0
				for value in h.values(subkey.rowid):
					cc += 1

					assert value.name == ''
					assert value.data is None
					assert value.is_deleted

				assert cc == 1
			else:
				assert False

		assert c == 2

		c = 0
		for value in h.values_unassociated():
			c += 1

			assert value.name == ''
			assert value.type == 1
			assert value.data is None
			assert value.is_deleted

		assert c == 1

	with RegistrySqlite.YarpDB(hive_offreg_sqlite, ':memory:') as h:
		hi = h.info()
		assert hi.recovered == 0
		assert hi.truncated == 0
		assert hi.rebuilt == 0
		assert hi.last_written_timestamp == 131331190512216222
		assert hi.last_reorganized_timestamp is None
		assert hi.offreg_serialization_timestamp == 131876648849521757

	with RegistrySqlite.YarpDB(hive_dirty_old, ':memory:') as h:
		assert h.info().recovered == 1
		assert h.info().truncated == 0
		assert h.info().rebuilt == 0

	with RegistrySqlite.YarpDB(hive_truncated, ':memory:') as h:
		assert h.info().recovered == 0
		assert h.info().truncated == 1
		assert h.info().rebuilt == 0

	with RegistrySqlite.YarpDB(fragment_sqlite, ':memory:') as h:
		assert h.info().recovered == 0
		assert h.info().truncated == 1
		assert h.info().rebuilt == 1

		root = h.root_key()

		assert not root.is_deleted
		assert root.name == '{dedef10d-30ff-45b5-9d44-b3fa249ecd49}'
		assert root.classname is None
		assert root.last_written_timestamp == 131491245452005837
		assert root.access_bits == 0
		assert h.security_info(root.rowid).owner_sid == 'S-1-5-32-544'

		c = 0
		for subkey in h.subkeys(root.rowid):
			c += 1

			assert (subkey.name == 'A1' and subkey.last_written_timestamp == 131491247867995634) or (subkey.name == 'A2' and subkey.last_written_timestamp == 131491246443034697)
			assert subkey.classname is None
			assert subkey.access_bits == 0
			assert not subkey.is_deleted
			assert h.get_rowid(subkey.parent_key_id) == root.rowid
			assert h.security_info(root.rowid).owner_sid == 'S-1-5-32-544'

		assert c == 2

	with RegistrySqlite.YarpDB(fragment_invalid_parent, ':memory:') as h:
		assert h.info().recovered == 0
		assert h.info().truncated == 1
		assert h.info().rebuilt == 1
		assert h.root_key() is None

		c = 0
		for subkey in h.subkeys_unassociated():
			c += 1

			assert subkey.name == '{dedef10d-30ff-45b5-9d44-b3fa249ecd49}'
			assert subkey.access_bits == 0
			assert subkey.classname is None
			assert not subkey.is_deleted

		assert c == 1

	with RegistrySqlite.YarpDB(hive_deleted_data, ':memory:') as h:
		assert h.info().recovered == 0
		assert h.info().truncated == 0
		assert h.info().rebuilt == 0

		c = 0
		for value in h.values_unassociated():
			c += 1

			assert value.is_deleted
			assert value.name == 'v' or value.name == 'v2'
			assert value.type == 1

		assert c == 2

	with RegistrySqlite.YarpDB(hive_deleted_data_truncated, ':memory:') as h:
		assert h.info().recovered == 0
		assert h.info().truncated == 1
		assert h.info().rebuilt == 0

		c = 0
		for value in h.values_unassociated():
			c += 1

			assert (value.is_deleted and (value.name == 'v' or value.name == 'v2')) or ((not value.is_deleted) and value.name == 'v1')
			assert value.type == 1

		assert c == 3

	with RegistrySqlite.YarpDB(None, fragment_sqlite_db) as h: # Warning: this test may not use the current database layout.
		assert h.info().recovered == 0
		assert h.info().truncated == 1
		assert h.info().rebuilt == 1

		root = h.root_key()

		assert not root.is_deleted
		assert root.name == '{dedef10d-30ff-45b5-9d44-b3fa249ecd49}'
		assert root.classname is None
		assert root.last_written_timestamp == 131491245452005837
		assert root.access_bits == 0

		c = 0
		for subkey in h.subkeys(root.rowid):
			c += 1

			assert (subkey.name == 'A1' and subkey.last_written_timestamp == 131491247867995634) or (subkey.name == 'A2' and subkey.last_written_timestamp == 131491246443034697)
			assert subkey.classname is None
			assert subkey.access_bits == 0
			assert not subkey.is_deleted
			assert h.get_rowid(subkey.parent_key_id) == root.rowid

			if subkey.name == 'A1':
				a1 = subkey.rowid
			else:
				a2 = subkey.rowid

		assert c == 2

		c = 0
		for subkey in h.subkeys(a2):
			c += 1

		assert c == 0

		c = 0
		for value in h.values(a2):
			c += 1

			assert value.name == 'A2'
			assert value.type == 1
			assert value.data == b'A\x00A\x00A\x002\x00\x00\x00'
			assert not value.is_deleted
			assert h.get_rowid(value.parent_key_id) == a2

		assert c == 1

		c = 0
		for value in h.values(a1):
			c += 1

			assert value.name == 'AAA1'
			assert value.type == 1
			assert value.data == b'\x00\x00'
			assert not value.is_deleted

		assert c == 1

		def process_rowid(rowid):
			for i in h.values(rowid):
				pass

			for i in h.subkeys(rowid):
				process_rowid(i.rowid)

		process_rowid(root.rowid)
		for i in h.subkeys_unassociated():
			process_rowid(i.rowid)

		for i in h.values_unassociated():
			pass

		for subkey in h.subkeys_with_name(root.rowid, 'nosuchkey'):
			assert False

		c = 0
		for subkey in h.subkeys_with_name(root.rowid, 'a1'):
			assert subkey.name == 'A1' and subkey.last_written_timestamp == 131491247867995634
			c += 1

		assert c == 1

	with RegistrySqlite.YarpDB(hive_two_owners, ':memory:') as h:
		assert h.info().recovered == 0
		assert h.info().truncated == 0
		assert h.info().rebuilt == 0

		rowid = h.root_key().rowid
		assert h.security_info(rowid).owner_sid == 'S-1-5-32-544'
		for subkey in h.subkeys(rowid):
			assert (subkey.name == u'Новый раздел #1' and h.security_info(subkey.rowid).owner_sid == 'S-1-5-32-544') or (subkey.name == u'Новый раздел #2' and h.security_info(subkey.rowid).owner_sid == 'S-1-5-21-3115585512-2168299736-1589779262-1003')

		h.db_cursor.execute('SELECT COUNT(*) FROM `security`')
		cnt = h.db_cursor.fetchone()[0]
		assert cnt == 2

	with RegistrySqlite.YarpDB(hive_values_order, ':memory:') as h:
		assert h.info().recovered == 0
		assert h.info().truncated == 0
		assert h.info().rebuilt == 0

		values_sorted = [ 'aaa', 'bbb', 'zzz' ]
		values_original = [ 'aaa', 'zzz', 'bbb' ]

		rowid = h.root_key().rowid

		for value in h.values(rowid, False):
			assert value.name == values_sorted.pop(0)

		for value in h.values(rowid, True):
			assert value.name == values_original.pop(0)

	with RegistrySqlite.YarpDB(hive_dupname_sqlite, ':memory:') as h:
		assert h.info().recovered == 0
		assert h.info().truncated == 0
		assert h.info().rebuilt == 0

		rowid = h.root_key().rowid
		for subkey in h.subkeys(rowid):
			assert subkey.name in [ 'bbb', 'ccc', u'Новый раздел #1' ]

		i = 0
		for subkey in h.subkeys_with_name(rowid, 'cCC'):
			if i == 0:
				assert not subkey.is_deleted
				assert subkey.name == 'ccc'
			elif i == 1:
				assert subkey.is_deleted
				assert subkey.name == 'ccc'

			i += 1

		assert i == 2

		i = 0
		for subkey in h.subkeys_with_name(rowid, u'новый раздел #1'):
			assert subkey.is_deleted
			assert subkey.name == u'Новый раздел #1'

			i += 1

		assert i == 1

		for subkey in h.subkeys_with_name(rowid, 'nosuchkey'):
			assert False

def test_translator():
	with open(truncated_hbin, 'rb') as src_obj:
		hive_obj = RegistryFile.FragmentTranslator(src_obj)

		hive = Registry.RegistryHiveTruncated(hive_obj)

		c = 0
		for key in hive.scan():
			assert type(key) is Registry.RegistryKey
			assert key.name() == '{6214ff27-7b1b-41a3-9ae4-5fb851ffed63}' or key.name() == 'key_with_many_subkeys'

			c += 1

		assert c == 2

def test_translator_with_margin():
	with open(hive_marg_recon_1, 'rb') as f:
		carver = RegistryCarve.Carver(f)

		c = 0
		for i in carver.carve(True, True, True):
			assert i.offset - i.suggested_margin_rounded == 0
			assert i.suggested_margin_rounded == 512

			f.seek(i.offset - i.suggested_margin)
			src_buf = f.read(i.size + i.suggested_margin)
			src_obj = BytesIO(src_buf)

			hive_obj = RegistryFile.FragmentTranslator(RegistryFile.FragmentWithMarginTranslator(src_obj, i.suggested_margin))
			hive = Registry.RegistryHiveTruncated(hive_obj)
			for item in hive.scan():
				pass

			c += 1

		assert c == 1

	with open(hive_marg_recon_2, 'rb') as f:
		carver = RegistryCarve.Carver(f)

		c = 0
		for i in carver.carve(True, True, True):
			assert i.offset - i.suggested_margin_rounded == 0
			assert i.suggested_margin_rounded == 512

			f.seek(i.offset - i.suggested_margin)
			src_buf = f.read(i.size + i.suggested_margin)
			src_obj = BytesIO(src_buf)

			hive_obj = RegistryFile.FragmentTranslator(RegistryFile.FragmentWithMarginTranslator(src_obj, i.suggested_margin))
			hive = Registry.RegistryHiveTruncated(hive_obj)
			for item in hive.scan():
				pass

			c += 1

		assert c == 1

	with open(hive_marg_recon_3, 'rb') as f:
		carver = RegistryCarve.Carver(f)

		c = 0
		for i in carver.carve(True, True, True):
			assert i.offset - i.suggested_margin_rounded == 0
			assert i.suggested_margin_rounded == 3584

			f.seek(i.offset - i.suggested_margin)
			src_buf = f.read(i.size + i.suggested_margin)
			src_obj = BytesIO(src_buf)

			hive_obj = RegistryFile.FragmentTranslator(RegistryFile.FragmentWithMarginTranslator(src_obj, i.suggested_margin))
			hive = Registry.RegistryHiveTruncated(hive_obj)
			for item in hive.scan():
				pass

			c += 1

		assert c == 1

def test_invalid_parent_fragment():
	with open(fragment_invalid_parent, 'rb') as f:
		hive_obj = RegistryFile.FragmentTranslator(f)

		hive = Registry.RegistryHiveTruncated(hive_obj)

		c = 0
		for key in hive.scan():
			assert type(key) is Registry.RegistryKey
			assert key.name() == '{dedef10d-30ff-45b5-9d44-b3fa249ecd49}'
			assert key.path_partial() == '{dedef10d-30ff-45b5-9d44-b3fa249ecd49}'

			c += 1

		assert c == 1

def test_bifragmented():
	with open(hive_recon_2, 'rb') as f:
		r = RegistryCarve.HiveReconstructor(f)
		r.find_fragments()

		h = md5()

		c = 0
		for i in r.reconstruct_bifragmented():
			c += 1
			h.update(i[1])

		assert c == 1
		assert h.hexdigest() == 'edaf7986726c1343752763bd1b31ddf2'

def test_trifragmented():
	with open(hive_recon_3, 'rb') as f:
		r = RegistryCarve.HiveReconstructor(f)
		r.find_fragments()

		h = md5()

		c = 0
		for i in r.reconstruct_trifragmented():
			c += 1
			h.update(i[1])

		assert c == 1
		assert h.hexdigest() == '2b9c80fed56a3f25ef7fd03d9462387f'

def test_quadfragmented():
	with open(hive_recon_4, 'rb') as f:
		r = RegistryCarve.HiveReconstructor(f)
		r.find_fragments()

		h = md5()

		c = 0
		for i in r.reconstruct_quadfragmented():
			c += 1
			h.update(i[1])

		assert c == 1
		assert h.hexdigest() == '2b9c80fed56a3f25ef7fd03d9462387f'

def test_biplusfragmented():
	with open(hive_recon_2plus1, 'rb') as f:
		r = RegistryCarve.HiveReconstructor(f)
		r.find_fragments()

		h = md5()

		c = 0
		for i in r.reconstruct_trifragmented():
			c += 1
			h.update(i[1])

		assert c == 1
		assert h.hexdigest() == 'edaf7986726c1343752763bd1b31ddf2'

def test_biandquadfragmented():
	with open(hive_recon_2and4, 'rb') as f:
		r = RegistryCarve.HiveReconstructor(f)
		r.find_fragments()

		c = 0
		for i in r.reconstruct_fragmented():
			c += 1

			h = md5()
			h.update(i[1])
			assert h.hexdigest() == '2b9c80fed56a3f25ef7fd03d9462387f' or h.hexdigest() == 'edaf7986726c1343752763bd1b31ddf2'

		assert c == 2

		h = RegistryCarve.Carver(f)
		l = []
		for i in h.carve(True, True):
			l.append(i)

		r = RegistryCarve.HiveReconstructor(f)
		r.set_fragments(l)

		c = 0
		for i in r.reconstruct_fragmented():
			c += 1

			h = md5()
			h.update(i[1])
			assert h.hexdigest() == '2b9c80fed56a3f25ef7fd03d9462387f' or h.hexdigest() == 'edaf7986726c1343752763bd1b31ddf2'

		assert c == 2

def test_incremental():
	with open(hive_recon_2, 'rb') as f:
		r = RegistryCarve.HiveReconstructor(f)
		r.find_fragments()

		h = md5()

		c = 0
		for i in r.reconstruct_incremental():
			c += 1
			h.update(i[1])

		assert c == 1
		assert h.hexdigest() == 'edaf7986726c1343752763bd1b31ddf2'

	with open(hive_recon_3, 'rb') as f:
		r = RegistryCarve.HiveReconstructor(f)
		r.find_fragments()

		h = md5()

		c = 0
		for i in r.reconstruct_incremental():
			c += 1
			h.update(i[1])

		assert c == 1
		assert h.hexdigest() == '2b9c80fed56a3f25ef7fd03d9462387f'

	with open(hive_recon_4, 'rb') as f:
		r = RegistryCarve.HiveReconstructor(f)
		r.find_fragments()

		h = md5()

		c = 0
		for i in r.reconstruct_incremental():
			c += 1
			h.update(i[1])

		assert c == 1
		assert h.hexdigest() == '2b9c80fed56a3f25ef7fd03d9462387f'

	with open(hive_recon_2plus1, 'rb') as f:
		r = RegistryCarve.HiveReconstructor(f)
		r.find_fragments()

		h = md5()

		c = 0
		for i in r.reconstruct_incremental():
			c += 1
			h.update(i[1])

		assert c == 1
		assert h.hexdigest() == 'edaf7986726c1343752763bd1b31ddf2'

def test_ntfs_data_attr():
	if sys.version_info.major != 3:
		pytest.skip()

	assert not RegistryHelpers.NTFSValidateAndDecodeDataAttributeRecord(b'')

	buf = b'\x80\x00\x00\x00H\x00\x00\x00\x01\x00\x00\x00\x00\x00\x03'
	assert not RegistryHelpers.NTFSValidateAndDecodeDataAttributeRecord(buf)

	buf = b'\x80\x00\x00\x00H\x00\x00\x00\x01\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00Q\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00 \x05\x00\x00\x00\x00\x00\xc0\x10\x05\x00\x00\x00\x00\x00\xc0\x10\x05\x00\x00\x00\x00\x001R\x8d\xef\x00\x00\x00\x00'
	data_attr = RegistryHelpers.NTFSValidateAndDecodeDataAttributeRecord(buf)
	assert data_attr
	assert data_attr.data_runs == [ (61325, 82) ]

	data_size, data_runs = RegistryHelpers.NTFSDecodeMappingPairs(b'')
	assert data_size == 0
	assert data_runs == []

	mapping_pairs = b'\x11\x30\x60\x21\x10\x00\x01\x11\x20\xE0\x00'
	data_size, data_runs = RegistryHelpers.NTFSDecodeMappingPairs(mapping_pairs)
	assert data_size == 96
	assert data_runs == [ (96, 48), (352, 16), (320, 32) ]

	mapping_pairs = b'\x11\x30\x60\x21\x10\x00\x01\x11\x20\xE0\x00\x00'
	data_size, data_runs = RegistryHelpers.NTFSDecodeMappingPairs(mapping_pairs)
	assert data_size == 96
	assert data_runs == [ (96, 48), (352, 16), (320, 32) ]

	mapping_pairs = b'\x11\x30\x60\x21\x10\x00\x01\x11\x20\xE0'
	data_size, data_runs = RegistryHelpers.NTFSDecodeMappingPairs(mapping_pairs)
	assert data_size == 96
	assert data_runs == [ (96, 48), (352, 16), (320, 32) ]

	mapping_pairs = b'\x11\x30\x60\x21\x10\x00\x01\x11\x20'
	data_size, data_runs = RegistryHelpers.NTFSDecodeMappingPairs(mapping_pairs)
	assert data_size == 64
	assert data_runs == [ (96, 48), (352, 16) ]

	mapping_pairs = b'\x11\x30\x20\x01\x60\x11\x10\x30\x00'
	data_size, data_runs = RegistryHelpers.NTFSDecodeMappingPairs(mapping_pairs)
	assert data_size == 48
	assert data_runs == [ (32, 48) ]

	buf = b'\x80\x00\x00\x00H\x00\x00\x00\x01\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00Q\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00 \x05\x00\x00\x00\x00\x00\xc0\x10\x05\x00\x00\x00\x00\x00\xc0\x10\x05\x00\x00\x00\x00\x001R\x8d\xef\x00\x00\x00\x00'
	data_attrs = RegistryHelpers.NTFSFindDataAttributeRecords(buf)
	assert len(data_attrs) == 1
	assert data_attrs[0].data_runs == [ (61325, 82) ]

	buf = b'\x00\x80\x00\x00\x00H\x00\x00\x00\x01\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00Q\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00 \x05\x00\x00\x00\x00\x00\xc0\x10\x05\x00\x00\x00\x00\x00\xc0\x10\x05\x00\x00\x00\x00\x001R\x8d\xef\x00\x00\x00\x00'
	data_attrs = RegistryHelpers.NTFSFindDataAttributeRecords(buf)
	assert len(data_attrs) == 1
	assert data_attrs[0].data_runs == [ (61325, 82) ]

	buf = b'\x00\x00\x80\x00\x00\x00H\x00\x00\x00\x01\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00Q\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00 \x05\x00\x00\x00\x00\x00\xc0\x10\x05\x00\x00\x00\x00\x00\xc0\x10\x05\x00\x00\x00\x00\x001R\x8d\xef\x00\x00\x00\x00'
	data_attrs = RegistryHelpers.NTFSFindDataAttributeRecords(buf)
	assert len(data_attrs) == 1
	assert data_attrs[0].data_runs == [ (61325, 82) ]

	assert RegistryHelpers.NTFSFindDataAttributeRecords(b'') == []

def test_sid_parsing():
	if sys.version_info.major != 3:
		pytest.skip()

	sid = b'\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x32\x16\x89\x26\x0e\x2f\xad\x6f\xfa\x0f\xef\x24\x56\x04\x00\x00'
	assert RegistryHelpers.ParseSID(sid) == 'S-1-5-21-646518322-1873620750-619646970-1110'

	sid_tooshort = sid[ : -1]
	with pytest.raises(ValueError):
		RegistryHelpers.ParseSID(sid_tooshort)

	sid_tooshort = sid[ : -2]
	with pytest.raises(ValueError):
		RegistryHelpers.ParseSID(sid_tooshort)

	sid_tooshort = sid[ : -3]
	with pytest.raises(ValueError):
		RegistryHelpers.ParseSID(sid_tooshort)

	sid_tooshort = sid[ : -4]
	with pytest.raises(ValueError):
		RegistryHelpers.ParseSID(sid_tooshort)

	sid_tooshort = sid[ : -5]
	with pytest.raises(ValueError):
		RegistryHelpers.ParseSID(sid_tooshort)

	sid_toolong = sid + b'\x00'
	assert RegistryHelpers.ParseSID(sid_toolong) == 'S-1-5-21-646518322-1873620750-619646970-1110'

	sid_toolong = sid + b'\x00\x00'
	assert RegistryHelpers.ParseSID(sid_toolong) == 'S-1-5-21-646518322-1873620750-619646970-1110'

def test_key_security():
	if sys.version_info.major != 3:
		pytest.skip()

	with open(hive_empty, 'rb') as primary:
		hive = Registry.RegistryHive(primary)
		descriptor = hive.root_key().security().descriptor()
		secinfo = RegistryHelpers.ParseSecurityDescriptorRelative(descriptor)
		assert secinfo.owner_sid == 'S-1-5-32-544'

def test_lz77():
	assert RegistryHelpers.LZ77DecompressBuffer(b'') == (b'', True, 0)
	assert RegistryHelpers.LZ77DecompressBuffer(b'1') == (b'', True, 0)
	assert RegistryHelpers.LZ77DecompressBuffer(b'12') == (b'', True, 0)
	assert RegistryHelpers.LZ77DecompressBuffer(b'123') == (b'', True, 0)
	assert RegistryHelpers.LZ77DecompressBuffer(b'1234') == (b'', True, 4)

	compressed_data = b'\x3F\x00\x00\x00\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A'
	decompressed_data = b'abcdefghijklmnopqrstuvwxyz'
	assert RegistryHelpers.LZ77DecompressBuffer(compressed_data) == (decompressed_data, False, len(compressed_data))

	assert RegistryHelpers.LZ77DecompressBuffer(compressed_data + b'\x00') == (decompressed_data, True, len(compressed_data))
	assert RegistryHelpers.LZ77DecompressBuffer(compressed_data + b'\xFF') == (decompressed_data, True, len(compressed_data))
	assert RegistryHelpers.LZ77DecompressBuffer(compressed_data + b'\xFF\xFF') == (decompressed_data, True, len(compressed_data) + 2)
	assert RegistryHelpers.LZ77DecompressBuffer(compressed_data + b'\xFF\xFF\xFF') == (decompressed_data, True, len(compressed_data) + 3)
	assert RegistryHelpers.LZ77DecompressBuffer(compressed_data + b'\xFF\xFF\xFF\xFF') == (decompressed_data, True, len(compressed_data) + 4)

	compressed_data = b'\xFF\xFF\xFF\x1F\x61\x62\x63\x17\x00\x0F\xFF\x26\x01'
	decompressed_data = b'abc' * 100
	assert RegistryHelpers.LZ77DecompressBuffer(compressed_data) == (decompressed_data, False, len(compressed_data))

	assert RegistryHelpers.LZ77DecompressBuffer(compressed_data + b'\x00') == (decompressed_data, True, len(compressed_data))
	assert RegistryHelpers.LZ77DecompressBuffer(compressed_data + b'\xFF') == (decompressed_data, True, len(compressed_data))
	assert RegistryHelpers.LZ77DecompressBuffer(compressed_data + b'\xFF\xFF') == (decompressed_data, True, len(compressed_data) + 2)
	assert RegistryHelpers.LZ77DecompressBuffer(compressed_data + b'\xFF\xFF\xFF') == (decompressed_data, True, len(compressed_data) + 2)
	assert RegistryHelpers.LZ77DecompressBuffer(compressed_data + b'\xFF\xFF\xFF\xFF') == (decompressed_data, True, len(compressed_data) + 2)
	assert RegistryHelpers.LZ77DecompressBuffer(compressed_data + b'\xFF\xFF\xFF\xFF\xFF') == (decompressed_data, True, len(compressed_data) + 2)

	assert RegistryHelpers.LZ77CheckCompressedSignature(b'\x04\x00\x10\x00\x68\x62\x69\x6E', b'hbin')
	assert RegistryHelpers.LZ77CheckCompressedSignature(b'\x04\x00\x10\x00\x68\x62\x69\x6E', b'hbi')
	assert RegistryHelpers.LZ77CheckCompressedSignature(b'\x04\x00\x10\x00\x68\x62\x69\x6E', b'hb')
	assert RegistryHelpers.LZ77CheckCompressedSignature(b'\x04\x00\x10\x00\x68\x62\x69\x6E', b'h')
	assert not RegistryHelpers.LZ77CheckCompressedSignature(b'\x04\x00\x10\x00\x68\x62\x69\x6E', b'hbin1234')

def test_lz77huffman():
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(b'') == (b'', True, 0)
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(b'1') == (b'', True, 0)
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(b'12') == (b'', True, 0)
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(b'123') == (b'', True, 0)
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(b'1234') == (b'', True, 0)

	compressed_data = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x45\x44\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd8\x52\x3e\xd7\x94\x11\x5b\xe9\x19\x5f\xf9\xd6\x7c\xdf\x8d\x04\x00\x00\x00\x00'
	decompressed_data = b'abcdefghijklmnopqrstuvwxyz'
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data) == (decompressed_data, False, len(compressed_data))

	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data + b'\x00') == (decompressed_data, False, len(compressed_data))
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data + b'\xFF') == (decompressed_data, False, len(compressed_data))
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data + b'\xFF\xFF') == (decompressed_data, False, len(compressed_data))
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data + b'\xFF\xFF\xFF') == (decompressed_data, False, len(compressed_data))
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data + b'\xFF\xFF\xFF\xFF') == (decompressed_data, False, len(compressed_data))
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data + b'\xFF\xFF\xFF\xFF\xFF') == (decompressed_data, False, len(compressed_data))

	compressed_data = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x23\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa8\xdc\x00\x00\xff\x26\x01'
	decompressed_data = b'abc' * 100

	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data) == (decompressed_data, False, len(compressed_data))

	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data + b'\x00') == (decompressed_data, False, len(compressed_data))
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data + b'\xFF') == (decompressed_data, False, len(compressed_data))
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data + b'\xFF\xFF') == (decompressed_data, False, len(compressed_data))
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data + b'\xFF\xFF\xFF') == (decompressed_data, False, len(compressed_data))
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data + b'\xFF\xFF\xFF\xFF') == (decompressed_data, False, len(compressed_data))
	assert RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data + b'\xFF\xFF\xFF\xFF\xFF') == (decompressed_data, False, len(compressed_data))

	a = RegistryHelpers.LZ77HuffmanDecompressBuffer(compressed_data + b'\xFF\xFF\xFF\xFF\xFF', True)
	assert a[0].startswith(decompressed_data)
	assert a[1]

def test_memcarving():
	with open(hive_memcarving_0, 'rb') as f:
		carver = RegistryCarve.MemoryCarver(f)
		assert carver.fileno is not None

		c = 0
		for i in carver.carve():
			c += 1
			assert i.offset == 0
			assert len(i.buffer) == 28672
			assert i.hbin_start == 0
			assert not i.compressed

		assert c == 1

	with open(hive_memcarving_1, 'rb') as f:
		carver = RegistryCarve.MemoryCarver(f)
		assert carver.fileno is not None

		c = 0
		for i in carver.carve():
			c += 1
			assert i.offset == 1
			assert len(i.buffer) == 28672
			assert i.hbin_start == 0
			assert not i.compressed

		assert c == 1

	with open(hive_memcarving_1, 'rb') as f:
		d = f.read()

		carver = RegistryCarve.MemoryCarver(d)
		assert carver.fileno is None

		c = 0
		for i in carver.carve():
			c += 1
			assert i.offset == 1
			assert len(i.buffer) == 28672
			assert i.hbin_start == 0
			assert not i.compressed

		assert c == 1

	with open(hive_memcarving_3, 'rb') as f:
		carver = RegistryCarve.MemoryCarver(f)

		c = 0
		for i in carver.carve():
			c += 1
			assert i.offset == 3
			assert len(i.buffer) == 28672
			assert i.hbin_start == 0
			assert not i.compressed

		assert c == 1

	with open(hive_memcarving_3, 'rb') as f:
		d = f.read()

		carver = RegistryCarve.MemoryCarver(d)
		assert carver.fileno is None

		c = 0
		for i in carver.carve():
			c += 1
			assert i.offset == 3
			assert len(i.buffer) == 28672
			assert i.hbin_start == 0
			assert not i.compressed

		assert c == 1

	with open(hive_memcarving_2fragments, 'rb') as f:
		carver = RegistryCarve.MemoryCarver(f)
		assert carver.fileno is not None

		c = 0
		for i in carver.carve():
			c += 1

			if c == 1:
				assert i.offset == 2 and len(i.buffer) == 510
			elif c == 2:
				assert i.offset == 512 and len(i.buffer) == 28672

			assert i.hbin_start == 0
			assert not i.compressed

		assert c == 2

	with open(hive_memcarving_2fragments_gap, 'rb') as f:
		carver = RegistryCarve.MemoryCarver(f)
		assert carver.fileno is not None

		c = 0
		for i in carver.carve():
			c += 1

			if c == 1:
				assert i.offset == 2 and len(i.buffer) == 511
			elif c == 2:
				assert i.offset == 513 and len(i.buffer) == 28672

			assert i.hbin_start == 0
			assert not i.compressed

		assert c == 2

	with open(hive_duplicate_subkeys, 'rb') as f:
		carver = RegistryCarve.MemoryCarver(f)
		assert carver.fileno is not None

		c = 0
		for i in carver.carve():
			c += 1
			if c == 1:
				assert i.offset == 4096
				assert i.hbin_start == 0
				assert len(i.buffer) == 32 * 4096
				assert not i.compressed
			elif c == 2:
				assert i.offset == 4096 + 32 * 4096
				assert i.hbin_start == 32 * 4096
				assert len(i.buffer) == 32 * 4096
				assert not i.compressed
			elif c == 3:
				assert i.offset == 4096 + 64 * 4096
				assert i.hbin_start == 64 * 4096
				assert len(i.buffer) == 32 * 4096
				assert not i.compressed
			elif c == 4:
				assert i.offset == 4096 + 96 * 4096
				assert i.hbin_start == 96 * 4096
				assert len(i.buffer) > 0 and len(i.buffer) < 32 * 4096
				assert not i.compressed

		assert c == 4

	with open(hive_memcarving_2fragments_gap2, 'rb') as f:
		carver = RegistryCarve.MemoryCarver(f)
		assert carver.fileno is not None

		c = 0
		for i in carver.carve():
			c += 1

			if c == 1:
				assert i.offset == 2 and len(i.buffer) == 512
			elif c == 2:
				assert i.offset == 514 and len(i.buffer) == 28672

			assert i.hbin_start == 0
			assert not i.compressed

		assert c == 2

	with open(hive_memcarving_hbin_compressed, 'rb') as f:
		carver = RegistryCarve.MemoryCarver(f)
		assert carver.fileno is not None

		c = 0
		for i in carver.carve():
			c += 1

			assert i.offset == 0 and len(i.buffer) == 4096
			assert i.hbin_start == 0
			assert i.compressed

		assert c == 1

	def prepare_compressed_image(gap_size):
		with open(hive_memcarving_0, 'rb') as f:
			normal_data = f.read()

		with open(hive_memcarving_hbin_compressed, 'rb') as f:
			compressed_data = f.read()

		f = BytesIO()
		f.write(normal_data)

		if gap_size > 0:
			f.write(b'\x00' * gap_size)

		f.write(compressed_data)

		return f

	k = 0
	for gap_size in [ 0, 1, 2, 3, 15, 16, 17 ]:
		f = prepare_compressed_image(gap_size)

		carver = RegistryCarve.MemoryCarver(f)

		c = 0
		for i in carver.carve():
			c += 1

			if c == 1:
				assert i.offset == 0
				assert len(i.buffer) == 28672
				assert i.hbin_start == 0
				assert not i.compressed
			elif c == 2:
				assert i.offset == 28672 + gap_size
				assert len(i.buffer) == 4096
				assert i.hbin_start == 0
				assert i.compressed


		if gap_size % 16 != 0:
			assert c == 1
		else:
			assert c == 2
			k += 1

	assert k == 2

def test_log_carving_1():
	global found
	found = 0

	def test_translator(buf):
		src_obj = BytesIO(buf)
		log_file = RegistryFile.LogEntriesTranslator(src_obj)
		log = RegistryFile.NewLogFile(log_file)

		for l in log.log_entries():
			assert type(l) is RegistryFile.LogEntry

		for l in log.remnant_log_entries(False):
			assert False

		c = 0
		for l in log.remnant_log_entries(True):
			c += 1
			assert type(l) is RegistryFile.LogEntry

		hive_obj = log.rebuild_primary_file_using_remnant_log_entries(True)
		hive = Registry.RegistryHiveTruncated(hive_obj)

		cc = 0

		for l in hive.scan():
			if type(l) is Registry.RegistryKey:
				if 'find_me_' in l.name():
					global found
					found += 1

			cc += 1

		assert cc > 0

		src_obj.close()
		return c


	if sys.version_info.major != 3:
		# For some reason, this test works well with Python 3 only.
		# When Python 2.7 is used, the test fails (no log entries found) unless an uncompressed disk image is given (instead of the TGZ archive).

		try:
			f = open(log_carving_bootcamp_raw, 'rb')
		except Exception:
			pytest.skip() # Skip the test, if there is no uncompressed disk image.
	else:
		f = tarfile.open(log_carving_bootcamp, 'r:gz').extractfile('bootcamp_unallocated_decrypted_nogarbage_sparse.raw')

	carver = RegistryCarve.Carver(f)

	c = 0
	l = 0
	found_multiple = False
	for i in carver.carve(True, True, True, True):
		if type(i) is RegistryCarve.CarveResultLog:
			c += i.log_entries_count
			if i.log_entries_count > 2:
				found_multiple = True

			f.seek(i.offset)
			buf_log = f.read(i.size)
			l += test_translator(buf_log)

	assert c == 14
	assert found_multiple
	assert l == c
	assert found > 0

	f.close()

def test_log_carving_2():
	def test_translator(buf):
		src_obj = BytesIO(buf)
		log_file = RegistryFile.LogEntriesTranslator(src_obj)
		log = RegistryFile.NewLogFile(log_file)

		for l in log.log_entries():
			assert type(l) is RegistryFile.LogEntry

		for l in log.remnant_log_entries(False):
			assert False

		for l in log.remnant_log_entries(True):
			assert type(l) is RegistryFile.LogEntry

		hive_obj = log.rebuild_primary_file_using_remnant_log_entries(True)
		hive = Registry.RegistryHiveTruncated(hive_obj)

		cc = 0
		for l in hive.scan():
			cc += 1

		assert cc > 5

		src_obj.close()


	with open(hive_dirty_new1_log2, 'rb') as f:
		buf = f.read()

	f = BytesIO(buf[512 : ])
	carver = RegistryCarve.Carver(f)

	cnt = 0
	for i in carver.carve(True, True, True, True):
		cnt += 1
		assert type(i) is RegistryCarve.CarveResultLog
		assert i.offset == 0 and i.size == 40448

		f.seek(i.offset)
		buf_log = f.read(i.size)
		test_translator(buf_log)

	assert cnt == 1

	f.close()

	f = BytesIO(buf)
	carver = RegistryCarve.Carver(f)

	cnt = 0
	for i in carver.carve(True, True, True, True):
		cnt += 1
		assert type(i) is RegistryCarve.CarveResultLog
		assert i.offset == 512 and i.size == 40448

		f.seek(i.offset)
		buf_log = f.read(i.size)
		test_translator(buf_log)

	assert cnt == 1

	f.close()

	f = BytesIO(buf[128 : ])
	carver = RegistryCarve.Carver(f)

	for i in carver.carve(True, True, True, True):
		assert False

	f.close()

	f = BytesIO(buf[8192 : ] + buf[512 : 8192])
	carver = RegistryCarve.Carver(f)

	cnt = 0
	for i in carver.carve(True, True, True, True):
		cnt += 1
		assert type(i) is RegistryCarve.CarveResultLog
		assert (cnt == 1 and i.offset == 0 and i.size == 32768) or (cnt == 2 and i.offset == 57344 and i.size == 7680)

		f.seek(i.offset)
		buf_log = f.read(i.size)
		test_translator(buf_log)

	assert cnt == 2

	f.close()

	f = BytesIO(buf[8192 : 8192 + 32768] + buf[512 : 8192])
	carver = RegistryCarve.Carver(f)

	cnt = 0
	for i in carver.carve(True, True, True, True):
		cnt += 1
		assert type(i) is RegistryCarve.CarveResultLog
		assert (cnt == 1 and i.offset == 0 and i.size == 32768) or (cnt == 2 and i.offset == 32768 and i.size == 7680)

		f.seek(i.offset)
		buf_log = f.read(i.size)
		test_translator(buf_log)

	assert cnt == 2

	f.close()

	f = BytesIO(buf[512 : 8192] + buf[512 : 8192])
	carver = RegistryCarve.Carver(f)

	cnt = 0
	for i in carver.carve(True, True, True, True):
		cnt += 1
		assert type(i) is RegistryCarve.CarveResultLog
		assert i.size == 7680

		f.seek(i.offset)
		buf_log = f.read(i.size)
		test_translator(buf_log)

	assert cnt == 2

	f.close()

	padding = b'HvLE' * 128
	f = BytesIO(buf[512 : 8192] + padding + buf[512 : 8192])
	carver = RegistryCarve.Carver(f)

	cnt = 0
	for i in carver.carve(True, True, True, True):
		cnt += 1
		assert type(i) is RegistryCarve.CarveResultLog
		assert i.size == 7680

		f.seek(i.offset)
		buf_log = f.read(i.size)
		test_translator(buf_log)

	assert cnt == 2

	f.close()

	f = BytesIO(padding + buf[512 : 8192] + padding + buf[512 : 8192])
	carver = RegistryCarve.Carver(f)

	cnt = 0
	for i in carver.carve(True, True, True, True):
		cnt += 1
		assert type(i) is RegistryCarve.CarveResultLog
		assert i.size == 7680

		f.seek(i.offset)
		buf_log = f.read(i.size)
		test_translator(buf_log)

	assert cnt == 2

	f.close()

	f = BytesIO(padding + buf[513 : 8193] + padding + buf[512 : 8192])
	carver = RegistryCarve.Carver(f)

	cnt = 0
	for i in carver.carve(True, True, True, True):
		cnt += 1
		assert type(i) is RegistryCarve.CarveResultLog
		assert i.size == 7680

		f.seek(i.offset)
		buf_log = f.read(i.size)
		test_translator(buf_log)

	assert cnt == 1

	f.close()

def test_layered_keys():
	f = open(delta_hive, 'rb')
	h = Registry.RegistryHive(f)

	assert h.are_layered_keys_supported()

	k = h.find_key('\\ControlSet001\\Services\\xboxgipsvc')
	assert k.key_node.get_layered_key_bit_fields() == (RegistryRecords.KEY_INHERIT_CLASS | RegistryRecords.KEY_IS_SUPERSEDE_TREE)

	assert k.flags_str() == 'InheritClass | IsSupersedeTree'

	k = h.find_key('\\ControlSet001\\Services\\xboxgipsvc\\a_subkey')
	assert k.key_node.get_layered_key_bit_fields() == RegistryRecords.KEY_IS_SUPERSEDE_TREE

	assert k.flags_str() == 'IsSupersedeTree'

	k = h.find_key('\\ControlSet001\\Services\\XBOXGIP')
	assert k.key_node.get_layered_key_bit_fields() == RegistryRecords.KEY_IS_TOMBSTONE

	assert k.flags_str() == 'IsTombstone'

	v = h.find_key('\\ControlSet001\\Services\\XboxNetApiSvc').value('displayname')
	assert v.key_value.get_flags() & RegistryRecords.VALUE_TOMBSTONE > 0
	assert v.flags_str() == 'IsTombstone'

	v = h.find_key('\\ControlSet001\\Services\\XboxNetApiSvc').value('start')
	assert v.key_value.get_flags() & RegistryRecords.VALUE_TOMBSTONE == 0
	assert v.flags_str() is None

	f.close()

	f = open(hive_strings, 'rb')
	h = Registry.RegistryHive(f)

	assert not h.are_layered_keys_supported()

	k = h.find_key('kEy')
	assert k.flags_str() is None
	f.close()
