from builtins import str
from miasm.core.locationdb import LocationDB


# Basic tests (LocationDB description)
loc_db = LocationDB()
loc_key1 = loc_db.add_location()
loc_key2 = loc_db.add_location(offset=0x1234)
loc_key3 = loc_db.add_location(name="first_name")
loc_db.add_location_name(loc_key3, "second_name")
loc_db.set_location_offset(loc_key3, 0x5678)
loc_db.remove_location_name(loc_key3, "second_name")

assert loc_db.get_location_offset(loc_key1) is None
assert loc_db.get_location_offset(loc_key2) == 0x1234

assert loc_db.pretty_str(loc_key1) == str(loc_key1)
assert loc_db.pretty_str(loc_key2) == "loc_1234"
assert loc_db.pretty_str(loc_key3) == "first_name"
loc_db.consistency_check()

# Offset manipulation
loc_key4 = loc_db.add_location()
assert loc_db.get_location_offset(loc_key4) is None
loc_db.set_location_offset(loc_key4, 0x1122)
assert loc_db.get_location_offset(loc_key4) == 0x1122
loc_db.unset_location_offset(loc_key4)
assert loc_db.get_location_offset(loc_key4) is None
try:
    loc_db.set_location_offset(loc_key4, 0x1234)
    has_raised = False
except KeyError:
    has_raised = True
assert has_raised
assert loc_db.get_location_offset(loc_key4) is None
loc_db.set_location_offset(loc_key4, 0x1122)
try:
    loc_db.set_location_offset(loc_key4, 0x1123)
    has_raised = False
except ValueError:
    has_raised = True
assert has_raised
assert loc_db.get_location_offset(loc_key4) == 0x1122
loc_db.set_location_offset(loc_key4, 0x1123, force=True)
assert loc_db.get_location_offset(loc_key4) == 0x1123
assert 0x1123 in loc_db.offsets
try:
    loc_db.add_location(offset=0x1123)
    has_raised = False
except ValueError:
    has_raised = True
assert loc_db.add_location(offset=0x1123, strict=False) == loc_key4
assert loc_db.get_offset_location(0x1123) == loc_key4
assert loc_db.get_or_create_offset_location(0x1123) == loc_key4
loc_key4_bis = loc_db.get_or_create_offset_location(0x1144)
assert loc_db.get_offset_location(0x1144) == loc_key4_bis
loc_db.consistency_check()

# Names manipulation
loc_key5 = loc_db.add_location()
name1 = "name1"
name2 = "name2"
name3 = "name3"
assert len(loc_db.get_location_names(loc_key5)) == 0
loc_db.add_location_name(loc_key5, name1)
loc_db.add_location_name(loc_key5, name2)
assert name1 in loc_db.names
assert name2 in loc_db.names
assert name1 in loc_db.get_location_names(loc_key5)
assert name2 in loc_db.get_location_names(loc_key5)
assert loc_db.get_name_location(name1) == loc_key5
loc_db.remove_location_name(loc_key5, name1)
assert name1 not in loc_db.names
assert name1 not in loc_db.get_location_names(loc_key5)
try:
    loc_db.remove_location_name(loc_key5, name1)
    has_raised = False
except KeyError:
    has_raised = True
try:
    loc_db.add_location_name(loc_key1, name2)
    has_raised = False
except KeyError:
    has_raised = True
try:
    loc_db.add_location(name=name2)
    has_raised = False
except ValueError:
    has_raised = True
assert loc_db.add_location(name=name2, strict=False) == loc_key5
assert loc_db.get_or_create_name_location(name2) == loc_key5
loc_key5_bis = loc_db.get_or_create_name_location(name3)
assert loc_db.get_name_location(name3) == loc_key5_bis
loc_db.consistency_check()

# Name and offset manipulation
assert loc_db.get_name_offset(name2) is None
assert loc_db.get_name_offset("unk_name") is None
assert loc_db.get_name_offset("first_name") == 0x5678

# Merge
loc_db2 = LocationDB()
loc_db2.add_location(offset=0x3344)
loc_db2.add_location(name=name2)
loc_db.merge(loc_db2)
assert 0x3344 in loc_db.offsets
assert name2 in loc_db.names
loc_db.consistency_check()
assert loc_db.get_name_location(name2) == loc_key5

# Delete
loc_db.remove_location(loc_key5)
assert loc_db.get_name_location(name2) is None
loc_db.consistency_check()
