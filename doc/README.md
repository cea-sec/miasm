# Documentation

Miasm documentation is organized around the following elements:

- code comments, as:
```python
>>> from miasm.core.locationdb import LocationDB
>>> help(LocationDB)

class LocationDB(builtins.object)
 |  LocationDB is a "database" of information associated to location.
 |  
 |  An entry in a LocationDB is uniquely identified with a LocKey.
 |  Additional information which can be associated with a LocKey are:
 |  - an offset (uniq per LocationDB)
 |  - several names (each are uniqs per LocationDB)
 |  
 |  As a schema:
 |  loc_key  1 <-> 0..1  offset
 |           1 <-> 0..n  name
 |  
 |  >>> loc_db = LocationDB()
 |  # Add a location with no additional information
 |  >>> loc_key1 = loc_db.add_location()
 |  # Add a location with an offset
 |  >>> loc_key2 = loc_db.add_location(offset=0x1234)
 |  # Add a location with several names
 |  >>> loc_key3 = loc_db.add_location(name="first_name")
 |  >>> loc_db.add_location_name(loc_key3, "second_name")
 |  # Associate an offset to an existing location
 |  >>> loc_db.set_location_offset(loc_key3, 0x5678)
 |  # Remove a name from an existing location
 |  >>> loc_db.remove_location_name(loc_key3, "second_name")
...
```

- examples for the main features (see `/example`)
- interactive tutorials (IPython Notebooks) on the following topics:
  - Miasm's IR bricks known as `Expr`: [notebook](expression/expression.ipynb)
  - Lifting from assembly to IR: [notebook](ir/lift.ipynb)
  - `LocationDB` usage, the database for locations: [notebook](locationdb/locationdb.ipynb)
- more complex examples through blog posts on [miasm.re](https://miasm.re)
- cheatsheets:
  - `Sandbox` and associated emulation options: [cheatsheet](cheatsheets/reminder_sandbox.pdf)
  - Disassembler, lifter and associated structures: [cheatsheet](cheatsheets/reminder_disassembler.pdf)
