import warnings
from builtins import int as int_types

from functools import reduce
from future.utils import viewitems, viewvalues

from miasm.core.utils import printable
from miasm.expression.expression import LocKey, ExprLoc


class LocationDB(object):
    """
    LocationDB is a "database" of information associated to location.

    An entry in a LocationDB is uniquely identified with a LocKey.
    Additional information which can be associated with a LocKey are:
    - an offset (uniq per LocationDB)
    - several names (each are uniqs per LocationDB)

    As a schema:
    loc_key  1 <-> 0..1  offset
             1 <-> 0..n  name

    >>> loc_db = LocationDB()
    # Add a location with no additional information
    >>> loc_key1 = loc_db.add_location()
    # Add a location with an offset
    >>> loc_key2 = loc_db.add_location(offset=0x1234)
    # Add a location with several names
    >>> loc_key3 = loc_db.add_location(name="first_name")
    >>> loc_db.add_location_name(loc_key3, "second_name")
    # Associate an offset to an existing location
    >>> loc_db.set_location_offset(loc_key3, 0x5678)
    # Remove a name from an existing location
    >>> loc_db.remove_location_name(loc_key3, "second_name")

    # Get back offset
    >>> loc_db.get_location_offset(loc_key1)
    None
    >>> loc_db.get_location_offset(loc_key2)
    0x1234
    >>> loc_db.get_location_offset("first_name")
    0x5678

    # Display a location
    >>> loc_db.pretty_str(loc_key1)
    loc_key_1
    >>> loc_db.pretty_str(loc_key2)
    loc_1234
    >>> loc_db.pretty_str(loc_key3)
    first_name
    """

    def __init__(self):
        # Known LocKeys
        self._loc_keys = set()

        # Association tables
        self._loc_key_to_offset = {}
        self._loc_key_to_names = {}
        self._name_to_loc_key = {}
        self._offset_to_loc_key = {}

        # Counter for new LocKey generation
        self._loc_key_num = 0

    def get_location_offset(self, loc_key):
        """
        Return the offset of @loc_key if any, None otherwise.
        @loc_key: LocKey instance
        """
        assert isinstance(loc_key, LocKey)
        return self._loc_key_to_offset.get(loc_key)

    def get_location_names(self, loc_key):
        """
        Return the frozenset of names associated to @loc_key
        @loc_key: LocKey instance
        """
        assert isinstance(loc_key, LocKey)
        return frozenset(self._loc_key_to_names.get(loc_key, set()))

    def get_name_location(self, name):
        """
        Return the LocKey of @name if any, None otherwise.
        @name: target name
        """
        assert isinstance(name, str)
        return self._name_to_loc_key.get(name)

    def get_or_create_name_location(self, name):
        """
        Return the LocKey of @name if any, create one otherwise.
        @name: target name
        """
        assert isinstance(name, str)
        loc_key = self._name_to_loc_key.get(name)
        if loc_key is not None:
            return loc_key
        return self.add_location(name=name)

    def get_offset_location(self, offset):
        """
        Return the LocKey of @offset if any, None otherwise.
        @offset: target offset
        """
        return self._offset_to_loc_key.get(offset)

    def get_or_create_offset_location(self, offset):
        """
        Return the LocKey of @offset if any, create one otherwise.
        @offset: target offset
        """
        loc_key = self._offset_to_loc_key.get(offset)
        if loc_key is not None:
            return loc_key
        return self.add_location(offset=offset)

    def get_name_offset(self, name):
        """
        Return the offset of @name if any, None otherwise.
        @name: target name
        """
        assert isinstance(name, str)
        loc_key = self.get_name_location(name)
        if loc_key is None:
            return None
        return self.get_location_offset(loc_key)

    def add_location_name(self, loc_key, name):
        """Associate a name @name to a given @loc_key
        @name: str instance
        @loc_key: LocKey instance
        """
        assert isinstance(name, str)
        assert loc_key in self._loc_keys
        already_existing_loc = self._name_to_loc_key.get(name)
        if already_existing_loc is not None and already_existing_loc != loc_key:
            raise KeyError("%r is already associated to a different loc_key "
                           "(%r)" % (name, already_existing_loc))
        self._loc_key_to_names.setdefault(loc_key, set()).add(name)
        self._name_to_loc_key[name] = loc_key

    def remove_location_name(self, loc_key, name):
        """Disassociate a name @name from a given @loc_key
        Fail if @name is not already associated to @loc_key
        @name: str instance
        @loc_key: LocKey instance
        """
        assert loc_key in self._loc_keys
        assert isinstance(name, str)
        already_existing_loc = self._name_to_loc_key.get(name)
        if already_existing_loc is None:
            raise KeyError("%r is not already associated" % name)
        if already_existing_loc != loc_key:
            raise KeyError("%r is already associated to a different loc_key "
                           "(%r)" % (name, already_existing_loc))
        del self._name_to_loc_key[name]
        self._loc_key_to_names[loc_key].remove(name)

    def set_location_offset(self, loc_key, offset, force=False):
        """Associate the offset @offset to an LocKey @loc_key

        If @force is set, override silently. Otherwise, if an offset is already
        associated to @loc_key, an error will be raised
        """
        assert loc_key in self._loc_keys
        already_existing_loc = self.get_offset_location(offset)
        if already_existing_loc is not None and already_existing_loc != loc_key:
            raise KeyError("%r is already associated to a different loc_key "
                           "(%r)" % (offset, already_existing_loc))
        already_existing_off = self._loc_key_to_offset.get(loc_key)
        if (already_existing_off is not None and
            already_existing_off != offset):
            if not force:
                raise ValueError(
                    "%r already has an offset (0x%x). Use 'force=True'"
                    " for silent overriding" % (
                        loc_key, already_existing_off
                    ))
            else:
                self.unset_location_offset(loc_key)
        self._offset_to_loc_key[offset] = loc_key
        self._loc_key_to_offset[loc_key] = offset

    def unset_location_offset(self, loc_key):
        """Disassociate LocKey @loc_key's offset

        Fail if there is already no offset associate with it
        @loc_key: LocKey
        """
        assert loc_key in self._loc_keys
        already_existing_off = self._loc_key_to_offset.get(loc_key)
        if already_existing_off is None:
            raise ValueError("%r already has no offset" % (loc_key))
        del self._offset_to_loc_key[already_existing_off]
        del self._loc_key_to_offset[loc_key]

    def consistency_check(self):
        """Ensure internal structures are consistent with each others"""
        assert set(self._loc_key_to_names).issubset(self._loc_keys)
        assert set(self._loc_key_to_offset).issubset(self._loc_keys)
        assert self._loc_key_to_offset == {v: k for k, v in viewitems(self._offset_to_loc_key)}
        assert reduce(
            lambda x, y:x.union(y),
            viewvalues(self._loc_key_to_names),
            set(),
        ) == set(self._name_to_loc_key)
        for name, loc_key in viewitems(self._name_to_loc_key):
            assert name in self._loc_key_to_names[loc_key]

    def find_free_name(self, name):
        """
        If @name is not known in DB, return it
        Else append an index to it corresponding to the next unknown name

        @name: string
        """
        assert isinstance(name, str)
        if self.get_name_location(name) is None:
            return name
        i = 0
        while True:
            new_name = "%s_%d" % (name, i)
            if self.get_name_location(new_name) is None:
                return new_name
            i += 1

    def add_location(self, name=None, offset=None, strict=True):
        """Add a new location in the locationDB. Returns the corresponding LocKey.
        If @name is set, also associate a name to this new location.
        If @offset is set, also associate an offset to this new location.

        Strict mode (set by @strict, default):
          If a location with @offset or @name already exists, an error will be
        raised.
        Otherwise:
          If a location with @offset or @name already exists, the corresponding
        LocKey may be updated and will be returned.
        """

        # Deprecation handling
        if isinstance(name, int_types):
            assert offset is None or offset == name
            warnings.warn("Deprecated API: use 'add_location(offset=)' instead."
                          " An additional 'name=' can be provided to also "
                          "associate a name (there is no more default name)")
            offset = name
            name = None

        # Argument cleaning
        offset_loc_key = None
        if offset is not None:
            offset = int(offset)
            offset_loc_key = self.get_offset_location(offset)

        # Test for collisions
        name_loc_key = None
        if name is not None:
            assert isinstance(name, str)
            name_loc_key = self.get_name_location(name)

        if strict:
            if name_loc_key is not None:
                raise ValueError("An entry for %r already exists (%r), and "
                                 "strict mode is enabled" % (
                                     name, name_loc_key
                                 ))
            if offset_loc_key is not None:
                raise ValueError("An entry for 0x%x already exists (%r), and "
                                 "strict mode is enabled" % (
                                     offset, offset_loc_key
                                 ))
        else:
            # Non-strict mode
            if name_loc_key is not None:
                known_offset = self.get_offset_location(name_loc_key)
                if known_offset is None:
                    if offset is not None:
                        self.set_location_offset(name_loc_key, offset)
                elif known_offset != offset:
                    raise ValueError(
                        "Location with name '%s' already have an offset: 0x%x "
                        "(!= 0x%x)" % (name, offset, known_offset)
                        )
                # Name already known, same offset -> nothing to do
                return name_loc_key

            elif offset_loc_key is not None:
                if name is not None:
                    # Check for already known name are checked above
                    return self.add_location_name(offset_loc_key, name)
                # Offset already known, no name specified
                return offset_loc_key

        # No collision, this is a brand new location
        loc_key = LocKey(self._loc_key_num)
        self._loc_key_num += 1
        self._loc_keys.add(loc_key)

        if offset is not None:
            assert offset not in self._offset_to_loc_key
            self._offset_to_loc_key[offset] = loc_key
            self._loc_key_to_offset[loc_key] = offset

        if name is not None:
            self._name_to_loc_key[name] = loc_key
            self._loc_key_to_names[loc_key] = set([name])

        return loc_key

    def remove_location(self, loc_key):
        """
        Delete the location corresponding to @loc_key
        @loc_key: LocKey instance
        """
        assert isinstance(loc_key, LocKey)
        if loc_key not in self._loc_keys:
            raise KeyError("Unknown loc_key %r" % loc_key)
        names = self._loc_key_to_names.pop(loc_key, [])
        for name in names:
            del self._name_to_loc_key[name]
        offset = self._loc_key_to_offset.pop(loc_key, None)
        self._offset_to_loc_key.pop(offset, None)
        self._loc_keys.remove(loc_key)

    def pretty_str(self, loc_key):
        """Return a human readable version of @loc_key, according to information
        available in this LocationDB instance"""
        names = self.get_location_names(loc_key)
        new_names = set()
        for name in names:
            try:
                name = name.decode()
            except AttributeError:
                pass
            new_names.add(name)
        names = new_names
        if names:
            return ",".join(names)
        offset = self.get_location_offset(loc_key)
        if offset is not None:
            return "loc_%x" % offset
        return str(loc_key)

    @property
    def loc_keys(self):
        """Return all loc_keys"""
        return self._loc_keys

    @property
    def names(self):
        """Return all known names"""
        return list(self._name_to_loc_key)

    @property
    def offsets(self):
        """Return all known offsets"""
        return list(self._offset_to_loc_key)

    def __str__(self):
        out = []
        for loc_key in self._loc_keys:
            names = self.get_location_names(loc_key)
            offset = self.get_location_offset(loc_key)
            out.append(
                "%s: %s - %s" % (
                    loc_key,
                    "0x%x" % offset if offset is not None else None,
                    ",".join(printable(name) for name in names)
                )
            )
        return "\n".join(out)

    def merge(self, location_db):
        """Merge with another LocationDB @location_db

        WARNING: old reference to @location_db information (such as LocKeys)
        must be retrieved from the updated version of this instance. The
        dedicated "get_*" APIs may be used for this task
        """
        # A simple merge is not doable here, because LocKey will certainly
        # collides

        for foreign_loc_key in location_db.loc_keys:
            foreign_names = location_db.get_location_names(foreign_loc_key)
            foreign_offset = location_db.get_location_offset(foreign_loc_key)
            if foreign_names:
                init_name = list(foreign_names)[0]
            else:
                init_name = None
            loc_key = self.add_location(offset=foreign_offset, name=init_name,
                                        strict=False)
            cur_names = self.get_location_names(loc_key)
            for name in foreign_names:
                if name not in cur_names and name != init_name:
                    self.add_location_name(loc_key, name=name)

    def canonize_to_exprloc(self, expr):
        """
        If expr is ExprInt, return ExprLoc with corresponding loc_key
        Else, return expr

        @expr: Expr instance
        """
        if expr.is_int():
            loc_key = self.get_or_create_offset_location(int(expr))
            ret = ExprLoc(loc_key, expr.size)
            return ret
        return expr

    # Deprecated APIs
    @property
    def items(self):
        """Return all loc_keys"""
        warnings.warn('DEPRECATION WARNING: use "loc_keys" instead of "items"')
        return list(self._loc_keys)

    def __getitem__(self, item):
        warnings.warn('DEPRECATION WARNING: use "get_name_location" or '
                      '"get_offset_location"')
        if item in self._name_to_loc_key:
            return self._name_to_loc_key[item]
        if item in self._offset_to_loc_key:
            return self._offset_to_loc_key[item]
        raise KeyError('unknown symbol %r' % item)

    def __contains__(self, item):
        warnings.warn('DEPRECATION WARNING: use "get_name_location" or '
                      '"get_offset_location", or ".offsets" or ".names"')
        return item in self._name_to_loc_key or item in self._offset_to_loc_key

    def loc_key_to_name(self, loc_key):
        """[DEPRECATED API], see 'get_location_names'"""
        warnings.warn("Deprecated API: use 'get_location_names'")
        return sorted(self.get_location_names(loc_key))[0]

    def loc_key_to_offset(self, loc_key):
        """[DEPRECATED API], see 'get_location_offset'"""
        warnings.warn("Deprecated API: use 'get_location_offset'")
        return self.get_location_offset(loc_key)

    def remove_loc_key(self, loc_key):
        """[DEPRECATED API], see 'remove_location'"""
        warnings.warn("Deprecated API: use 'remove_location'")
        self.remove_location(loc_key)

    def del_loc_key_offset(self, loc_key):
        """[DEPRECATED API], see 'unset_location_offset'"""
        warnings.warn("Deprecated API: use 'unset_location_offset'")
        self.unset_location_offset(loc_key)

    def getby_offset(self, offset):
        """[DEPRECATED API], see 'get_offset_location'"""
        warnings.warn("Deprecated API: use 'get_offset_location'")
        return self.get_offset_location(offset)

    def getby_name(self, name):
        """[DEPRECATED API], see 'get_name_location'"""
        warnings.warn("Deprecated API: use 'get_name_location'")
        return self.get_name_location(name)

    def getby_offset_create(self, offset):
        """[DEPRECATED API], see 'get_or_create_offset_location'"""
        warnings.warn("Deprecated API: use 'get_or_create_offset_location'")
        return self.get_or_create_offset_location(offset)

    def getby_name_create(self, name):
        """[DEPRECATED API], see 'get_or_create_name_location'"""
        warnings.warn("Deprecated API: use 'get_or_create_name_location'")
        return self.get_or_create_name_location(name)

    def rename_location(self, loc_key, newname):
        """[DEPRECATED API], see 'add_name_location' and 'remove_location_name'
        """
        warnings.warn("Deprecated API: use 'add_location_name' and "
                      "'remove_location_name'")
        for name in self.get_location_names(loc_key):
            self.remove_location_name(loc_key, name)
        self.add_location_name(loc_key, name)

    def set_offset(self, loc_key, offset):
        """[DEPRECATED API], see 'set_location_offset'"""
        warnings.warn("Deprecated API: use 'set_location_offset'")
        self.set_location_offset(loc_key, offset, force=True)

    def gen_loc_key(self):
        """[DEPRECATED API], see 'add_location'"""
        warnings.warn("Deprecated API: use 'add_location'")
        return self.add_location()

    def str_loc_key(self, loc_key):
        """[DEPRECATED API], see 'pretty_str'"""
        warnings.warn("Deprecated API: use 'pretty_str'")
        return self.pretty_str(loc_key)
