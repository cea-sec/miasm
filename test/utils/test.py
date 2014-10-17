class Test(object):
    "Stand for a test to run"

    def __init__(self, command_line, base_dir="", depends=None,
                 products=None):
        """Create a Test instance.
        @command_line: list of string standing for arguments to launch
        @base_dir: base directory for launch
        @depends: list of Test instance indicating dependencies
        @products: elements produced to remove after tests
        """
        self.command_line = command_line
        self.base_dir = base_dir
        self.depends = depends if depends else []
        self.products = products if products else []

    def __repr__(self):
        displayed = ["command_line", "base_dir", "depends", "products"]
        return "<Test " + \
            " ".join("%s=%s" % (n, getattr(self,n)) for n in displayed ) + ">"

    def __eq__(self, test):
        if not isinstance(test, Test):
            return False

        return all([self.command_line == test.command_line,
                    self.base_dir == test.base_dir,
                    self.depends == test.depends,
                    self.products == test.products])
