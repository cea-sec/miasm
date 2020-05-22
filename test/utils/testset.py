from __future__ import print_function
from builtins import range
import os
import subprocess
import sys
import time
from multiprocessing import cpu_count, Queue, Process

from .test import Test


class Message(object):

    "Message exchanged in the TestSet message queue"
    pass


class MessageTaskNew(Message):

    "Stand for a new task"

    def __init__(self, task):
        self.task = task


class MessageTaskDone(Message):

    "Stand for a task done"

    def __init__(self, task, error):
        self.task = task
        self.error = error


class MessageClose(Message):

    "Close the channel"
    pass

def worker(todo_queue, message_queue, init_args):
    """Worker launched in parallel
    @todo_queue: task to do
    @message_queue: communication with Host
    @init_args: additional arguments for command line
    """

    # Main loop
    while True:
        # Acquire a task
        test = todo_queue.get()
        if test is None:
            break
        test.start_time = time.time()
        message_queue.put(MessageTaskNew(test))

        # Launch test
        executable = test.executable if test.executable else sys.executable
        testpy = subprocess.Popen(([executable] +
                                   init_args + test.command_line),
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  cwd=test.base_dir)
        outputs = testpy.communicate()

        # Check result
        error = None
        if testpy.returncode != 0:
            error = outputs[1]

        # Report task finish
        message_queue.put(MessageTaskDone(test, error))

class TestSet(object):

    "Manage a set of test"

    worker = staticmethod(worker)

    def __init__(self, base_dir):
        """Initialise a test set
        @base_dir: base directory for tests
        """
        # Parse arguments
        self.base_dir = base_dir

        # Init internals
        self.task_done_cb = lambda tst, err: None  # On task done callback
        self.task_new_cb = lambda tst: None       # On new task callback
        self.todo_queue = Queue()                 # Tasks to do
        self.message_queue = Queue()              # Messages with workers
        self.tests = []                           # Tests to run
        self.tests_done = []                      # Tasks done
        self.cpu_c = cpu_count()                  # CPUs available
        self.errorcode = 0                        # Non-zero if a test failed
        self.additional_args = []                 # Arguments to always add

    def __add__(self, test):
        "Same as TestSet.add"
        self.add(test)
        return self

    def add(self, test):
        "Add a test instance to the current test set"
        if not isinstance(test, Test):
            raise ValueError("%s is not a valid test instance" % (repr(test)))
        self.tests.append(test)

    def set_cpu_numbers(self, cpu_c):
        """Set the number of cpu to use
        @cpu_c: Number of CPU to use (default is maximum)
        """
        self.cpu_c = cpu_c

    def set_callback(self, task_done=None, task_new=None):
        """Set callbacks for task information retrieval
        @task_done: function(Test, Error message)
        @task_new: function(Test)
        """
        if task_done:
            self.task_done_cb = task_done
        if task_new:
            self.task_new_cb = task_new

    def _add_tasks(self):
        "Add tests to do, regarding to dependencies"
        for test in self.tests:
            # Check dependencies
            launchable = True
            for dependency in test.depends:
                if dependency not in self.tests_done:
                    launchable = False
                    break

            if launchable:
                # Add task
                self.tests.remove(test)
                self.todo_queue.put(test)

        if len(self.tests) == 0:
            # Poison pills
            for _ in range(self.cpu_c):
                self.todo_queue.put(None)

        # All tasks done
        if len(self.tests_done) == self.init_tests_number:
            self.message_queue.put(MessageClose())

    def _messages_handler(self):
        "Manage message between Master and Workers"

        # Main loop
        while True:
            message = self.message_queue.get()
            if isinstance(message, MessageClose):
                # Poison pill
                break
            elif isinstance(message, MessageTaskNew):
                # A task begins
                self.task_new_cb(message.task)
            elif isinstance(message, MessageTaskDone):
                # A task has been done
                self.tests_done.append(message.task)
                self._add_tasks()
                self.task_done_cb(message.task, message.error)
                if message.error is not None:
                    self.errorcode = -1
            else:
                raise ValueError("Unknown message type %s" % type(message))

    @staticmethod
    def fast_unify(seq, idfun=None):
        """Order preserving unifying list function
        @seq: list to unify
        @idfun: marker function (default is identity)
        """
        if idfun is None:
            idfun = lambda x: x
        seen = {}
        result = []
        for item in seq:
            marker = idfun(item)

            if marker in seen:
                continue
            seen[marker] = 1
            result.append(item)
        return result

    def _clean(self):
        "Remove produced files"

        # Build the list of products
        products = []
        current_directory = os.getcwd()
        for test in self.tests_done:
            for product in test.products:
                # Get the full product path
                products.append(os.path.join(current_directory, test.base_dir,
                                             product))

        # Unify the list and remove products
        for product in TestSet.fast_unify(products):
            try:
                os.remove(product)
            except OSError:
                print("Cleaning error: Unable to remove %s" % product)

    def add_additional_args(self, args):
        """Add arguments to used on the test command line
        @args: list of str
        """
        self.additional_args += args

    def run(self):
        "Launch tests"

        # Go in the right directory
        self.current_directory = os.getcwd()
        os.chdir(self.base_dir)

        # Launch workers
        processes = []
        for _ in range(self.cpu_c):
            p = Process(target=TestSet.worker, args=(self.todo_queue,
                                                     self.message_queue,
                                                     self.additional_args))

            processes.append(p)
            p.start()

        # Add initial tasks
        self.init_tests_number = len(self.tests)
        # Initial tasks
        self._add_tasks()

        # Handle messages
        self._messages_handler()

        # Close queue and join processes
        self.todo_queue.close()
        self.todo_queue.join_thread()
        self.message_queue.close()
        self.message_queue.join_thread()
        for p in processes:
            p.join()

    def end(self, clean=True):
        """End a testset run
        @clean: (optional) if set, remove tests products
        PRE: run()
        """
        # Clean
        if clean:
            self._clean()

        # Restore directory
        os.chdir(self.current_directory)

    def tests_passed(self):
        "Return a non zero value if at least one test failed"
        return self.errorcode

    def filter_tags(self, include_tags=None, exclude_tags=None):
        """Filter tests by tags
        @include_tags: list of tags' name (whitelist)
        @exclude_tags: list of tags' name (blacklist)
        If @include_tags and @exclude_tags are used together, @exclude_tags will
        act as a blacklist on @include_tags generated tests
        """

        new_testset = []

        include_tags = set(include_tags)
        exclude_tags = set(exclude_tags)
        if include_tags.intersection(exclude_tags):
            raise ValueError("Tags are mutually included and excluded: %s" % include_tags.intersection(exclude_tags))

        for test in self.tests:
            tags = set(test.tags)
            if exclude_tags.intersection(tags):
                # Ignore the current test because it is excluded
                continue
            if not include_tags:
                new_testset.append(test)
            else:
                if include_tags.intersection(tags):
                    new_testset.append(test)

                    # Add tests dependencies
                    dependency = list(test.depends)
                    while dependency:
                        subtest = dependency.pop()
                        if subtest not in new_testset:
                            new_testset.append(subtest)
                        for subdepends in subtest.depends:
                            if subdepends not in new_testset:
                                dependency.append(subdepends)

        self.tests = new_testset
