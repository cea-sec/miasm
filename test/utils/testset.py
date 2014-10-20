import os
import subprocess
from multiprocessing import cpu_count, Queue, Process
from test import Test


class Message(object):
    "Message exchanged in the TestSet message queue"
    pass


class MessageTaskNew(object):
    "Stand for a new task"
    def __init__(self, task):
        self.task = task


class MessageTaskDone(object):
    "Stand for a task done"
    def __init__(self, task, error):
        self.task = task
        self.error = error


class MessageClose(object):
    "Close the channel"
    pass


class TestSet(object):
    "Manage a set of test"

    def __init__(self, base_dir):
        """Initalise a test set
        @base_dir: base directory for tests
        """
        # Parse arguments
        self.base_dir = base_dir

        # Init internals
        self.task_done_cb = lambda tst, err: None # On task done callback
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

    def add_tasks(self):
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
            for _ in xrange(self.cpu_c):
                self.todo_queue.put(None)

        # All tasks done
        if len(self.tests_done) == self.init_tests_number:
            self.message_queue.put(MessageClose())

    def messages_handler(self):
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
                self.add_tasks()
                self.task_done_cb(message.task, message.error)
                if message.error is not None:
                    self.errorcode = -1
            else:
                raise ValueError("Unknown message type %s" % type(message))

    @staticmethod
    def worker(todo_queue, message_queue, init_args):
        """Worker launched in parrallel
        @todo_queue: task to do
        @message_queue: communication with Host
        @init_args: additionnal arguments for command line
        """

        # Main loop
        while True:
            # Acquire a task
            test = todo_queue.get()
            if test is None:
                break
            message_queue.put(MessageTaskNew(test))

            # Go to the expected directory
            current_directory = os.getcwd()
            os.chdir(test.base_dir)

            # Launch test
            testpy = subprocess.Popen(["python"] + init_args + test.command_line,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            outputs = testpy.communicate()

            # Check result
            error = None
            if testpy.returncode != 0:
                error = outputs[1]

            # Restore directory
            os.chdir(current_directory)

            # Report task finish
            message_queue.put(MessageTaskDone(test, error))

    def clean(self):
        "Remove produced files"

        for test in self.tests_done:
            # Go to the expected directory
            current_directory = os.getcwd()
            os.chdir(test.base_dir)

            # Remove files
            for product in test.products:
                try:
                    os.remove(product)
                except OSError:
                    print "Cleanning error: Unable to remove %s" % product

            # Restore directory
            os.chdir(current_directory)

    def add_additionnal_args(self, args):
        """Add arguments to used on the test command line
        @args: list of str
        """
        self.add_additionnal_args += args

    def run(self):
        "Launch tests"

        # Go in the right directory
        current_directory = os.getcwd()
        os.chdir(self.base_dir)

        # Launch workers
        processes = []
        for _ in xrange(self.cpu_c):
            p = Process(target=TestSet.worker, args=(self.todo_queue,
                                                     self.message_queue,
                                                     self.additional_args))

            processes.append(p)
            p.start()

        # Add initial tasks
        self.init_tests_number = len(self.tests)
        # Initial tasks
        self.add_tasks()

        # Handle messages
        self.messages_handler()

        # Close queue and join processes
        self.todo_queue.close()
        self.todo_queue.join_thread()
        self.message_queue.close()
        self.message_queue.join_thread()
        for p in processes:
            p.join()

        # Clean
        self.clean()

        # Restore directory
        os.chdir(current_directory)

    def tests_passed(self):
        "Return a non zero value if at least one test failed"
        return self.errorcode
