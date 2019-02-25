"""rpyc IDA server"""
from __future__ import print_function

from rpyc.utils.server import OneShotServer
from rpyc.core import SlaveService



def serve_threaded(hostname="localhost", port=4455):
    """This will run a rpyc server in IDA, so a custom script client will be
    able to access IDA api.
    WARNING: IDA will be locked until the client script terminates.
    """

    print('Running server')
    server = OneShotServer(SlaveService, hostname=hostname,
                           port=port, reuse_addr=True, ipv6=False,
                           authenticator=None,
                           auto_register=False)
    server.logger.quiet = False

    return server.start()


if __name__ == "__main__":
    serve_threaded()
