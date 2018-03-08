import sys
if sys.version_info < (3, 0):
    import Queue as queue
else:
    import queue

import avatar2.protocols.remote_memory

from os import O_CREAT, O_RDONLY, O_WRONLY, O_RDWR
from posix_ipc import MessageQueue

from nose.tools import *


def setup_func():
    pass


def teardown_func():
    pass


@with_setup(setup_func, teardown_func)
def test_remote_memory_request():
    magic1 = 0x4141414141414141
    magic2 = 0x4242424242424242
    magic3 = 0x4343434343434343
    magic4 = 0x4444444444444444
    magic5 = 4

    q = queue.Queue()
    a = MessageQueue('/a', flags=O_CREAT|O_RDWR)
    b = MessageQueue('/b', flags=O_CREAT|O_RDWR)
    mprot1 = avatar2.protocols.remote_memory.RemoteMemoryProtocol('/a','/b', q)

    ret = mprot1.connect()
    assert_equal(ret, True)
    assert_not_equal(mprot1._rx_queue, None)
    assert_not_equal(mprot1._tx_queue, None)


    request = avatar2.protocols.remote_memory.RemoteMemoryReq(magic1, magic2,
                                                              magic3, magic4, 
                                                              magic5, 1)
    a.send(request)
    msg = q.get()

    assert_equal(msg.id, magic1)
    assert_equal(msg.pc, magic2)
    assert_equal(msg.address, magic3)
    assert_equal(msg.value, magic4)
    assert_equal(msg.size, magic5)

