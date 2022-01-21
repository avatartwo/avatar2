import unittest

import sys
if sys.version_info < (3, 0):
    import Queue as queue
else:
    import queue

import avatar2.protocols.remote_memory

from os import O_CREAT, O_RDONLY, O_WRONLY, O_RDWR
from posix_ipc import MessageQueue



class RemoteMemoryTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass


    def test_remote_memory_request(self):
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
        self.assertEqual(ret, True)
        self.assertNotEqual(mprot1._rx_queue, None)
        self.assertNotEqual(mprot1._tx_queue, None)


        request = avatar2.protocols.remote_memory.RemoteMemoryReq(magic1, magic2,
                                                                  magic3, magic4, 
                                                                  magic5, 1)
        a.send(request)
        msg = q.get()

        self.assertEqual(msg.id, magic1)
        self.assertEqual(msg.pc, magic2)
        self.assertEqual(msg.address, magic3)
        self.assertEqual(msg.value, magic4)
        self.assertEqual(msg.size, magic5)



if __name__ == '__main__':
    unittest.main()
