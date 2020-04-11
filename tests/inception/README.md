# Inception

Inception is a framework to perform security testing of real world firmware programs [1][1] [2][2].
It features several components, but here we are interested into its low latency hardware debugger [3][3].

The inception target and protocol allow Avatar2 to interact with the inception debugger and speed up read/write operations between the host and the device.
To install the debugger, please refer to: https://github.com/Inception-framework/debugger

In the same folder is present a script `test_inception_hardware_perf.py` that test read/write operations using the nucleo L152RE example [4][4].
Following is the output with the nucleo board:
```
# python3 test-inception.py
Targets initialized
Targets stopped, start tests for n = 100
[*] Raw read / writes tests
 -  Read the full memory
   -> On average raw read of 81920 bytes takes 1.99 sec, speed: 40.21 KB/sec
 -  Write the full memory
   -> On average raw write of 81920 bytes takes 1.11 sec, speed: 72.02 KB/sec
 -  Read and write the full memory
   -> On average raw read&write of 81920 bytes takes 3.10 sec, speed: 25.79 KB/sec
 -  Random read / writes of random size in the ram
[*] Transfer state to dummy target
 -  Transfer state
   -> On average transfer state from nucleo to dum of 81920 bytes takes 2.00 sec, speed: 40.06 KB/sec
[*] Test completed
```

# References
[1]: https://inception-framework.github.io/inception/
[2]: https://github.com/Inception-framework
[3]: https://inception-framework.github.io/inception/debugger.html
[4]: https://github.com/avatartwo/avatar2-examples/tree/master/nucleo_l152re
