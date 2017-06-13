Welcome to avatar², the target orchestration framework with focus on dynamic
 analysis of embedded devices' firmware!

Avatar² is developed and maintained by [Eurecom's S3 Group](http://s3.eurecom.fr/).

# Building

Building avatar² is easy!
The following three commands are enough to install the core.
```
$ git clone https://github.com/avatartwo/avatar2.git
$ cd avatar2
$ sudo pip install .
```
Afterwards, the different target endpoints can be built, such as QEmu or PANDA.
```
$ cd targets
$ ./build_*.sh
```

# Getting started
For discovering the power of avatar² and getting a feeling of its usage,
we recommend checking out the 
[handbook](https://github.com/avatartwo/avatar2/tree/master/handbook) here on
github.
Additionally, a documentation of the API is provided 
[here](https://avatartwo.github.io/avatar2-docs/).
