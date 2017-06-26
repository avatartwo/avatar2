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
For doing so, we are providing build-scripts for Ubuntu 16.04 - while other
distributions are not officially supported (yet), the scripts are known to
work with slight modifications on other distributions as well.
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

For further support or follow-up questions, feel free to contact us via IRC
in #avatar2 on freenode, or to send a mail to avatar2 [at] lists.eurecom.fr, 
our public mailing list.

Additionally, you can subscribe to the list 
[here](https://lists.eurecom.fr/sympa/subscribe/avatar2).
