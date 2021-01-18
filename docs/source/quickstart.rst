Introduction
==================

Pyperf2 is an abstraction layer to simplify programatic use of the iperf2 binary for linux. It was written to have a simple interface for network test setups. It is mostly used for unicast/multicast network convergence tests so the defaults are tcp 1000pps per instance to have packetloss == 1ms/second. Nevertheless all options are configurable.

Why iperf2 and not iperf3
-------------------------

The reason is simple, iperf3 does not support multicast streams as of now. I need multicast testing capability, so I chose iperf2.

Features
-----------------

Pyperf2 has following features:
    * create and manage iperf2 server instances
    * create and manage iperf2 client instances
    * get results of client and server instances by parsing output to python datastructures.
    * register callbacks for packetloss and intermediate results.
    * linux namespace support (requires ip command of iproute2 package)


Installation
------------

Install pyperf2 by running:

.. code-block:: bash

    pip3 install pyperf2


Examples
---------

Create a unicast udp 1000pps setup and test for 10 seconds
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    from pyperf2 import Server, Client
    from time import sleep
    from pprint import pformat


    def on_data_callback(message, **kwargs):
        print(f"got message {pformat(message)} \n\n kwargs are {pformat(kwargs)}")
        print("----------------------------------------------------------------------")


    receiver = Server()
    sender = Client()

    receiver.set_options(protocol="udp", server_ip="127.0.0.1", test_duration=12)
    receiver.register_on_data_callback(
        on_data_callback, some_custom_parameter="some_custom_value"
    )
    receiver.start()


    sender.set_options(protocol="udp", server_ip="127.0.0.1", test_duration=10)
    sender.start()

    while sender.status != "stopped":
        print(f"status sender: {sender.status}\nstatus receiver: {receiver.status}\n")
        print("do something usefull in the main thread -> sleeping for 1 second\n")
        sleep(1)


Supported Parameters
---------------------

To see all supported parameters for the set_options function, review the constructor of the IPerfInstance object.


Contribute
----------

- Issue Tracker: https://github.com/jinjamator/pyperf2/issues
- Source Code: https://github.com/jinjamator/pyperf2

Roadmap
-----------------

Selected Roadmap items:
    * add class documentation

For documentation please refer to https://pyperf2.readthedocs.io/en/latest/

License
-----------------

This project is licensed under the Apache License Version 2.0