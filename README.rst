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


Configure loss detection mode and threshold
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Two options control how packet loss is detected from iperf2 output:

**use_iperf_loss_counter** (``None`` / ``True`` / ``False``, default ``None``)
  Selects the loss detection source.

  ``None`` — *auto* (default): trust iperf's ``packets_lost`` field directly,
  **unless** ``bandwidth`` is given in ``pps`` format, in which case the
  expected-minus-received heuristic is used. This provides backwards
  compatibility with older iperf2 builds (< 2.0.13) that did not report
  per-interval loss reliably.

  ``True`` — always trust iperf's ``packets_lost`` counter. Recommended for
  iperf2 ≥ 2.0.13. Eliminates false positives caused by startup burst
  inflation when many streams are started simultaneously.

  ``False`` — always use the heuristic regardless of iperf output. Intended
  for very old iperf2 builds where the per-interval counter is known to be
  zero even when loss occurs.

**loss_threshold** (integer ≥ 0, default ``0``)
  Minimum number of inferred lost packets per interval required to register a
  loss event. Only meaningful when the heuristic is active (i.e.
  ``use_iperf_loss_counter`` is ``False`` or auto with a ``pps`` bandwidth).
  A value of ``4`` suppresses spurious events caused by interval timing jitter
  where a full window delivers 1–4 fewer packets than the configured rate
  without any real loss occurring.

.. code-block:: python

    from pyperf2 import Server, Client
    from time import sleep

    # Modern iperf2 (>= 2.0.13): trust iperf's loss counter directly.
    receiver = Server()
    receiver.set_options(
        protocol="udp",
        port="5201",
        test_duration=15,
        bandwidth="1000pps",
        use_iperf_loss_counter=True,
        loss_threshold=0,
    )
    receiver.start()

    # Old iperf2: use heuristic with a noise floor of 4 packets.
    receiver_compat = Server()
    receiver_compat.set_options(
        protocol="udp",
        port="5202",
        test_duration=15,
        bandwidth="1000pps",
        use_iperf_loss_counter=False,
        loss_threshold=4,
    )
    receiver_compat.start()

    sender = Client()
    sender.set_options(protocol="udp", server_ip="127.0.0.1", port="5201",
                       bandwidth="1000pps", test_duration=12)
    sender.start()
    while sender.status != "stopped":
        sleep(1)

See ``examples/loss_detection_modes.py`` for a complete side-by-side
demonstration of all three modes.


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