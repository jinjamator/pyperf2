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
    * configurable loss detection: trust iperf's built-in counter or use an
      expected-minus-received heuristic for compatibility with older iperf2 builds
    * configurable loss threshold to suppress timing jitter noise
    * warmup / ramp-up period: suppress loss detection for the first N intervals
      so streams can stabilise before measurement begins


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


Loss Detection
--------------

Background
^^^^^^^^^^

iperf2 reports per-interval packet loss in the UDP receiver output. Older
builds (< 2.0.13) sometimes reported ``packets_lost = 0`` even when loss
occurred; the reliable figure was only available in the final summary line.
Pyperf2 originally worked around this with an *expected-minus-received
heuristic*: if fewer packets arrived than expected (based on the configured
``bandwidth`` in ``pps``), the shortfall was counted as loss.

Modern iperf2 (≥ 2.0.13) reports per-interval loss correctly. The heuristic
is no longer needed and can produce false positives — for example when many
streams start simultaneously, the first interval may receive slightly more
packets than steady state (connection establishment timing), inflating the
baseline so every subsequent full interval looks like it lost packets.

Three options let you tune loss detection to match your iperf2 version and
deployment:

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Option
     - Default
     - Purpose
   * - ``use_iperf_loss_counter``
     - ``None``
     - Selects the loss source: iperf counter, heuristic, or auto
   * - ``loss_threshold``
     - ``0``
     - Minimum lost packets per interval to register a loss event
   * - ``warmup_intervals``
     - ``0``
     - Leading intervals to skip before loss detection starts

use_iperf_loss_counter
^^^^^^^^^^^^^^^^^^^^^^

``None`` — *auto* (default): trust iperf's ``packets_lost`` field directly,
**unless** ``bandwidth`` is given in ``pps`` format, in which case the
heuristic is used. This preserves backwards compatibility with older iperf2
builds.

``True`` — always trust iperf's ``packets_lost`` counter. Recommended for
iperf2 ≥ 2.0.13. Eliminates false positives entirely — if iperf says 0 lost,
pyperf2 accepts that without second-guessing it.

``False`` — always use the expected-minus-received heuristic, regardless of
what iperf reports. For very old iperf2 builds where the per-interval counter
is known to be unreliable.

loss_threshold
^^^^^^^^^^^^^^

Minimum number of inferred lost packets per interval required to register a
loss event. Only meaningful when the heuristic is active (``use_iperf_loss_counter``
is ``False``, or ``None`` with a ``pps`` bandwidth). A value of ``4``
suppresses spurious events caused by interval timing jitter where a full
window delivers 1–4 fewer packets than the configured rate without any real
loss occurring.

warmup_intervals
^^^^^^^^^^^^^^^^

Number of leading report intervals to skip before loss detection starts.
During the warmup period:

* the packetloss callback is **not** called
* no loss events are recorded
* the data callback **is** still called so callers can observe the ramp-up
* the ``expected_interval_packets`` baseline is updated from observed traffic,
  so it reflects the true steady-state rate by the time warmup ends

The warmup duration in wall-clock seconds is
``warmup_intervals × report_interval``.

Recommended settings
^^^^^^^^^^^^^^^^^^^^

+------------------------------+------------------------------------+---------------------+
| Scenario                     | Recommended settings               | Why                 |
+==============================+====================================+=====================+
| Modern iperf2 (≥ 2.0.13),    | ``use_iperf_loss_counter=True``    | Fully accurate;     |
| single stream                | ``warmup_intervals=0``             | no ramp-up needed   |
+------------------------------+------------------------------------+---------------------+
| Modern iperf2, many streams  | ``use_iperf_loss_counter=True``    | Skip inflated first |
| started simultaneously       | ``warmup_intervals=1``             | interval            |
+------------------------------+------------------------------------+---------------------+
| Old iperf2 (< 2.0.13)        | ``use_iperf_loss_counter=False``   | Heuristic needed;   |
|                              | ``loss_threshold=4``               | filter jitter noise |
+------------------------------+------------------------------------+---------------------+
| Unknown iperf2 version       | leave all at defaults              | Auto mode is safe   |
+------------------------------+------------------------------------+---------------------+

.. code-block:: python

    from pyperf2 import Server, Client
    from time import sleep

    # Modern iperf2, 12 streams started in parallel — skip first interval,
    # trust iperf's loss counter directly.
    receiver = Server()
    receiver.set_options(
        protocol="udp",
        port="5201",
        test_duration=60,
        bandwidth="1000pps",
        use_iperf_loss_counter=True,
        warmup_intervals=1,
        loss_threshold=0,
    )
    receiver.start()

    # Old iperf2 compat — heuristic with noise floor.
    receiver_compat = Server()
    receiver_compat.set_options(
        protocol="udp",
        port="5202",
        test_duration=60,
        bandwidth="1000pps",
        use_iperf_loss_counter=False,
        loss_threshold=4,
        warmup_intervals=0,
    )
    receiver_compat.start()

    sender = Client()
    sender.set_options(protocol="udp", server_ip="127.0.0.1", port="5201",
                       bandwidth="1000pps", test_duration=55)
    sender.start()
    while sender.status != "stopped":
        sleep(1)

See ``examples/loss_detection_modes.py`` for a complete side-by-side
demonstration of all four modes.


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
