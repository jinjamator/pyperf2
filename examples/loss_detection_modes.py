"""
Demonstrates the two loss detection extensions:

  loss_threshold          -- minimum number of lost packets per interval to
                             count as a real loss event (default: 0)

  use_iperf_loss_counter  -- controls which loss source is authoritative:
                               None  (default) auto: trust iperf directly
                                     unless bandwidth is given in pps, in
                                     which case the heuristic is used for
                                     compatibility with older iperf2 builds
                                     that did not report per-interval loss
                                     reliably.
                               True  always trust iperf's packets_lost field
                               False always use the expected-minus-received
                                     heuristic (old iperf compat)

Three receiver instances are started to illustrate each mode.
"""

from pyperf2 import Server, Client
from time import sleep
from pprint import pformat


def on_loss_callback(message, **kwargs):
    label = kwargs.get("label", "")
    print(f"[{label}] LOSS EVENT: {pformat(message)}")
    print("----------------------------------------------------------------------")


def on_data_callback(message, **kwargs):
    label = kwargs.get("label", "")
    lost = message.get("packets_lost", "0")
    received = message.get("packets_received", "?")
    print(f"[{label}] interval {message['interval_begin']}-{message['interval_end']}s  lost={lost}  received={received}")


# ── Mode 1: auto (default) ────────────────────────────────────────────────────
# bandwidth is in pps → heuristic is active for old iperf2 compat.
# loss_threshold=0 means every inferred missing packet triggers a loss event.
receiver_auto = Server()
receiver_auto.set_options(
    protocol="udp",
    port="5201",
    test_duration=15,
    bandwidth="1000pps",
    # use_iperf_loss_counter not set → None (auto)
    loss_threshold=0,
)
receiver_auto.register_on_data_callback(on_data_callback, label="auto")
receiver_auto.register_on_packtetloss_callback(on_loss_callback, label="auto")
receiver_auto.start()

# ── Mode 2: always trust iperf's loss counter ─────────────────────────────────
# Recommended for iperf2 >= 2.0.13 which reports per-interval loss reliably.
# The heuristic is completely bypassed regardless of bandwidth format.
receiver_iperf = Server()
receiver_iperf.set_options(
    protocol="udp",
    port="5202",
    test_duration=15,
    bandwidth="1000pps",
    use_iperf_loss_counter=True,
    loss_threshold=0,
)
receiver_iperf.register_on_data_callback(on_data_callback, label="iperf-counter")
receiver_iperf.register_on_packtetloss_callback(on_loss_callback, label="iperf-counter")
receiver_iperf.start()

# ── Mode 3: always use heuristic, with a noise floor ─────────────────────────
# Useful when iperf2 is known to underreport loss (very old builds).
# loss_threshold=4 suppresses spurious events caused by interval timing jitter
# (e.g. a full 10 s window occasionally delivering 1-4 fewer packets than the
# configured rate without any real loss occurring).
receiver_heuristic = Server()
receiver_heuristic.set_options(
    protocol="udp",
    port="5203",
    test_duration=15,
    bandwidth="1000pps",
    use_iperf_loss_counter=False,
    loss_threshold=4,
)
receiver_heuristic.register_on_data_callback(on_data_callback, label="heuristic(threshold=4)")
receiver_heuristic.register_on_packtetloss_callback(on_loss_callback, label="heuristic(threshold=4)")
receiver_heuristic.start()

# ── Senders ───────────────────────────────────────────────────────────────────
senders = []
for port in ("5201", "5202", "5203"):
    s = Client()
    s.set_options(protocol="udp", server_ip="127.0.0.1", port=port,
                  bandwidth="1000pps", test_duration=12)
    s.start()
    senders.append(s)

while any(s.status != "stopped" for s in senders):
    sleep(1)

for r in (receiver_auto, receiver_iperf, receiver_heuristic):
    r.stop()
