import queue
import subprocess
import threading
import signal
import time
import json
import re
import os
import pyjq
import copy
from decimal import Decimal
from pprint import pprint, pformat
import logging
import datetime
from pyroute2 import netns



def output_reader(proc, outq, parent):
    for line in iter(proc.stdout.readline, b""):
        outq.put(line.decode("utf-8"))

        # print("{0} {1}".format(parent.name,line.decode('utf-8')))

        parent.line_ready_callback()

class NameSpaceNotFoundError(Exception):
    pass

class IPerfInstance(object):
    def __init__(self):
        self.type = None
        self.report_interval = "1"
        self.protocol = "tcp"
        self.iperf_binary_path = "/usr/bin/iperf"
        self._outq = queue.Queue()
        self._proc = None
        self.server_ip = None
        self.bind_ip = None
        self.name = None
        self._running = False
        self.realtime = True
        self.bandwidth = "1000pps"
        self.port = "5001"
        self.status = "configured"
        self.packet_len = "1470"
        self.dscp = None
        self._result_regex = None
        self._info_regex = None
        self._results = {}
        self.test_duration = 0
        self.client_source_port = None
        self.use_linux_namespace = None
        self._on_data_callbacks = []
        self._on_packetloss_callbacks = []
        self.currently_has_loss = {}
        self._output_reader_thread = None
        self._cleanup_timer_thread = None
        self._raw_log_filepath = None
        self._raw_log_filehandler = None
        self._creation_time = datetime.datetime.now().replace(microsecond=0).isoformat()
        self.ttl=255

        if "pps" in self.bandwidth:
            self.expected_interval_packets = int(
                Decimal(self.report_interval) * Decimal(self.bandwidth[:-3])
            )
        else:
            self.expected_interval_packets = None
        self._log = logging.getLogger("")
        self._current_event_number = 0

    def __del__(self):
        try:
            self._raw_log_filehandler.close()
        except:
            pass

    def set_raw_log_path(self, path):
        self._raw_log_filepath = "{0}{1}{3}_{2}_instance_raw.log".format(
            path, os.path.sep, self.name, self._creation_time
        )
        self._raw_log_filehandler = open(self._raw_log_filepath, "w")

    def line_ready_callback(self):
        info_data = None
        report_data = None
        line = self._outq.get(block=True)
        stream_id = None
        interval_begin = None
        interval_end = None
        last_interval_begin = None
        is_receiver = False
        is_sender = False
        packets_lost = None
        packets_received = None
        packet_loss_event_message = False
        report_message = False
        timestamp = datetime.datetime.now().isoformat()
        if self._raw_log_filehandler:
            self._raw_log_filehandler.write(line)
            self._raw_log_filehandler.flush()
        if not self._info_regex:
            raise RuntimeError("missing regex for parsing output",pformat(self.generate_cli_from_options()))
        
        result = self._info_regex.match(line)  # check if it's an info header
        if result:
            info_data = result.groupdict()
            stream_id = info_data["stream_id"]
            if (
                stream_id not in self._results
            ):  # new stream id detected -> create new result structure
                self._results[stream_id] = {
                    "summary": {},
                    "detail": [],
                    "info": result.groupdict(),
                    "events": [],
                    "timestamp": timestamp,
                }
                self.currently_has_loss[stream_id] = False

        result = self._result_regex.match(line)  # check if it's a report line
        if result:
            report_data = result.groupdict()
            stream_id = report_data["stream_id"]

            interval_begin = Decimal(report_data["interval_begin"])
            interval_end = Decimal(report_data["interval_end"])
            if "packets_lost" in report_data:
                is_receiver = True
                packets_lost = int(report_data["packets_lost"])
                packets_received = int(report_data["packets_received"])
            else:
                is_sender = True

            try:  # check if we have a predecessor result
                last_interval_begin = Decimal(
                    self._results[stream_id]["detail"][-1]["interval_begin"]
                )
            except IndexError:
                last_interval_begin = -1

            if (
                last_interval_begin > interval_begin
            ):  # if it's a summary store it and return
                self._results[stream_id]["summary"] = result.groupdict()
                self._log.debug("got summary result")
                return True  # suppress any message for summary

            if is_receiver:
                report_message = copy.copy(report_data)
                report_message["stream_name"] = self.name

                if packets_received < self.expected_interval_packets:
                    probably_packets_lost = (
                        self.expected_interval_packets - packets_received
                    )
                    # print('probably lost {0}'.format(probably_packets_lost))
                    if (
                        probably_packets_lost > 4
                    ):  # ignore minimal loss because it could also be a timing issue
                        report_message["packets_lost"] = probably_packets_lost
                        report_message[
                            "packets_received"
                        ] = self.expected_interval_packets
                        packets_lost = probably_packets_lost
                        packets_received = self.expected_interval_packets
                        # print('{0} {1}'.format(packets_lost, packets_received))

                if (
                    packets_lost > self.expected_interval_packets + 4
                ):  # handle summary packet loss message
                    # pprint( self._results[stream_id]['events'])
                    try:
                        packets_lost = (
                            packets_lost
                            - self._results[stream_id]["events"][-1][
                                "total_packets_lost_since_event_start"
                            ]
                        )
                        packets_received = self.expected_interval_packets - packets_lost
                        report_message["packets_lost"] = packets_lost
                        report_message["packets_received"] = packets_received
                        # print('{0} {1}'.format(packets_lost,packets_received))

                    except (
                        IndexError
                    ):  # loss without event registred, can only be at interval_begin 0.0 -> ignore
                        # print('----------------------index error------------------------')
                        if interval_begin == 0:
                            report_message["packets_lost"] = 0
                            report_message[
                                "packets_received"
                            ] = self.expected_interval_packets
                        else:
                            self._log.debug(pformat(self._results))
                            self._log.debug(pformat(report_message))
                            self._log.debug(line)
                            raise Exception("Something went wrong")

                packet_loss_event_message = {
                    "event_number": self._current_event_number,
                    "stream_id": str(stream_id),
                    "stream_name": self.name,
                    "status": "",
                    "total_packets_lost_since_event_start": 0,
                    "packets_lost": packets_lost,
                    "packets_received": packets_received,
                    "event_begin": interval_begin,
                    "event_end": None,
                    "timestamp_start": timestamp,
                    "timestamp_current": timestamp,
                    "timestamp_end": None,
                }

                if packets_received == 0:  # handle 100% packet loss situation
                    report_message["packets_lost"] = self.expected_interval_packets
                    packets_lost = self.expected_interval_packets
                    if self.currently_has_loss[stream_id]:
                        self._log.debug(
                            "losing all packets, receiving nothing, should receive {} (cont.)".format(
                                self.bandwidth
                            )
                        )
                        self._results[stream_id]["events"][-1][
                            "total_packets_lost_since_event_start"
                        ] += packets_lost
                        self._results[stream_id]["events"][-1][
                            "timestamp_current"
                        ] = timestamp
                        self._results[stream_id]["events"][-1][
                            "packets_lost"
                        ] = packets_lost
                        self._results[stream_id]["events"][-1][
                            "status"
                        ] = "losing all packets (cont.)"
                        self._results[stream_id]["events"][-1][
                            "packets_received"
                        ] = packets_received
                        packet_loss_event_message = copy.copy(
                            self._results[stream_id]["events"][-1]
                        )

                    else:
                        self._log.debug(
                            "losing all packets, receiving nothing, should receive {}".format(
                                self.bandwidth
                            )
                        )
                        self._current_event_number += 1
                        packet_loss_event_message[
                            "event_number"
                        ] = self._current_event_number
                        packet_loss_event_message[
                            "packets_lost"
                        ] = (
                            self.expected_interval_packets
                        )  # set lost packets to pps because iperf reports 0 lost which breaks graph
                        packet_loss_event_message[
                            "total_packets_lost_since_event_start"
                        ] = packets_lost
                        packet_loss_event_message["status"] = "losing all packets"
                        packet_loss_event_message["packets_received"] = packets_received
                        self._results[stream_id]["events"].append(
                            packet_loss_event_message
                        )
                        self.currently_has_loss[stream_id] = True

                elif packets_lost > 0:  # handle packet loss situation
                    if self.currently_has_loss[
                        stream_id
                    ]:  # handle ongoing packet loss situation
                        self._log.debug("ongoing packet loss detected")
                        self._results[stream_id]["events"][-1][
                            "total_packets_lost_since_event_start"
                        ] += packets_lost
                        self._results[stream_id]["events"][-1][
                            "timestamp_current"
                        ] = timestamp
                        self._results[stream_id]["events"][-1][
                            "status"
                        ] = "losing packets (cont.)"
                        self._results[stream_id]["events"][-1][
                            "packets_lost"
                        ] = packets_lost
                        self._results[stream_id]["events"][-1][
                            "packets_received"
                        ] = packets_received

                        packet_loss_event_message = copy.copy(
                            self._results[stream_id]["events"][-1]
                        )

                    else:  # handle new packet loss situation
                        self._log.debug("begin of packet loss detected")
                        self.currently_has_loss[stream_id] = True
                        self._current_event_number += 1
                        packet_loss_event_message[
                            "event_number"
                        ] = self._current_event_number
                        packet_loss_event_message["status"] = "losing packets"
                        packet_loss_event_message[
                            "total_packets_lost_since_event_start"
                        ] = packets_lost
                        self._results[stream_id]["events"].append(
                            packet_loss_event_message
                        )

                elif self.currently_has_loss[stream_id]:  # handle end of loss situation
                    self._log.debug("end of packet loss detected")
                    self.currently_has_loss[stream_id] = False
                    self._results[stream_id]["events"][-1][
                        "timestamp_current"
                    ] = timestamp
                    self._results[stream_id]["events"][-1]["timestamp_end"] = timestamp
                    self._results[stream_id]["events"][-1][
                        "interval_end"
                    ] = interval_end
                    self._results[stream_id]["events"][-1]["status"] = "stable"
                    self._results[stream_id]["events"][-1][
                        "packets_lost"
                    ] = packets_lost
                    self._results[stream_id]["events"][-1][
                        "packets_received"
                    ] = packets_received

                    packet_loss_event_message = copy.copy(
                        self._results[stream_id]["events"][-1]
                    )

                else:  # do not send loss event in case of no loss
                    packet_loss_event_message = False
        else:
            self._log.debug("cannot parse report line: {0}".format(line))

        if packet_loss_event_message:
            # print(packet_loss_event_message)
            # self._results[stream_id]['events'].append(packet_loss_event_message)
            for callback, args in self._on_packetloss_callbacks:
                callback(packet_loss_event_message, **args)

        if report_message:
            self._results[stream_id]["detail"].append(report_message)
            for callback, args in self._on_data_callbacks:
                callback(report_message, **args)

    def get_result_events(self):
        results_with_packet_loss = pyjq.all('.[] | select(.packets_lost!="0")', data)
        events = []
        event_data = []
        event_begin = None
        event_loss = 0
        for idx, result in enumerate(results_with_packet_loss):
            event_data.append(result)
            event_loss += int(result["packets_lost"])
            if not event_begin:
                event_begin = Decimal(result["interval_begin"])
            try:
                if (
                    result["interval_end"]
                    != results_with_packet_loss[idx + 1]["interval_begin"]
                ):
                    events.append(
                        {
                            "detail": event_data,
                            "summary": {
                                "total_loss": event_loss,
                                "begin": str(event_begin),
                                "end": str(Decimal(result["interval_end"])),
                                "duration": str(
                                    Decimal(result["interval_end"]) - event_begin
                                ),
                                "packet_rate": "{0[packet_rate]} {0[packet_rate_unit]}".format(
                                    result
                                ),
                            },
                        }
                    )
                    event_data = []
                    event_loss = 0
                    event_begin = None

            except IndexError:
                events.append(
                    {
                        "detail": event_data,
                        "summary": {
                            "total_loss": event_loss,
                            "begin": str(event_begin),
                            "end": str(Decimal(result["interval_end"])),
                            "duration": str(
                                Decimal(result["interval_end"]) - event_begin
                            ),
                            "packet_rate": "{0[packet_rate]} {0[packet_rate_unit]}".format(
                                result
                            ),
                        },
                    }
                )
        return events

    def register_on_data_callback(self, cb, **kwargs):
        self._on_data_callbacks.append((cb, kwargs))

    def register_on_packtetloss_callback(self, cb, **kwargs):
        self._on_packetloss_callbacks.append((cb, kwargs))

    @property
    def get_name(self):
        if not self.name:
            raise ValueError("iperf instance needs a name")
        return self.name

    def output_reader(self):
        for line in iter(self._proc.stdout.readline, b""):
            self._outq.put(line.decode("utf-8"))

    def set_options(self, **kwargs):
        for option_name, option_value in kwargs.items():
            if option_name in ["status"]:
                continue
            self.__setattr__(option_name, str(option_value))
        if "pps" in self.bandwidth:
            self.expected_interval_packets = int(
                Decimal(self.report_interval) * Decimal(self.bandwidth[:-3])
            )
        else:
            self.expected_interval_packets = None
        if self.test_duration == None:
            self.test_duration = 0

    def get_options(self):
        retval = {}
        for k, v in self.__dict__.items():
            if not k.startswith("_"):
                retval[k] = v
        return retval

    def generate_cli_from_options(self):
        _cli = []
        if self.use_linux_namespace:
            if self.use_linux_namespace not in list(netns.listnetns()):
                raise NameSpaceNotFoundError(f"Namespace {self.use_linux_namespace} cannot be found.")
            _cli.extend("ip netns exec {0}".format(self.use_linux_namespace).split(" "))
        _cli.append(self.iperf_binary_path)
        _cli.append("-e")
        if self.test_duration:
            _cli.append("-t")
            _cli.append(self.test_duration)
        if self.type == "server":
            _cli.append("-s")
            if self.bind_ip:
                _cli.append("-B")
                _cli.append(self.bind_ip)
            if self.protocol == "udp":
                # multicast server result
                # [  4] 2.6000-2.7000 sec  0.00 Bytes   0.00 bits/sec    0.000 ms    0/    0 (0%)  -/-/-/-                    ms    0 pps
                # [  3] 8.7000-8.8000 sec   144 KBytes  11.8 Mbits/sec   0.002 ms    0/  100 (0%)  0.015/ 0.008/ 0.037/ 0.006 ms 1000 pps  100753.94
                self._result_regex = re.compile(
                    r"^\[\s*(?P<stream_id>\d+)\]\s+(?P<interval_begin>\d+\.\d+)-(?P<interval_end>\d+\.\d+)\s+(?P<interval_unit>\S+)\s+(?P<received>\S+)\s+(?P<received_unit>\S+)\s+(?P<bandwidth>\S+)\s+(?P<bandwidth_unit>\S+)\s+(?P<jitter>\S+)\s+(?P<jitter_unit>\S+)\s+(?P<packets_lost>\S+)/\s*(?P<packets_received>\S+)\s+\(.*\)\s+(?P<latency_avg>\S+)\s*/\s*(?P<latency_min>\S+)\s*/\s*(?P<latency_max>\S+)\s*/\s*(?P<latency_stdev>\S+)\s+(?P<latency_unit>\S+)\s+(?P<packet_rate>\d+)\s+(?P<packet_rate_unit>\S+)\s*(?P<net_pwr>\S+)?"
                )

        elif self.type == "client":
            _cli.append("-c")
            if not self.server_ip:
                raise ValueError("Client needs server_ip to be set")
            _cli.append(self.server_ip)
            if self.bind_ip and self.client_source_port:
                _cli.append("-B")
                _cli.append("{0}:{1}".format(self.bind_ip, self.client_source_port))
            if self.protocol == "udp":
                _cli.append("-l")
                _cli.append(self.packet_len)
                # [  3] local 192.168.51.154 port 54877 connected with 225.0.0.5 port 5001
                self._result_regex = re.compile(
                    r"^\[\s*(?P<stream_id>\d+)\]\s+(?P<interval_begin>\d+\.\d+)-(?P<interval_end>\d+\.\d+)\s+(?P<interval_unit>\S+)\s+(?P<transferred>\S+)\s+(?P<transferred_unit>\S+)\s+(?P<bandwidth>\S+)\s+(?P<bandwidth_unit>\S+)\s+(?P<packets_written>\S+)/(?P<packets_error>\S+)\s+(?P<packet_rate>\d+)\s+(?P<packet_rate_unit>\S+)"
                )
            if self.ttl:
                _cli.append("-T")
                _cli.append(str(self.ttl))

        else:
            raise ValueError("type must be set to either server or client")
        if self.protocol == "udp":
            _cli.append("-u")
            self._info_regex = re.compile(
                r"^\[\s*(?P<stream_id>\d+)\]\s+local\s+(?P<local_ip>\S+)\s+port\s+(?P<local_port>\S+)\s+connected\s+with\s+(?P<remote_ip>\S+)\s+port\s+(?P<remote_port>\S+)"
            )
            #
        if self.realtime:
            _cli.append("-z")

        _cli.append("-i")
        _cli.append(self.report_interval)

        _cli.append("-b")
        _cli.append(self.bandwidth)

        _cli.append("-p")
        _cli.append(self.port)

        if self.dscp:
            accepted_tos_values = [
                "af11",
                "af12",
                "af13",
                "af21",
                "af22",
                "af23",
                "af31",
                "af32",
                "af33",
                "af41",
                "af42",
                "af43",
                "cs0",
                "cs1",
                "cs2",
                "cs3",
                "cs4",
                "cs5",
                "cs6",
                "cs7",
                "ef",
                "le",
                "nqb",
                "nqb2",
                "ac_be",
                "ac_bk",
                "ac_vi",
                "ac_vo",
                "lowdelay",
                "throughput",
            ]
            self.dscp = self.dscp.lower()
            if str(self.dscp) in accepted_tos_values or (
                int(self.dscp) > 0 and int(self.dscp) <= 255
            ):
                _cli.append("-S")
                _cli.append(self.dscp)
            else:
                raise ValueError(f'"{self.dscp}" is not a valid DSCP Value')

            _cli.append("-S")
            _cli.append(self.dscp)

        return _cli

    def start(self, create_thread_function=threading.Thread):
        self._results = {}
        if self._cleanup_timer_thread:
            self._cleanup_timer_thread.join()
            del self._cleanup_timer_thread
            self._cleanup_timer_thread = None
        # print(' '.join(self.generate_cli_from_options()))
        # pprint(self.generate_cli_from_options())
        self._proc = subprocess.Popen(
            self.generate_cli_from_options(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        if not self._output_reader_thread:
            self._output_reader_thread = create_thread_function(
                target=output_reader, args=(self._proc, self._outq, self)
            )

        self._output_reader_thread.start()
        self._running = True
        self.status = "running"
        time.sleep(0.2)

        self._cleanup_timer_thread = threading.Timer(
            int(self.test_duration) + 10, self.stop
        )
        self._cleanup_timer_thread.start()

        if self._proc.poll() is not None:
            self.stop()
            return False

        return True

    def stop(self):
        if self._running:
            self._proc.terminate()
            self._proc.wait()
            del self._proc
            self._proc = None
            self._output_reader_thread.join()
            del self._output_reader_thread
            self._output_reader_thread = None
            self._running = False
            self.status = "stopped"
            if self._raw_log_filehandler:
                self._raw_log_filehandler.close()
        return True

    def get_results(self):
        return self._results


class Server(IPerfInstance):
    def __init__(self):
        super(Server, self).__init__()
        self.type = "server"


class Client(IPerfInstance):
    def __init__(self, server_ip=None):
        super(Client, self).__init__()
        self.type = "client"
