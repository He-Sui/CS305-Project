import sys
import os
import select
import util.simsocket as simsocket
import struct
import socket
import math
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle
from typing import Dict, Set, Tuple
from time import time

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024
FORMAT = '!HBBHHII'
HEADER_LEN = struct.calcsize(FORMAT)
MAX_PAYLOAD = 1024
TEAM = 15
ALPHA = 0.125
BETA = 0.25

config = None


class Ack_Record:
    def __init__(self):
        self.ack = 0
        self.sending_chunk_hash = ''
        self.sending_time = dict()
        self.ack_packet = set()
        self.cwnd = 1.0
        self.ssthresh = 64
        self.mode = 0
        self.duplicated_ack = 0
        self.estimated_RTT = None
        self.dev_RTT = None
        self.timeout_interval = None
        self.transfer_num: Dict[int, int] = dict()
        self.next_seq_num = 1


class Data_Info:
    def __int__(self):
        self.received_chunk = b''
        self.buffer = dict()
        self.ack = 0
        self.received_pkt = set()
        self.downloading_chunk_hash = ''


ack_records: Dict[tuple, Ack_Record] = dict()
data_info: Dict[tuple, Data_Info] = dict()


def process_download(sock, chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    print('PROCESS DOWNLOAD SKELETON CODE CALLED.  Fill me in!')


def process_inbound_udp(sock):
    # Receive pkt
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack(FORMAT, pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    if type == 0:
        pass
    elif type == 1:
        pass
    elif type == 2:
        pass
    elif type == 3:
        process_data(sock, from_addr, data, Seq)
    elif type == 4:
        process_ack(sock, from_addr, Seq, Ack)
    elif type == 5:
        pass


def process_data(sock: simsocket.SimSocket, addr: tuple, data: bytes, seq: int):
    record = data_info[addr]
    if seq not in record.received_pkt:
        record.buffer[seq] = data
        record.received_pkt.add(seq)
        while record.ack + 1 in record.received_pkt:
            record.ack += 1
            record.received_chunk += record.buffer[record.ack]
            del record.buffer[record.ack]
        if len(record.received_chunk) == CHUNK_DATA_SIZE:
            with open(config.output_file, "wb") as wf:
                pickle.dump(record.received_chunk, wf)
            config.haschunks[record.downloading_chunk_hash] = record.received_chunk
    pkt = struct.pack(FORMAT, 52305, TEAM, 4, HEADER_LEN, HEADER_LEN, seq, record.ack)
    sock.sendto(pkt, addr)


def send_data(sock: simsocket.SimSocket, addr: tuple, seq: int):
    left = (seq - 1) * MAX_PAYLOAD
    right = min(seq * MAX_PAYLOAD, CHUNK_DATA_SIZE)
    if left >= right:
        return
    next_data = config.haschunks[ack_records[addr].sending_chunk_hash][left:right]
    data_header = struct.pack(FORMAT, 52305, TEAM, 3, HEADER_LEN, HEADER_LEN + len(next_data), seq, 0)
    ack_records[addr].sending_time[seq] = time()
    if ack_records[addr].transfer_num.get(seq) is None:
        ack_records[addr].transfer_num[seq] = 0
    ack_records[addr].transfer_num[seq] += 1
    sock.sendto(data_header + next_data, addr)


def timeout_retransmission(sock: simsocket.SimSocket):
    for addr in ack_records:
        record = ack_records[addr]
        for seq in record.sending_time:
            if time() - record.sending_time[seq] > record.timeout_interval:
                send_data(sock, addr, seq)


def process_ack(sock: simsocket.SimSocket, addr: tuple, seq: int, ack: int):
    record = ack_records.get(addr)
    if record.ack * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
        return
    record.ack_packet.add(seq)
    if record.transfer_num[seq] == 1:
        sample_rtt = time() - record.sending_time[seq]
        record.estimated_RTT = (1 - ALPHA) * record.estimated_RTT + ALPHA * sample_rtt
        record.dev_RTT = (1 - BETA) * record.dev_RTT + BETA * abs(sample_rtt - record.estimated_RTT)
        record.timeout_interval = record.estimated_RTT + 4 * record.dev_RTT
    if seq in record.sending_time:
        del record.sending_time[seq]
    if ack > record.ack:
        record.ack = ack
        record.duplicated_ack = 1
        if record.mode == 0:
            record.cwnd += 1
            if record.mode >= record.ssthresh:
                record.mode = 1
        else:
            record.cwnd += 1 / record.cwnd
        for i in range(record.next_seq_num, record.ack + math.floor(record.cwnd) + 2):
            if (i - 1) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                break
            record.next_seq_num += 1
            send_data(sock, addr, i)
    elif ack == record.ack:
        record.duplicated_ack += 1
        if record.duplicated_ack == 3:
            record.ssthresh = max(math.floor(record.cwnd / 2), 2)
            record.cwnd = 1
            if record.mode == 1:
                record.mode = 0
            send_data(sock, addr, record.ack + 1)


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period 
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)
