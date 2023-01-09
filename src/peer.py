import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
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
from collections import deque

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024
FORMAT = '!HBBHHII'
HEADER_LEN = struct.calcsize(FORMAT)
MAX_PAYLOAD = 1024
MAGIC = 52305
TEAM = 15
ALPHA = 0.125
BETA = 0.25

config = None
downloading = False


class RTT_Info:
    def __init__(self):
        self.estimated_rtt = None
        self.dev_rtt = None
        self.timeout_interval = None

    def update_info(self, sample_rtt):
        if self.estimated_rtt is None:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = 0
            if config.timeout is None:
                self.timeout_interval = 2 * self.estimated_rtt
        else:
            self.estimated_rtt = (1 - ALPHA) * self.estimated_rtt + ALPHA * sample_rtt
            self.dev_rtt = (1 - BETA) * self.dev_rtt + BETA * abs(sample_rtt - self.estimated_rtt)
            if config.timeout is None:
                self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt


class Ack_Record:
    def __init__(self):
        self.ack = 0
        self.sending_chunk_hash = ''
        self.sending_time = dict()
        self.max_seq = 0
        self.ack_packet = set()
        self.cwnd = 1.0
        self.ssthresh = 64
        self.mode = 0
        self.duplicated_ack = 0
        self.transfer_num: Dict[int, int] = dict()
        self.next_seq_num = 1


class Data_Info:
    def __init__(self):
        self.received_chunk = b''
        self.buffer: Dict[int, bytes] = dict()
        self.ack = 0
        self.received_pkt = set()
        self.downloading_chunk_hash = ''
        self.last_receive_time = None


ack_records: Dict[tuple, Ack_Record] = dict()
data_info: Dict[tuple, Data_Info] = dict()
hash_peer_list: Dict[str, deque] = dict()
rtt_info: Dict[tuple, RTT_Info] = dict()
received_hash = dict()
unfetch_hash = set()
target_hash = set()


def process_download(sock, chunkfile, outputfile):
    global downloading
    downloading = True
    config.output_file = outputfile
    with open(chunkfile, 'r') as cf:
        while True:
            line = cf.readline().strip()
            if not line:
                break
            _, hash_str = line.split(" ")
            target_hash.add(hash_str)
            unfetch_hash.add(hash_str)
    peer_list = config.peers
    for hash_str in unfetch_hash:
        whohas_header = struct.pack(FORMAT, MAGIC, TEAM, 0, HEADER_LEN, HEADER_LEN + len(hash_str), 0, 0)
        whohas_pkt = whohas_header + hash_str.encode()
        for p in peer_list:
            if int(p[0]) != config.identity:
                sock.sendto(whohas_pkt, (p[1], int(p[2])))


def process_inbound_udp(sock):
    # Receive pkt
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    magic, team, type_code, hlen, plen, seq, ack = struct.unpack(FORMAT, pkt[:HEADER_LEN])
    if magic != MAGIC:
        return
    data = pkt[HEADER_LEN:]
    if type_code == 0:
        chunk_hash = data.decode()
        if chunk_hash in config.haschunks:
            ihave_header = struct.pack(FORMAT, MAGIC, TEAM, 1, HEADER_LEN, HEADER_LEN + len(chunk_hash), 0, 0)
            ihave_pkt = ihave_header + chunk_hash.encode()
            sock.sendto(ihave_pkt, from_addr)
    elif type_code == 1:
        chunk_hash = data.decode()
        if chunk_hash not in hash_peer_list:
            hash_peer_list[chunk_hash] = deque()
        hash_peer_list[chunk_hash].append(from_addr)
    elif type_code == 2:
        sending_chunk_hash = data.decode()
        if len(ack_records) >= config.max_conn:
            denied_header = struct.pack(FORMAT, MAGIC, TEAM, 5, HEADER_LEN, HEADER_LEN + len(sending_chunk_hash), 0, 0)
            sock.sendto(denied_header + sending_chunk_hash.encode(), from_addr)
            return
        record = Ack_Record()
        record.sending_chunk_hash = sending_chunk_hash
        record.next_seq_num = 2
        ack_records[from_addr] = record
        send_data(sock, from_addr, 1)
    elif type_code == 3:
        process_data(sock, from_addr, data, seq)
    elif type_code == 4:
        process_ack(sock, from_addr, seq, ack)
    elif type_code == 5:
        chunk_hash = data.decode()
        if chunk_hash in hash_peer_list:
            hash_peer_list[chunk_hash].append(hash_peer_list[chunk_hash].popleft())
            unfetch_hash.add(chunk_hash)
            if from_addr in data_info:
                del data_info[from_addr]


def process_data(sock: simsocket.SimSocket, addr: tuple, data: bytes, seq: int):
    record = data_info.get(addr)
    if record is None:
        return
    record.last_receive_time = time()
    if seq not in record.received_pkt:
        record.buffer[seq] = data
        record.received_pkt.add(seq)
        while record.ack + 1 in record.received_pkt:
            record.ack += 1
            record.received_chunk += record.buffer[record.ack]
            del record.buffer[record.ack]
        if len(record.received_chunk) == CHUNK_DATA_SIZE:
            config.haschunks[record.downloading_chunk_hash] = record.received_chunk
            received_hash[record.downloading_chunk_hash] = record.received_chunk
            del data_info[addr]
    pkt = struct.pack(FORMAT, MAGIC, TEAM, 4, HEADER_LEN, HEADER_LEN, seq, record.ack)
    sock.sendto(pkt, addr)


def send_get(sock: simsocket.SimSocket):
    for chunk_hash in list(unfetch_hash):
        if hash_peer_list.get(chunk_hash) is not None and len(hash_peer_list[chunk_hash]) > 0:
            addr = hash_peer_list[chunk_hash][0]
            if addr in data_info:
                hash_peer_list[chunk_hash].append(hash_peer_list[chunk_hash].popleft())
                continue
            get_header = struct.pack(FORMAT, MAGIC, TEAM, 2, HEADER_LEN, HEADER_LEN + len(chunk_hash), 0, 0)
            sock.sendto(get_header + chunk_hash.encode(), addr)
            data_info[addr] = Data_Info()
            data_info[addr].last_receive_time = time()
            data_info[addr].downloading_chunk_hash = chunk_hash
            unfetch_hash.remove(chunk_hash)


def send_data(sock: simsocket.SimSocket, addr: tuple, seq: int):
    left = (seq - 1) * MAX_PAYLOAD
    right = min(seq * MAX_PAYLOAD, CHUNK_DATA_SIZE)
    if left >= right:
        return
    next_data = config.haschunks[ack_records[addr].sending_chunk_hash][left:right]
    data_header = struct.pack(FORMAT, MAGIC, TEAM, 3, HEADER_LEN, HEADER_LEN + len(next_data), seq, 0)
    ack_records[addr].sending_time[seq] = time()
    if ack_records[addr].transfer_num.get(seq) is None:
        ack_records[addr].transfer_num[seq] = 0
    ack_records[addr].transfer_num[seq] += 1
    ack_records[addr].max_seq = max(ack_records[addr].max_seq, seq)
    sock.sendto(data_header + next_data, addr)


def timeout_retransmission(sock: simsocket.SimSocket):
    for addr in ack_records:
        record = ack_records[addr]
        timeout_interval = rtt_info[addr].timeout_interval if rtt_info[addr].timeout_interval is not None else 10
        for seq in list(record.sending_time.keys()):
            if seq <= record.ack:
                del record.sending_time[seq]
            elif time() - record.sending_time[seq] > timeout_interval:
                record.ssthresh = max(math.floor(record.cwnd / 2), 2)
                record.cwnd = 1
                record.mode = 0
                send_data(sock, addr, seq)


def process_ack(sock: simsocket.SimSocket, addr: tuple, seq: int, ack: int):
    record = ack_records.get(addr)
    if record is None:
        return
    if seq > record.max_seq:
        return
    if record.ack * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
        ack_records.pop(addr)
        return
    record.ack_packet.add(seq)
    if record.transfer_num[seq] == 1:
        sample_rtt = time() - record.sending_time[seq]
        rtt_info[addr].update_info(sample_rtt)
    if seq in record.sending_time:
        del record.sending_time[seq]
    if ack > record.ack:
        record.ack = ack
        record.duplicated_ack = 0
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
            record.mode = 0
            send_data(sock, addr, record.ack + 1)


def handle_crash():
    for addr in list(ack_records.keys()):
        record = ack_records[addr]
        flag = True
        for seq in record.transfer_num.keys():
            if seq > record.ack + math.floor(record.cwnd):
                continue
            if record.transfer_num[seq] < 3:
                flag = False
                break
        if len(record.transfer_num) > 0 and flag:
            del ack_records[addr]
    for addr in list(data_info.keys()):
        record = data_info[addr]
        timeout = 20 if rtt_info[addr].timeout_interval is None else 2 * rtt_info[addr].timeout_interval
        if time() - record.last_receive_time > timeout:
            chunk_hash = data_info[addr].downloading_chunk_hash
            unfetch_hash.add(chunk_hash)
            hash_peer_list[chunk_hash].append(hash_peer_list[chunk_hash].popleft())
            del data_info[addr]


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)
    peer_list = config.peers
    for p in peer_list:
        if int(p[0]) != config.identity:
            rtt_info[(p[1], int(p[2]))] = RTT_Info()
            rtt_info[(p[1], int(p[2]))].timeout_interval = config.timeout
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
            timeout_retransmission(sock)
            send_get(sock)
            handle_crash()
            global downloading
            if len(target_hash) == len(received_hash) and downloading:
                downloading = False
                with open(config.output_file, "wb") as wf:
                    pickle.dump(received_hash, wf)

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
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=None)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)
