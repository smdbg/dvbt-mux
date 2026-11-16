#!/usr/bin/env python3
"""Black-box UDP/TS regression checks for the standalone VBR multiplexer."""
import argparse
import json
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'dvb-mux'


def crc(data):
    value = 0xffffffff
    for byte in data:
        value ^= byte << 24
        for _ in range(8):
            value = ((value << 1) ^ (0x04c11db7 if value & 0x80000000 else 0)) & 0xffffffff
    return value


def section(tid, extension, body, version=0, number=0, last=0):
    data = bytearray([tid, 0xb0, 0]) + struct.pack('>HBBB', extension, 0xc1 | version << 1, number, last) + body
    length = len(data) + 1
    data[1] |= length >> 8
    data[2] = length & 255
    return bytes(data) + struct.pack('>I', crc(data))


def ca(pid=600):
    return bytes([9, 4, 0x0b, 0, 0xe0 | pid >> 8, pid & 255])


def pmt(sid=10, es=256, ecm=500):
    descriptors = ca(ecm)
    body = struct.pack('>HH', 0xe000 | es, 0xf000 | len(descriptors)) + descriptors
    body += bytes([0x1b]) + struct.pack('>HH', 0xe000 | es, 0xf000)
    return section(2, sid, body)


def pat(sid=10, pid=100, **kwargs):
    return section(0, 10, struct.pack('>HH', sid, 0xe000 | pid), **kwargs)


def eit(sid=10):
    # Actual-TS p/f; opaque valid event body preserved byte-for-byte.
    descriptor = bytes([0x4d, 10]) + b'eng\x03EPG\x02ok'
    event = bytes.fromhex('0001ef23120000010000') + struct.pack('>H', 0x8000 | len(descriptor)) + descriptor
    return section(0x4e, sid, struct.pack('>HHBB', 10, 20, 0, 0x4e) + event)


def cyrillic_eit(sid=10):
    """Tagged ISO-8859-5 in every short/extended event text field."""
    def text(value):
        return b'\x01' + value.encode('iso8859_5')
    title, description = text('Новини'), text('Български текст')
    short = b'bul' + bytes([len(title)]) + title + bytes([len(description)]) + description
    key, value = text('Участници'), text('Иван')
    items = bytes([len(key)]) + key + bytes([len(value)]) + value
    more = text('Продължение на описанието')
    extended = b'\x00bul' + bytes([len(items)]) + items + bytes([len(more)]) + more
    descriptors = bytes([0x4d, len(short)]) + short + bytes([0x4e, len(extended)]) + extended
    event = bytes.fromhex('0001ef23120000010000') + struct.pack('>H', 0x8000 | len(descriptors)) + descriptors
    return section(0x4e, sid, struct.pack('>HHBB', 10, 20, 0, 0x4e) + event)


def packetize(pid, data, counters):
    packets = []
    first = True
    while data:
        count = 183 if first else 184
        payload, data = data[:count], data[count:]
        cc = counters.get(pid, 0)
        counters[pid] = (cc + 1) & 15
        packets.append(bytes([0x47, (pid >> 8) | (0x40 if first else 0), pid & 255, 0x10 | cc]) + (b'\0' if first else b'') + payload + b'\xff' * (count - len(payload)))
        first = False
    return b''.join(packets)


def media(pid, marker, cc=0):
    return bytes([0x47, pid >> 8, pid & 255, 0x90 | (cc & 15)]) + marker.ljust(184, b'\xaa')


def sections(packets, pid):
    result, buffer = [], bytearray()
    for packet in packets:
        if (((packet[1] & 31) << 8) | packet[2]) != pid or not packet[3] & 16:
            continue
        at = 4
        if packet[3] & 32:
            at += packet[4] + 1
        if at >= 188:
            continue
        if packet[1] & 64:
            at += 1 + packet[at]
            buffer.clear()
        buffer.extend(packet[at:])
        while len(buffer) >= 3 and buffer[0] != 255:
            n = 3 + ((buffer[1] & 15) << 8) + buffer[2]
            if len(buffer) < n:
                break
            result.append(bytes(buffer[:n]))
            del buffer[:n]
    return result


def descriptors(data):
    result = []
    while data:
        if len(data) < 2 or len(data) < 2 + data[1]:
            raise AssertionError('invalid descriptor bounds')
        n = 2 + data[1]
        result.append(data[:n])
        data = data[n:]
    return result


class MuxTests(unittest.TestCase):
    def config(self, ports):
        return dict(network_id=20, transport_stream_id=30, original_network_id=40,
                    network_name='Тестова мрежа', provider_name='Доставчик', country='BGR',
                    frequency_khz=474000, modulation='64-QAM', bandwidth_mhz=8,
                    fec='3/4', guard='1/32', transmission_mode='8K', buffer_bytes=1048576,
                    codepage='UTF-8', capacity_bps=27144384, inputs=[
                        dict(id=f'in{i}', url=f'udp://127.0.0.1:{port}', interface='127.0.0.1',
                             input_service_id=10, service_id=100 + i, name=f'Канал {i}',
                             lcn=i + 1, scrambled=True, emm_group='same-tvcas', emm_caid=0x0b00,
                             emm_pid=600) for i, port in enumerate(ports)])

    def execute(self, config, send=None):
        with tempfile.TemporaryDirectory(prefix='dvb-mux-test-') as tmp:
            path = Path(tmp) / 'config.json'
            path.write_text(json.dumps(config, ensure_ascii=False))
            if send is None:
                return subprocess.run([str(BINARY), '--config', str(path), '--check-config'], capture_output=True)
            status = Path(tmp) / 'status.json'
            proc = subprocess.Popen([str(BINARY), '--config', str(path), '--status-file', str(status)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, logs = bytearray(), bytearray()
            readers = [threading.Thread(target=lambda: output.extend(proc.stdout.read())), threading.Thread(target=lambda: logs.extend(proc.stderr.read()))]
            for thread in readers:
                thread.start()
            try:
                time.sleep(.1)
                send(proc)
            finally:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=5)
                for thread in readers:
                    thread.join(timeout=5)
                proc.stdout.close()
                proc.stderr.close()
            self.assertEqual(proc.returncode, 0, logs.decode())
            self.assertNotIn(b'ERROR: AddressSanitizer', logs)
            self.assertEqual(len(output) % 188, 0)
            packets = [output[x:x+188] for x in range(0, len(output), 188)]
            self.assertTrue(all(p[0] == 0x47 for p in packets))
            return packets, json.loads(status.read_text()), logs

    def test_config_validation(self):
        config = self.config([34567])
        self.assertEqual(self.execute(config).returncode, 0)
        for field, invalid in [('guard', '1/34'), ('codepage', 'bad'), ('country', 'BG'), ('network_name', 'а' * 128), ('buffer_bytes', 0)]:
            altered = {**config, field: invalid}
            self.assertEqual(self.execute(altered).returncode, 2, field)
        config['inputs'][0]['name'] = 'а' * 125
        self.assertEqual(self.execute(config).returncode, 2)

    def test_text_encoding_validation(self):
        config = self.config([34567])
        config['codepage'] = 'ISO-8859-5'
        # 254 Cyrillic characters become 254 encoded bytes plus selector 01.
        config['network_name'] = 'Б' * 254
        self.assertEqual(self.execute(config).returncode, 0)
        config['network_name'] += 'Б'
        self.assertEqual(self.execute(config).returncode, 2)
        config['network_name'] = 'Мрежа'
        config['inputs'][0]['name'] = 'Знак 😀'
        self.assertEqual(self.execute(config).returncode, 2)
        config['inputs'][0]['name'] = 'Име'
        config['codepage'] = 'ISO-6937'
        self.assertEqual(self.execute(config).returncode, 2)
        config['network_name'] = 'Réseau €'
        config['provider_name'] = 'Provider'
        config['inputs'][0]['name'] = 'Café'
        self.assertEqual(self.execute(config).returncode, 0)
        config['inputs'][0]['name'] = 'A' * 126
        config['inputs'][0]['provider_name'] = 'P' * 126
        self.assertEqual(self.execute(config).returncode, 0)
        config['inputs'][0]['provider_name'] += 'P'
        self.assertEqual(self.execute(config).returncode, 2)

    def test_generated_name_encodings_leave_cyrillic_epg_unchanged(self):
        cases = [
            ('UTF-8', 'Мрежа', 'Канал', 'Доставчик',
             b'\x15' + 'Мрежа'.encode(), b'\x15' + 'Канал'.encode(), b'\x15' + 'Доставчик'.encode()),
            ('ISO-8859-5', 'Мрежа', 'Канал', 'Доставчик',
             b'\x01' + 'Мрежа'.encode('iso8859_5'), b'\x01' + 'Канал'.encode('iso8859_5'), b'\x01' + 'Доставчик'.encode('iso8859_5')),
            ('ISO-6937', 'Réseau €', 'Café', 'Provider', b'R\xc2eseau \xa4', b'Caf\xc2e', b'Provider'),
        ]
        for encoding, network, name, provider, expected_network, expected_name, expected_provider in cases:
            with self.subTest(encoding=encoding):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
                sock.close()
                config = self.config([port])
                config.update(codepage=encoding, network_name=network, provider_name=provider)
                config['inputs'][0]['name'] = name
                epg_input = cyrillic_eit()
                def send(proc):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    cc = {}
                    try:
                        for turn in range(12):
                            data = packetize(0, pat(), cc) + packetize(100, pmt(), cc)
                            data += packetize(18, epg_input, cc) + media(256, b'CONTENT', turn)
                            sock.sendto(data, ('127.0.0.1', port))
                            time.sleep(.02)
                        time.sleep(.1)
                    finally:
                        sock.close()
                packets, status, _ = self.execute(config, send)
                self.assertEqual(status['ready_services'], 1)
                nit = sections(packets, 16)[-1]
                nlen = int.from_bytes(nit[8:10], 'big') & 4095
                self.assertEqual(descriptors(nit[10:10+nlen])[0][2:], expected_network)
                sdt = sections(packets, 17)[-1]
                self.assertEqual(crc(sdt), 0)
                dlen = int.from_bytes(sdt[14:16], 'big') & 4095
                service = next(d for d in descriptors(sdt[16:16+dlen]) if d[0] == 0x48)
                plen = service[3]
                self.assertEqual(service[4:4+plen], expected_provider)
                nlen = service[4+plen]
                self.assertEqual(service[5+plen:5+plen+nlen], expected_name)
                epg = sections(packets, 18)
                self.assertTrue(epg)
                self.assertTrue(all(part[14:-4] == epg_input[14:-4] for part in epg))
                self.assertTrue(all(crc(part) == 0 for part in epg))
                self.assertTrue(all(part[3:5] == b'\0d' and part[8:12] == b'\0\x1e\0\x28' for part in epg))

    def test_protocol_remux(self):
        sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
        ports = []
        for sock in sockets:
            sock.bind(('127.0.0.1', 0))
            ports.append(sock.getsockname()[1])
        for sock in sockets:
            sock.close()
        config = self.config(ports)
        # Exercise the exact SDT descriptor byte limit with multibyte text.
        config['network_name'] = 'М' * 127
        for item in config['inputs']:
            item['name'] = 'К' * 65
            item['provider_name'] = 'П' * 60
        counters = [{}, {}]
        def send(proc):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for turn in range(25):
                    self.assertIsNone(proc.poll())
                    for i, port in enumerate(ports):
                        cc = counters[i]
                        # Multi-section PAT: selected service is only in section 1.
                        data = packetize(0, pat(0, 16, number=0, last=1), cc)
                        data += packetize(0, pat(number=1, last=1), cc)
                        data += packetize(1, section(1, 0xffff, ca()), cc)
                        data += packetize(100, pmt(), cc)
                        data += media(256, f'MEDIA-{i}'.encode(), turn & 15)
                        data += packetize(500, section(0x80, 1, b'ECM'), cc)
                        data += packetize(600, section(0x82, 1, b'EMM'), cc)
                        data += packetize(18, eit(), cc)
                        data += media(8191, b'NULL')
                        sock.sendto(data, ('127.0.0.1', port))
                    time.sleep(.02)
                # Corrupt and structurally malformed sections must not replace valid PSI.
                bad = bytearray(pmt()); bad[-1] ^= 1
                sock.sendto(packetize(100, bad, counters[0]), ('127.0.0.1', ports[0]))
                sock.sendto(b'not MPEG TS', ('127.0.0.1', ports[0]))
                time.sleep(.2)
            finally:
                sock.close()
        packets, status, logs = self.execute(config, send)
        self.assertGreater(len(packets), 100)
        self.assertFalse(any(((p[1] & 31) << 8 | p[2]) == 8191 for p in packets))
        self.assertEqual(status['ready_services'], 2)
        self.assertEqual(status['active_services'], 2)
        self.assertEqual(status['dropped_packets'], 0)
        self.assertGreater(status['null_dropped'], 0)
        self.assertGreater(status['invalid_packets'], 0)
        pat_out = sections(packets, 0)[-1]
        entries = {int.from_bytes(pat_out[a:a+2], 'big'): int.from_bytes(pat_out[a+2:a+4], 'big') & 8191 for a in range(8, len(pat_out)-4, 4)}
        self.assertEqual(set(entries), {0, 100, 101})
        pmts = [sections(packets, entries[100+i])[-1] for i in range(2)]
        mapped_es, mapped_ecm = [], []
        for i, p in enumerate(pmts):
            self.assertEqual(crc(p), 0)
            self.assertEqual(int.from_bytes(p[3:5], 'big'), 100+i)
            info = int.from_bytes(p[10:12], 'big') & 4095
            mapped_ecm.append(int.from_bytes(descriptors(p[12:12+info])[0][4:6], 'big') & 8191)
            mapped_es.append(int.from_bytes(p[13+info:15+info], 'big') & 8191)
            self.assertEqual(int.from_bytes(p[8:10], 'big') & 8191, mapped_es[-1])
        self.assertEqual(len(set(mapped_es + mapped_ecm)), 4)
        for i, pid in enumerate(mapped_es):
            media_out = [p for p in packets if (((p[1] & 31) << 8) | p[2]) == pid]
            self.assertTrue(media_out)
            self.assertTrue(all(p[4:11] == f'MEDIA-{i}'.encode() for p in media_out))
            self.assertEqual([p[3] & 15 for p in media_out[:16]], list(range(16)))
            self.assertTrue(all(p[3] & 0xc0 == 0x80 for p in media_out))
        cat = sections(packets, 1)[-1]
        self.assertEqual(crc(cat), 0)
        cat_desc = descriptors(cat[8:-4])
        self.assertEqual(len(cat_desc), 1)
        self.assertEqual(int.from_bytes(cat_desc[0][4:6], 'big') & 8191, 8064)
        self.assertTrue(sections(packets, 8064))
        epg = sections(packets, 18)
        self.assertEqual({int.from_bytes(e[3:5], 'big') for e in epg}, {100, 101})
        self.assertTrue(all(crc(e) == 0 and e[8:12] == b'\0\x1e\0\x28' and e[14:-4] == eit()[14:-4] for e in epg))
        nit = sections(packets, 16)[-1]
        self.assertEqual(crc(nit), 0)
        nlen = int.from_bytes(nit[8:10], 'big') & 4095
        self.assertEqual(descriptors(nit[10:10+nlen])[0][2], 0x15)
        offset = 12+nlen
        tlen = int.from_bytes(nit[offset+4:offset+6], 'big') & 4095
        nit_descriptors = descriptors(nit[offset+6:offset+6+tlen])
        terrestrial = next(d for d in nit_descriptors if d[0] == 0x5a)
        self.assertEqual(int.from_bytes(terrestrial[2:6], 'big'), 47400000)
        self.assertEqual(terrestrial[7] >> 6, 2)
        self.assertEqual(terrestrial[7] & 7, 2)
        self.assertEqual((terrestrial[8] >> 3) & 3, 0)
        self.assertEqual((terrestrial[8] >> 1) & 3, 1)
        self.assertTrue(sections(packets, 17))
        self.assertTrue(sections(packets, 20))

    def test_shared_unicast_input_and_peer_nit(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        config = self.config([port, port])
        config['inputs'][1]['input_service_id'] = 11
        # Enough entries to force multi-section NIT, including max-length name.
        config['network_name'] = 'М' * 127
        config['network_transports'] = [dict(transport_stream_id=200+i, original_network_id=40,
            frequency_khz=482000+i*8000, bandwidth_mhz=8, modulation='16-QAM', fec='5/6',
            guard='1/8', transmission_mode='2K', inputs=[dict(service_id=1000+k,lcn=k+1) for k in range(64)]) for i in range(8)]
        def send(proc):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            cc = {}
            try:
                for turn in range(15):
                    data = packetize(0, section(0, 10, struct.pack('>HHHH', 10, 0xe000|100, 11, 0xe000|101)), cc)
                    data += packetize(100, pmt(10, 256), cc)
                    data += packetize(101, pmt(11, 257), cc)
                    data += media(256, b'SHARED-A', turn)
                    data += media(257, b'SHARED-B', turn)
                    sock.sendto(data, ('127.0.0.1', port))
                    time.sleep(.02)
                time.sleep(.2)
            finally:
                sock.close()
        packets, status, _ = self.execute(config, send)
        self.assertEqual(status['ready_services'], 2)
        self.assertEqual(status['active_services'], 2)
        self.assertTrue(any(p[4:12] == b'SHARED-A' for p in packets))
        self.assertTrue(any(p[4:12] == b'SHARED-B' for p in packets))
        nit = sections(packets, 16)
        self.assertTrue(all(crc(part) == 0 for part in nit))
        latest = {part[6]: part for part in nit if part[5] == nit[-1][5]}
        self.assertEqual(set(latest), set(range(nit[-1][7]+1)))
        self.assertGreater(len(latest), 1)
        peers = {}
        for part in latest.values():
            pos = 12 + (int.from_bytes(part[8:10], 'big') & 4095)
            while pos < len(part)-4:
                tsid, onid, length = struct.unpack('>HHH', part[pos:pos+6])
                length &= 4095
                desc = descriptors(part[pos+6:pos+6+length])
                peers[tsid] = (onid, next(d for d in desc if d[0] == 0x5a))
                pos += 6+length
        self.assertEqual(set(peers), {30, *range(200, 208)})
        self.assertEqual(int.from_bytes(peers[203][1][2:6], 'big'), (482000+3*8000)*100)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, default=BINARY)
    args, remaining = parser.parse_known_args()
    BINARY = args.binary.resolve()
    unittest.main(argv=[__file__, *remaining])
