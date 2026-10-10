"""Tests for :mod:`parsers`."""

from __future__ import annotations

import unittest

try:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    SCAPY_AVAILABLE = False

from parsers import ParsedPacket, parse_packet


def _stamp(pkt, epoch: float = 1_700_000_000.0):
    """Attach a deterministic timestamp so tests never depend on the wall clock."""
    pkt.time = epoch
    return pkt


@unittest.skipUnless(SCAPY_AVAILABLE, "Scapy is required to build test packets")
class ParserTests(unittest.TestCase):

    def test_parse_tcp_syn(self):
        pkt = _stamp(
            Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
            / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64)
            / TCP(sport=40000, dport=80, flags="S")
        )
        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.protocol, "TCP")
        self.assertEqual(parsed.src_ip, "10.0.0.1")
        self.assertEqual(parsed.dst_ip, "10.0.0.2")
        self.assertEqual(parsed.src_port, 40000)
        self.assertEqual(parsed.dst_port, 80)
        self.assertEqual(parsed.ttl, 64)
        self.assertTrue(parsed.tcp_syn)
        self.assertFalse(parsed.tcp_ack)
        self.assertIn("S", parsed.tcp_flags or "")
        self.assertEqual(parsed.src_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsed.dst_mac, "11:22:33:44:55:66")

    def test_parse_udp(self):
        pkt = _stamp(IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=55555, dport=53))
        parsed = parse_packet(pkt)
        assert parsed is not None
        self.assertEqual(parsed.protocol, "UDP")
        self.assertEqual(parsed.src_port, 55555)
        self.assertEqual(parsed.dst_port, 53)

    def test_parse_icmp_echo_request_and_reply(self):
        request = _stamp(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0))
        reply = _stamp(IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=0, code=0))

        req = parse_packet(request)
        rep = parse_packet(reply)
        assert req is not None and rep is not None
        self.assertEqual(req.icmp_type, 8)
        self.assertEqual(rep.icmp_type, 0)
        self.assertEqual(req.protocol, "ICMP")
        self.assertEqual(rep.protocol, "ICMP")

    def test_parse_arp_request_and_reply(self):
        request = _stamp(
            Ether() / ARP(op=1, psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:ff",
                          pdst="10.0.0.2", hwdst="00:00:00:00:00:00")
        )
        reply = _stamp(
            Ether() / ARP(op=2, psrc="10.0.0.2", hwsrc="11:22:33:44:55:66",
                          pdst="10.0.0.1", hwdst="aa:bb:cc:dd:ee:ff")
        )
        req = parse_packet(request)
        rep = parse_packet(reply)
        assert req is not None and rep is not None
        self.assertEqual(req.protocol, "ARP")
        self.assertEqual(req.arp_op, 1)
        self.assertEqual(req.arp_sender_ip, "10.0.0.1")
        self.assertEqual(req.arp_sender_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(rep.arp_op, 2)
        self.assertEqual(rep.arp_sender_ip, "10.0.0.2")

    def test_parse_dns_query(self):
        pkt = _stamp(
            IP(src="10.0.0.1", dst="8.8.8.8")
            / UDP(sport=40000, dport=53)
            / DNS(id=1234, rd=1, qd=DNSQR(qname="example.com"))
        )
        parsed = parse_packet(pkt)
        assert parsed is not None
        self.assertEqual(parsed.protocol, "DNS")
        self.assertTrue(parsed.dns_is_query)
        self.assertFalse(parsed.dns_is_response)
        self.assertEqual(parsed.dns_qname, "example.com")
        self.assertEqual(parsed.dns_qtype, "A")
        self.assertEqual(parsed.dns_txid, 1234)

    def test_parse_dns_nxdomain_response(self):
        pkt = _stamp(
            IP(src="8.8.8.8", dst="10.0.0.1")
            / UDP(sport=53, dport=40000)
            / DNS(id=1234, qr=1, rcode=3, qd=DNSQR(qname="nonexistent.example"))
        )
        parsed = parse_packet(pkt)
        assert parsed is not None
        self.assertTrue(parsed.dns_is_response)
        self.assertFalse(parsed.dns_is_query)
        self.assertEqual(parsed.dns_rcode, 3)
        self.assertEqual(parsed.dns_rcode_name, "NXDOMAIN")
        self.assertEqual(parsed.dns_qname, "nonexistent.example")

    def test_packet_with_no_expected_layers(self):
        pkt = _stamp(Ether() / IP(src="10.0.0.1", dst="10.0.0.2"))
        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        # No TCP/UDP/ICMP/ARP/DNS layers were present; only IPv4 is known.
        self.assertIsNone(parsed.src_port)
        self.assertIsNone(parsed.dst_port)
        self.assertIsNone(parsed.icmp_type)
        self.assertIsNone(parsed.arp_op)
        self.assertFalse(parsed.dns_is_query)

    def test_malformed_input_does_not_crash(self):
        # Passing non-packet objects must return cleanly (either None or a
        # ParsedPacket whose parse_notes record the failure).
        for bad in (None, b"\x00\x01\x02", "not a packet"):
            result = parse_packet(bad)
            if result is not None:
                self.assertIsInstance(result, ParsedPacket)
                # protocol must always be a string, never None
                self.assertIsInstance(result.protocol, str)

    def test_timestamp_is_utc_iso(self):
        pkt = _stamp(IP() / UDP(dport=53), epoch=1_700_000_000.0)
        parsed = parse_packet(pkt)
        assert parsed is not None
        self.assertTrue(parsed.timestamp_utc.endswith("Z"))
        self.assertEqual(parsed.timestamp_epoch, 1_700_000_000.0)

    def test_legitimate_zero_ttl_is_preserved(self):
        # A TTL of 0 is unusual but must not be confused with "field absent".
        pkt = _stamp(Ether() / IP(src="1.1.1.1", dst="2.2.2.2", ttl=0) / UDP(dport=53))
        parsed = parse_packet(pkt)
        assert parsed is not None
        self.assertEqual(parsed.ttl, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()