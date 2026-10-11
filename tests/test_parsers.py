"""
test_parsers.py — Unit tests for parsers.py.

Tests run without live network access or elevated privileges.
Scapy is used to construct synthetic packets.
"""

import sys
import unittest
from pathlib import Path

# Ensure the project root is on the path.
sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw

from parsers import (
    ParsedPacket,
    parse_packet,
    is_tcp_syn,
    is_icmp_echo_request,
    is_arp_reply,
    is_arp_request,
    is_dns_query,
    is_dns_nxdomain,
    ICMP_ECHO_REQUEST,
    ICMP_ECHO_REPLY,
    ARP_REQUEST,
    ARP_REPLY,
    DNS_RCODE_NXDOMAIN,
)


def _make_tcp_syn(src="10.0.0.1", dst="10.0.0.2", sport=12345, dport=80):
    return (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src=src, dst=dst, ttl=64)
        / TCP(sport=sport, dport=dport, flags="S", seq=1000)
    )


def _make_tcp_syn_ack(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=12345):
    return (
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="SA")
    )


def _make_udp(src="10.0.0.1", dst="10.0.0.2", sport=5000, dport=53):
    return (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=sport, dport=dport)
    )


def _make_icmp_request(src="10.0.0.1", dst="10.0.0.2"):
    return (
        Ether()
        / IP(src=src, dst=dst)
        / ICMP(type=ICMP_ECHO_REQUEST, code=0)
    )


def _make_icmp_reply(src="10.0.0.2", dst="10.0.0.1"):
    return (
        Ether()
        / IP(src=src, dst=dst)
        / ICMP(type=ICMP_ECHO_REPLY, code=0)
    )


def _make_arp_request(src_ip="10.0.0.1", src_mac="aa:bb:cc:dd:ee:01",
                      dst_ip="10.0.0.2"):
    return (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=ARP_REQUEST, psrc=src_ip, hwsrc=src_mac, pdst=dst_ip)
    )


def _make_arp_reply(src_ip="10.0.0.2", src_mac="aa:bb:cc:dd:ee:02",
                    dst_ip="10.0.0.1", dst_mac="aa:bb:cc:dd:ee:01"):
    return (
        Ether(src=src_mac, dst=dst_mac)
        / ARP(op=ARP_REPLY, psrc=src_ip, hwsrc=src_mac,
              pdst=dst_ip, hwdst=dst_mac)
    )


def _make_dns_query(src="10.0.0.1", dst="8.8.8.8", name="example.com"):
    return (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=12345, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=name, qtype="A"))
    )


def _make_dns_response(
    src="8.8.8.8", dst="10.0.0.1", name="example.com",
    rcode=0, answer_ip="93.184.216.34"
):
    pkt = (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=53, dport=12345)
        / DNS(
            qr=1, rd=1, ra=1, rcode=rcode,
            qd=DNSQR(qname=name, qtype="A"),
            an=DNSRR(rrname=name, rdata=answer_ip) if rcode == 0 else None,
        )
    )
    return pkt


def _make_dns_nxdomain(src="8.8.8.8", dst="10.0.0.1", name="notexist.example"):
    return _make_dns_response(
        src=src, dst=dst, name=name, rcode=DNS_RCODE_NXDOMAIN
    )


class TestParsePacketReturnsNoneForNone(unittest.TestCase):
    def test_none_input_returns_none(self):
        self.assertIsNone(parse_packet(None))


class TestTcpParsing(unittest.TestCase):
    def setUp(self):
        self.pkt = _make_tcp_syn()
        self.parsed = parse_packet(self.pkt)

    def test_parsed_is_not_none(self):
        self.assertIsNotNone(self.parsed)

    def test_has_tcp(self):
        self.assertTrue(self.parsed.has_tcp)

    def test_protocol_is_tcp(self):
        self.assertEqual(self.parsed.protocol, "TCP")

    def test_src_ip(self):
        self.assertEqual(self.parsed.src_ip, "10.0.0.1")

    def test_dst_ip(self):
        self.assertEqual(self.parsed.dst_ip, "10.0.0.2")

    def test_src_port(self):
        self.assertEqual(self.parsed.src_port, 12345)

    def test_dst_port(self):
        self.assertEqual(self.parsed.dst_port, 80)

    def test_is_syn_true(self):
        self.assertTrue(self.parsed.is_syn)

    def test_is_syn_ack_false(self):
        self.assertFalse(self.parsed.is_syn_ack)

    def test_ip_ttl(self):
        self.assertEqual(self.parsed.ip_ttl, 64)

    def test_src_mac_present(self):
        self.assertIsNotNone(self.parsed.src_mac)

    def test_is_tcp_syn_helper(self):
        self.assertTrue(is_tcp_syn(self.parsed))

    def test_timestamp_not_empty(self):
        self.assertIsNotNone(self.parsed.timestamp_utc)
        self.assertTrue(self.parsed.timestamp_utc.endswith("Z"))

    def test_no_parse_error(self):
        self.assertFalse(self.parsed.parse_error)


class TestTcpSynAckParsing(unittest.TestCase):
    def test_syn_ack_flags(self):
        pkt = _make_tcp_syn_ack()
        parsed = parse_packet(pkt)
        self.assertFalse(parsed.is_syn)
        self.assertTrue(parsed.is_syn_ack)
        self.assertFalse(is_tcp_syn(parsed))


class TestUdpParsing(unittest.TestCase):
    def setUp(self):
        self.pkt = _make_udp()
        self.parsed = parse_packet(self.pkt)

    def test_has_udp(self):
        self.assertTrue(self.parsed.has_udp)

    def test_protocol_is_udp(self):
        self.assertEqual(self.parsed.protocol, "UDP")

    def test_src_port(self):
        self.assertEqual(self.parsed.src_port, 5000)

    def test_dst_port(self):
        self.assertEqual(self.parsed.dst_port, 53)

    def test_has_ip(self):
        self.assertTrue(self.parsed.has_ip)

    def test_not_tcp(self):
        self.assertFalse(self.parsed.has_tcp)


class TestIcmpParsing(unittest.TestCase):
    def setUp(self):
        self.req_pkt = _make_icmp_request()
        self.rep_pkt = _make_icmp_reply()
        self.req = parse_packet(self.req_pkt)
        self.rep = parse_packet(self.rep_pkt)

    def test_echo_request_type(self):
        self.assertEqual(self.req.icmp_type, ICMP_ECHO_REQUEST)

    def test_echo_reply_type(self):
        self.assertEqual(self.rep.icmp_type, ICMP_ECHO_REPLY)

    def test_is_echo_request_true(self):
        self.assertTrue(self.req.is_echo_request)

    def test_is_echo_reply_false_for_request(self):
        self.assertFalse(self.req.is_echo_reply)

    def test_is_echo_reply_true(self):
        self.assertTrue(self.rep.is_echo_reply)

    def test_has_icmp_true(self):
        self.assertTrue(self.req.has_icmp)

    def test_protocol_is_icmp(self):
        self.assertEqual(self.req.protocol, "ICMP")

    def test_helper_echo_request(self):
        self.assertTrue(is_icmp_echo_request(self.req))

    def test_helper_echo_reply_not_request(self):
        self.assertFalse(is_icmp_echo_request(self.rep))


class TestArpParsing(unittest.TestCase):
    def setUp(self):
        self.req_pkt = _make_arp_request()
        self.rep_pkt = _make_arp_reply()
        self.req = parse_packet(self.req_pkt)
        self.rep = parse_packet(self.rep_pkt)

    def test_arp_op_request(self):
        self.assertEqual(self.req.arp_op, ARP_REQUEST)

    def test_arp_op_reply(self):
        self.assertEqual(self.rep.arp_op, ARP_REPLY)

    def test_has_arp_true(self):
        self.assertTrue(self.req.has_arp)

    def test_protocol_is_arp(self):
        self.assertEqual(self.req.protocol, "ARP")

    def test_arp_src_ip(self):
        self.assertEqual(self.req.arp_src_ip, "10.0.0.1")

    def test_arp_dst_ip(self):
        self.assertEqual(self.req.arp_dst_ip, "10.0.0.2")

    def test_arp_src_mac(self):
        self.assertIsNotNone(self.req.arp_src_mac)

    def test_helper_is_arp_request(self):
        self.assertTrue(is_arp_request(self.req))

    def test_helper_is_arp_reply(self):
        self.assertTrue(is_arp_reply(self.rep))

    def test_helper_reply_not_request(self):
        self.assertFalse(is_arp_request(self.rep))


class TestDnsParsing(unittest.TestCase):
    def setUp(self):
        self.query_pkt = _make_dns_query(name="example.com")
        self.resp_pkt = _make_dns_response(name="example.com")
        self.nx_pkt = _make_dns_nxdomain(name="notexist.example")
        self.query = parse_packet(self.query_pkt)
        self.resp = parse_packet(self.resp_pkt)
        self.nx = parse_packet(self.nx_pkt)

    def test_query_is_dns(self):
        self.assertTrue(self.query.is_dns)

    def test_query_not_response(self):
        self.assertFalse(self.query.dns_is_response)

    def test_response_is_dns(self):
        self.assertTrue(self.resp.is_dns)

    def test_response_is_response_flag(self):
        self.assertTrue(self.resp.dns_is_response)

    def test_query_name_parsed(self):
        self.assertIsNotNone(self.query.dns_query_name)
        self.assertIn("example", self.query.dns_query_name)

    def test_response_rcode_ok(self):
        self.assertEqual(self.resp.dns_rcode, 0)

    def test_nxdomain_rcode(self):
        self.assertEqual(self.nx.dns_rcode, DNS_RCODE_NXDOMAIN)

    def test_helper_is_dns_query(self):
        self.assertTrue(is_dns_query(self.query))

    def test_helper_response_not_query(self):
        self.assertFalse(is_dns_query(self.resp))

    def test_helper_is_nxdomain(self):
        self.assertTrue(is_dns_nxdomain(self.nx))

    def test_helper_ok_response_not_nxdomain(self):
        self.assertFalse(is_dns_nxdomain(self.resp))


class TestMissingLayers(unittest.TestCase):
    """Ensure malformed / incomplete packets do not crash the parser."""

    def test_raw_bytes_only(self):
        """A packet with no Ethernet/IP layer should not crash."""
        from scapy.packet import Raw
        pkt = Raw(load=b"\x00" * 20)
        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)

    def test_ip_only_no_transport(self):
        """IP packet with no TCP/UDP/ICMP — protocol should be OTHER or None."""
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8", proto=253)
        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.has_ip)
        self.assertFalse(parsed.has_tcp)
        self.assertFalse(parsed.has_udp)
        self.assertFalse(parsed.has_icmp)

    def test_truncated_tcp_no_crash(self):
        """TCP packet that Scapy can still parse but has minimal content."""
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80)
        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.has_tcp)

    def test_arp_missing_fields(self):
        """ARP with only mandatory fields."""
        pkt = Ether() / ARP()
        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.has_arp)

    def test_parse_error_flag_not_set_on_valid_packet(self):
        pkt = _make_tcp_syn()
        parsed = parse_packet(pkt)
        self.assertFalse(parsed.parse_error)


if __name__ == "__main__":
    unittest.main()
