from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


BASE_DIR = Path("TEST")


def save_case(
    name: str,
    packets: list,
) -> None:

    folder = BASE_DIR / name

    folder.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = folder / "input.pcap"

    wrpcap(
        str(output),
        packets,
    )

    print(f"Created: {output}")


def main():

    client = "192.168.1.10"
    server = "192.168.1.20"

    # =============================================
    # 1. TCP handshake
    # =============================================

    syn = (
        Ether()
        / IP(src=client, dst=server)
        / TCP(
            sport=50000,
            dport=80,
            flags="S",
            seq=1000,
        )
    )

    syn_ack = (
        Ether()
        / IP(src=server, dst=client)
        / TCP(
            sport=80,
            dport=50000,
            flags="SA",
            seq=2000,
            ack=1001,
        )
    )

    ack = (
        Ether()
        / IP(src=client, dst=server)
        / TCP(
            sport=50000,
            dport=80,
            flags="A",
            seq=1001,
            ack=2001,
        )
    )

    save_case(
        "tcp_handshake",
        [syn, syn_ack, ack],
    )

    # =============================================
    # 2. TCP data
    # =============================================

    tcp_data = (
        Ether()
        / IP(src=client, dst=server)
        / TCP(
            sport=50000,
            dport=80,
            flags="PA",
        )
        / b"hello tcp"
    )

    save_case(
        "tcp_data",
        [tcp_data],
    )

    # =============================================
    # 3. UDP
    # =============================================

    udp_packet = (
        Ether()
        / IP(src=client, dst=server)
        / UDP(
            sport=40000,
            dport=9999,
        )
        / b"hello udp"
    )

    save_case(
        "udp",
        [udp_packet],
    )

    # =============================================
    # 4. HTTP GET
    # =============================================

    http_get_payload = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: TestClient\r\n"
        b"\r\n"
    )

    http_get = (
        Ether()
        / IP(src=client, dst=server)
        / TCP(
            sport=50001,
            dport=8088,
            flags="PA",
        )
        / http_get_payload
    )

    save_case(
        "http_get",
        [http_get],
    )

    # =============================================
    # 5. HTTP POST
    # =============================================

    http_post_payload = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 21\r\n"
        b"\r\n"
        b"user=nguyen&role=admin"
    )

    http_post = (
        Ether()
        / IP(src=client, dst=server)
        / TCP(
            sport=50002,
            dport=8088,
            flags="PA",
        )
        / http_post_payload
    )

    save_case(
        "http_post",
        [http_post],
    )

    # =============================================
    # 6. HTTP response
    # =============================================

    http_response_payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: 11\r\n"
        b"\r\n"
        b"Hello World"
    )

    http_response = (
        Ether()
        / IP(src=server, dst=client)
        / TCP(
            sport=8088,
            dport=50002,
            flags="PA",
        )
        / http_response_payload
    )

    save_case(
        "http_response",
        [http_response],
    )

    # =============================================
    # 7. DNS Query
    # =============================================

    dns_query = (
        Ether()
        / IP(src=client, dst="8.8.8.8")
        / UDP(
            sport=53000,
            dport=53,
        )
        / DNS(
            id=1234,
            qr=0,
            rd=1,
            qd=DNSQR(
                qname="example.com",
                qtype="A",
            ),
        )
    )

    save_case(
        "dns_query",
        [dns_query],
    )

    # =============================================
    # 8. DNS Response
    # =============================================

    dns_response = (
        Ether()
        / IP(src="8.8.8.8", dst=client)
        / UDP(
            sport=53,
            dport=53000,
        )
        / DNS(
            id=1234,
            qr=1,
            rd=1,
            ra=1,
            qd=DNSQR(
                qname="example.com",
                qtype="A",
            ),
            an=DNSRR(
                rrname="example.com",
                type="A",
                ttl=300,
                rdata="93.184.216.34",
            ),
        )
    )

    save_case(
        "dns_response",
        [dns_response],
    )

    # =============================================
    # 9. SMTP command
    # =============================================

    smtp_command = (
        Ether()
        / IP(src=client, dst=server)
        / TCP(
            sport=50003,
            dport=25,
            flags="PA",
        )
        / b"EHLO example.com\r\n"
    )

    save_case(
        "smtp_command",
        [smtp_command],
    )

    # =============================================
    # 10. SMTP response
    # =============================================

    smtp_response = (
        Ether()
        / IP(src=server, dst=client)
        / TCP(
            sport=25,
            dport=50003,
            flags="PA",
        )
        / b"250 OK\r\n"
    )

    save_case(
        "smtp_response",
        [smtp_response],
    )

    # =============================================
    # 11. Unknown
    # =============================================

    unknown = (
        Ether()
        / IP(src=client, dst=server)
        / b"\x01\x02\x03\x04"
    )

    save_case(
        "unknown",
        [unknown],
    )


if __name__ == "__main__":
    main()
