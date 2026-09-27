from scapy.layers.dns import DNS


DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}


def decode_name(
    value,
) -> str | None:

    if value is None:
        return None

    if isinstance(value, bytes):

        return value.decode(
            "utf-8",
            errors="replace",
        ).rstrip(".")

    return str(value).rstrip(".")


def parse_first_answer(
    dns,
) -> dict | None:

    answer = getattr(
        dns,
        "an",
        None,
    )

    if answer is None:
        return None

    rrname = getattr(
        answer,
        "rrname",
        None,
    )

    rrtype = getattr(
        answer,
        "type",
        None,
    )

    rdata = getattr(
        answer,
        "rdata",
        None,
    )

    if rrname is None:
        return None

    return {
        "name": decode_name(rrname),
        "type": DNS_TYPES.get(
            int(rrtype),
            str(rrtype),
        ),
        "rdata": str(rdata),
    }


def parse_dns(
    packet,
) -> dict:

    if not packet.haslayer(DNS):
        raise ValueError(
            "DNS layer not found"
        )

    dns = packet[DNS]

    query = None

    if getattr(dns, "qd", None) is not None:

        question = dns.qd

        qname = getattr(
            question,
            "qname",
            None,
        )

        qtype = getattr(
            question,
            "qtype",
            None,
        )

        query = {
            "domain": decode_name(qname),
            "query_type": DNS_TYPES.get(
                int(qtype),
                str(qtype),
            ),
        }

    message_type = (
        "response"
        if int(dns.qr) == 1
        else "query"
    )

    result = {
        "protocol": "DNS",
        "message_type": message_type,
        "transaction_id": int(dns.id),
        "query": query,
    }

    if message_type == "response":

        result["answer"] = (
            parse_first_answer(dns)
        )

    return result
