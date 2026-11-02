from scapy.utils import PcapReader


def read_pcap(
    filename: str,
):

    # Scapy's PcapReader expects a path-like object it can ``open`` itself; a
    # ``pathlib.Path`` is accepted here for convenience and converted first.
    reader = PcapReader(
        str(filename)
    )

    try:

        for packet in reader:
            yield packet

    finally:

        reader.close()
