from scapy.utils import PcapReader


def read_pcap(
    filename: str,
):

    reader = PcapReader(
        filename
    )

    try:

        for packet in reader:
            yield packet

    finally:

        reader.close()
