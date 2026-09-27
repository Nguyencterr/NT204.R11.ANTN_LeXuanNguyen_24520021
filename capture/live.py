from scapy.all import sniff


def start_live_capture(
    interface: str,
    callback,
    count: int = 0,
) -> None:

    sniff(
        iface=interface,
        prn=callback,
        store=False,
        count=count if count > 0 else 0,
    )
