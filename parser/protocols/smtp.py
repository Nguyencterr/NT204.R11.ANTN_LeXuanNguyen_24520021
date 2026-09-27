import re


def parse_smtp(
    payload: bytes,
) -> dict:

    if not payload:
        raise ValueError(
            "SMTP payload is empty"
        )

    text = payload.decode(
        "latin-1",
        errors="replace",
    )

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    if not lines:
        raise ValueError(
            "SMTP payload contains no lines"
        )

    first = lines[0]

    # ---------------------------------------------
    # SMTP response
    # Example:
    # 220 smtp.example.com
    # 250 OK
    # ---------------------------------------------
    response_match = re.match(
        r"^(\d{3})([\s-])(.*)$",
        first,
    )

    if response_match:

        return {
            "protocol": "SMTP",
            "type": "response",
            "status_code": int(
                response_match.group(1)
            ),
            "separator": response_match.group(2),
            "message": response_match.group(3),
        }

    # ---------------------------------------------
    # HELO / EHLO
    # ---------------------------------------------
    helo_match = re.match(
        r"^(HELO|EHLO)\s+(.+)$",
        first,
        flags=re.IGNORECASE,
    )

    if helo_match:

        return {
            "protocol": "SMTP",
            "type": "command",
            "command": helo_match.group(1).upper(),
            "argument": helo_match.group(2),
        }

    # ---------------------------------------------
    # MAIL FROM
    # ---------------------------------------------
    mail_match = re.match(
        r"^MAIL FROM:\s*(.*)$",
        first,
        flags=re.IGNORECASE,
    )

    if mail_match:

        return {
            "protocol": "SMTP",
            "type": "command",
            "command": "MAIL FROM",
            "argument": mail_match.group(1),
        }

    # ---------------------------------------------
    # RCPT TO
    # ---------------------------------------------
    rcpt_match = re.match(
        r"^RCPT TO:\s*(.*)$",
        first,
        flags=re.IGNORECASE,
    )

    if rcpt_match:

        return {
            "protocol": "SMTP",
            "type": "command",
            "command": "RCPT TO",
            "argument": rcpt_match.group(1),
        }

    raise ValueError(
        "Payload is not supported SMTP message"
    )
