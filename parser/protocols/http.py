import re


HTTP_METHODS = (
    "OPTIONS",
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "TRACE",
    "CONNECT",
)


def parse_headers(
    lines: list[str],
) -> dict[str, str]:
    """
    Parse HTTP header lines into a dictionary.
    """

    headers: dict[str, str] = {}

    for line in lines:

        if ":" not in line:
            continue

        name, value = line.split(":", 1)

        headers[name.strip()] = value.strip()

    return headers


def parse_http(
    payload: bytes,
) -> dict:
    """
    Parse HTTP/1.x request or response.
    """

    if not payload:
        raise ValueError(
            "HTTP payload is empty"
        )

    text = payload.decode(
        "latin-1",
        errors="replace",
    )

    # Separate headers and body.
    if "\r\n\r\n" in text:

        header_part, body = text.split(
            "\r\n\r\n",
            1,
        )

    elif "\n\n" in text:

        header_part, body = text.split(
            "\n\n",
            1,
        )

    else:

        header_part = text
        body = ""

    lines = (
        header_part
        .replace("\r\n", "\n")
        .split("\n")
    )

    if not lines:
        raise ValueError(
            "HTTP start line is missing"
        )

    start_line = lines[0].strip()

    # ---------------------------------------------
    # HTTP Response
    # Example:
    # HTTP/1.1 200 OK
    # ---------------------------------------------
    response_match = re.match(
        r"^HTTP/(1\.[01])\s+(\d{3})(?:\s+(.*))?$",
        start_line,
    )

    if response_match:

        version = response_match.group(1)

        status_code = int(
            response_match.group(2)
        )

        reason = (
            response_match.group(3)
            or ""
        )

        headers = parse_headers(
            lines[1:]
        )

        return {
            "protocol": "HTTP",
            "type": "response",
            "version": f"HTTP/{version}",
            "status_code": status_code,
            "reason": reason,
            "headers": headers,
            "body": body,
        }

    # ---------------------------------------------
    # HTTP Request
    # ---------------------------------------------
    request_pattern = (
        r"^("
        + "|".join(HTTP_METHODS)
        + r")\s+(\S+)\s+HTTP/(1\.[01])$"
    )

    request_match = re.match(
        request_pattern,
        start_line,
    )

    if request_match:

        method = request_match.group(1)

        path = request_match.group(2)

        version = request_match.group(3)

        headers = parse_headers(
            lines[1:]
        )

        return {
            "protocol": "HTTP",
            "type": "request",
            "method": method,
            "path": path,
            "version": f"HTTP/{version}",
            "headers": headers,
            "body": body,
        }

    raise ValueError(
        "Payload is not supported HTTP/1.x"
    )
