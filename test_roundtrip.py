import socket
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

STX = chr(0x02)
ETX = chr(0x03)


def build_telegram(xml_text: str) -> str:
    # IMPORTANT: This uses character length, matching your current server logic.
    # If LFS expects byte length, switch to len(xml_text.encode("utf-8")).
    length = len(xml_text)
    return f"{STX}{length:04d}{xml_text}{ETX}"


def parse_telegram(response_text: str) -> str:
    """
    Extract XML from STX/len/XML/ETX response.
    Mirrors your receiver logic: strip STX, read 4-digit length, strip ETX, lstrip.
    """
    s = response_text
    if s.startswith(STX):
        s = s[1:]

    # read length field (but we don't strictly need it to extract XML)
    s = s[4:]

    if s.endswith(ETX):
        s = s[:-1]

    return s.lstrip()


def extract_hcvenr(xml_text: str) -> str | None:
    root = ET.fromstring(xml_text)
    # Expecting: <LFS><PHVSRCV>...<HCVENR>...</HCVENR>...</PHVSRCV></LFS>
    hcvenr = root.find(".//HCVENR")
    return hcvenr.text.strip() if (hcvenr is not None and hcvenr.text) else None


def tcp_roundtrip(host: str, port: int, telegram: str, timeout: float = 5.0) -> str:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(telegram.encode("utf-8", errors="replace"))
        data = sock.recv(65535)
    return data.decode("utf-8", errors="replace")


def main():
    # Usage:
    # python test_roundtrip.py INCOMING.xml 127.0.0.1 8888 [OUTGOING.xml]
    if len(sys.argv) < 4:
        print("Usage: python test_roundtrip.py <incoming_xml> <host> <port> [outgoing_xml]")
        sys.exit(2)

    incoming_path = Path(sys.argv[1])
    host = sys.argv[2]
    port = int(sys.argv[3])
    outgoing_path = Path(sys.argv[4]) if len(sys.argv) >= 5 else None

    xml_in = incoming_path.read_text(encoding="utf-8")
    telegram = build_telegram(xml_in)

    print(f"[INFO] Sending telegram to {host}:{port} (payload chars={len(xml_in)})")
    resp_text = tcp_roundtrip(host, port, telegram)

    xml_out = parse_telegram(resp_text)

    # Validate XML
    try:
        ET.fromstring(xml_out)
    except Exception as e:
        print("[ERROR] Response XML is not well-formed:", e)
        print("---- RAW RESPONSE START ----")
        print(resp_text)
        print("---- RAW RESPONSE END ----")
        sys.exit(1)

    ve = extract_hcvenr(xml_out)
    if ve:
        print(f"[OK] HCVENR found: {ve}")
    else:
        print("[FAIL] HCVENR missing or empty in response.")
        print(xml_out)
        sys.exit(1)

    if outgoing_path:
        outgoing_path.write_text(xml_out, encoding="utf-8")
        print(f"[INFO] Wrote outgoing XML to: {outgoing_path}")

    sys.exit(0)


if __name__ == "__main__":
    main()
