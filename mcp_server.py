from __future__ import annotations

import socket
import xml.etree.ElementTree as ET

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pyShippingSystem-tools")


# -------------------------
# Protocol helpers
# -------------------------
STX = chr(0x02)
ETX = chr(0x03)

def add_protocol_header(xml_string: str) -> str:
    """STX + 4-digit length + XML + ETX (length counts XML chars only)."""
    xml_len = len(xml_string)
    return f"{STX}{xml_len:04d}{xml_string}{ETX}"

def parse_protocol_telegram(telegram: str) -> dict:
    """Parse STX/len/XML/ETX. Returns parsed XML (string) and validation flags."""
    raw = telegram

    has_stx = raw.startswith(STX)
    has_etx = raw.endswith(ETX)

    s = raw
    if has_stx:
        s = s[1:]
    length_field = s[:4]
    s = s[4:]

    declared_len_ok = length_field.strip().isdigit()
    declared_len = int(length_field) if declared_len_ok else None

    if has_etx and s.endswith(ETX):
        s = s[:-1]

    # remove leading whitespace after length field (your code does lstrip())
    xml = s.lstrip()

    actual_len = len(xml)
    length_matches = (declared_len == actual_len) if declared_len is not None else False

    # XML well-formed?
    xml_ok = True
    xml_error = ""
    try:
        ET.fromstring(xml)
    except Exception as e:
        xml_ok = False
        xml_error = str(e)

    return {
        "has_stx": has_stx,
        "has_etx": has_etx,
        "declared_len": declared_len,
        "actual_len": actual_len,
        "length_matches": length_matches,
        "xml_ok": xml_ok,
        "xml_error": xml_error,
        "xml": xml,
    }

def inject_hcvenr_into_response(xml_in: str, ve_nummer: str) -> str:
    """
    Mimics your create_response_xml(): build <LFS><PHVSRCV>..., copy fields from PHVSSND
    and insert <HCVENR> right after <HCPKNR_NUM>.
    """
    root = ET.fromstring(xml_in)
    phvssnd = root.find("PHVSSND")
    if phvssnd is None:
        raise ValueError("Missing PHVSSND in input XML")

    new_root = ET.Element("LFS")
    phvsrcv = ET.SubElement(new_root, "PHVSRCV")

    for child in phvssnd:
        new_child = ET.SubElement(phvsrcv, child.tag)
        new_child.text = child.text

        if child.tag == "HCPKNR_NUM":
            hcvenr = ET.SubElement(phvsrcv, "HCVENR")
            hcvenr.text = ve_nummer

    xml_out = ET.tostring(new_root, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_out


# -------------------------
# MCP tools
# -------------------------
@mcp.tool(description="Build a protocol telegram: STX + 4-digit length + XML + ETX.")
def build_telegram(xml_text: str) -> str:
    return add_protocol_header(xml_text)

@mcp.tool(description="Parse and validate a protocol telegram (STX/len/ETX + XML parse).")
def inspect_telegram(telegram: str) -> dict:
    return parse_protocol_telegram(telegram)

@mcp.tool(description="Create response XML by inserting <HCVENR> after <HCPKNR_NUM> (PHVSSND -> PHVSRCV).")
def make_response_xml(xml_in: str, ve_nummer: str) -> str:
    return inject_hcvenr_into_response(xml_in, ve_nummer)

@mcp.tool(description="Send a telegram to a TCP host/port and return the raw response (as text).")
def tcp_roundtrip(host: str, port: int, telegram: str, timeout_seconds: float = 3.0) -> dict:
    with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
        sock.settimeout(timeout_seconds)
        sock.sendall(telegram.encode("utf-8", errors="replace"))
        data = sock.recv(65535)
    text = data.decode("utf-8", errors="replace")
    return {"bytes": len(data), "response": text, "parsed": parse_protocol_telegram(text)}

if __name__ == "__main__":
    mcp.run()
