"""Bounded DNS resolver helpers for dns-resolve-plus."""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
from typing import Any

QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


def validate_resolvers(resolvers: list[str]) -> list[str]:
    validated: list[str] = []
    for resolver in resolvers:
        if resolver == "system":
            validated.append(resolver)
            continue
        try:
            ipaddress.ip_address(resolver)
        except ValueError as error:
            raise ValueError(f"resolver must be an IP address or system: {resolver}") from error
        validated.append(resolver)
    return validated


def resolve_system(domain: str, record_types: list[str], timeout_seconds: int) -> tuple[list[dict[str, Any]], int]:
    socket.setdefaulttimeout(timeout_seconds)
    observations: list[dict[str, Any]] = []
    query_count = 0
    if "A" in record_types:
        query_count += 1
        for _, _, _, _, sockaddr in socket.getaddrinfo(domain, None, socket.AF_INET):
            observations.append({"record_type": "A", "value": sockaddr[0], "ttl": None})
    if "AAAA" in record_types:
        query_count += 1
        for _, _, _, _, sockaddr in socket.getaddrinfo(domain, None, socket.AF_INET6):
            observations.append({"record_type": "AAAA", "value": sockaddr[0], "ttl": None})
    return observations, query_count


def resolve_public(domain: str, record_types: list[str], resolvers: list[str], timeout_seconds: int) -> tuple[list[dict[str, Any]], int]:
    validated_resolvers = [resolver for resolver in validate_resolvers(resolvers) if resolver != "system"]
    observations: dict[tuple[str, str], dict[str, Any]] = {}
    query_count = 0
    for record_type in record_types:
        if record_type not in QTYPE:
            continue
        for resolver in validated_resolvers:
            query_count += 1
            for record in udp_dns_query(domain, record_type, resolver, timeout_seconds):
                observations[(str(record["record_type"]), str(record["value"]))] = record
            if any(key[0] == record_type for key in observations):
                break
    return sorted(observations.values(), key=lambda item: (item["record_type"], item["value"])), query_count


def udp_dns_query(domain: str, record_type: str, resolver: str, timeout_seconds: int) -> list[dict[str, Any]]:
    query_id = random.SystemRandom().randint(0, 65535)
    packet = build_dns_query(query_id, domain, QTYPE[record_type])
    family = socket.AF_INET6 if ":" in resolver else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout_seconds)
        try:
            sock.sendto(packet, (resolver, 53))
            response, _ = sock.recvfrom(4096)
        except (OSError, socket.timeout):
            return []
    return parse_dns_response(response, query_id, QTYPE[record_type])


def build_dns_query(query_id: int, domain: str, qtype: int) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in domain.split("."))
    return header + labels + b"\x00" + struct.pack("!HH", qtype, 1)


def parse_dns_response(response: bytes, query_id: int, requested_qtype: int) -> list[dict[str, Any]]:
    if len(response) < 12:
        return []
    response_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", response[:12])
    if response_id != query_id or flags & 0x000F != 0:
        return []
    offset = 12
    for _ in range(qdcount):
        _name, offset = read_dns_name(response, offset)
        offset += 4
        if offset > len(response):
            return []

    records: list[dict[str, Any]] = []
    for _ in range(ancount):
        _name, offset = read_dns_name(response, offset)
        if offset + 10 > len(response):
            return []
        record_type, record_class, ttl, rdlength = struct.unpack("!HHIH", response[offset : offset + 10])
        offset += 10
        rdata_offset = offset
        rdata = response[offset : offset + rdlength]
        offset += rdlength
        if record_class != 1 or record_type != requested_qtype:
            continue
        value = decode_record_value(response, rdata, rdata_offset, record_type)
        if value:
            records.append({"record_type": qtype_name(record_type), "value": value, "ttl": ttl})
    return records


def decode_record_value(message: bytes, rdata: bytes, rdata_offset: int, record_type: int) -> str | None:
    if record_type == QTYPE["A"] and len(rdata) == 4:
        return socket.inet_ntop(socket.AF_INET, rdata)
    if record_type == QTYPE["AAAA"] and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if record_type in {QTYPE["CNAME"], QTYPE["NS"]}:
        name, _offset = read_dns_name(message, rdata_offset)
        return name.rstrip(".") if name else None
    if record_type == QTYPE["MX"] and len(rdata) >= 3:
        preference = struct.unpack("!H", rdata[:2])[0]
        exchange, _offset = read_dns_name(message, rdata_offset + 2)
        return f"{preference} {exchange.rstrip('.')}" if exchange else None
    if record_type == QTYPE["TXT"]:
        chunks: list[str] = []
        index = 0
        while index < len(rdata):
            length = rdata[index]
            index += 1
            if index + length > len(rdata):
                return None
            chunks.append(rdata[index : index + length].decode("utf-8", errors="replace"))
            index += length
        return "".join(chunks) if chunks else None
    return None


def read_dns_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    next_offset = offset
    visited = 0
    while offset < len(message) and visited < 64:
        visited += 1
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                return "", len(message)
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        if length == 0:
            if not jumped:
                next_offset = offset + 1
            return ".".join(labels), next_offset
        offset += 1
        if offset + length > len(message):
            return "", len(message)
        labels.append(message[offset : offset + length].decode("ascii", errors="ignore"))
        offset += length
        if not jumped:
            next_offset = offset
    return "", len(message)


def qtype_name(qtype: int) -> str:
    for name, value in QTYPE.items():
        if value == qtype:
            return name
    return str(qtype)
