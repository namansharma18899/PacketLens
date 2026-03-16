"""Single-threaded DPI pipeline: read PCAP, parse, classify, filter, write output."""

from typing import Dict, Optional, Tuple

from pcap_reader import PcapReader, RawPacket, PcapGlobalHeader, PcapPacketHeader
from packet_parser import PacketParser, PROTOCOL_TCP
from sni_extractor import SNIExtractor, HTTPHostExtractor
from rule_manager import RuleManager
from dpi_types import (
    FiveTuple,
    Flow,
    AppType,
    ip_to_int,
    int_to_ip,
    app_type_to_string,
    sni_to_app_type,
)


def _payload_offset_and_length(data: bytes) -> Tuple[int, int]:
    """Return (payload_offset, payload_length) for TCP after Ethernet+IP+TCP."""
    if len(data) < 14:
        return 0, 0
    offset = 14
    version_ihl = data[14] & 0x0F
    ip_header_len = version_ihl * 4
    offset += ip_header_len
    if offset + 12 >= len(data):
        return 0, 0
    tcp_data_offset = (data[offset + 12] >> 4) & 0x0F
    tcp_header_len = tcp_data_offset * 4
    offset += tcp_header_len
    return offset, len(data) - offset


def run_dpi(
    input_path: str,
    output_path: str,
    rules: RuleManager,
    verbose: bool = True,
) -> bool:
    """
    Run DPI: read input PCAP, classify flows, apply rules, write filtered PCAP.
    Returns True on success.
    """
    reader = PcapReader()
    if not reader.open(input_path):
        return False

    try:
        out = open(output_path, "wb")
    except OSError:
        print("Error: Cannot open output file:", output_path)
        reader.close()
        return False

    gh = reader.get_global_header()
    out.write(gh.to_bytes())

    flows: Dict[FiveTuple, Flow] = {}
    total_packets = 0
    forwarded = 0
    dropped = 0
    app_stats: Dict[AppType, int] = {}

    raw = RawPacket(header=PcapPacketHeader(0, 0, 0, 0), data=b"")

    if verbose:
        print("[DPI] Processing packets...")

    while reader.read_next_packet(raw):
        total_packets += 1
        parsed = PacketParser.parse(
            raw.header.ts_sec,
            raw.header.ts_usec,
            raw.data,
        )
        if parsed is None or not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            # Still forward non-IP or non-TCP/UDP if we want; here we skip
            continue

        tuple_ = FiveTuple(
            src_ip=ip_to_int(parsed.src_ip),
            dst_ip=ip_to_int(parsed.dest_ip),
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol,
        )

        if tuple_ not in flows:
            flows[tuple_] = Flow(tuple=tuple_)
        flow = flows[tuple_]
        flow.packets += 1
        flow.bytes_count += len(raw.data)

        # SNI for HTTPS (port 443)
        if (
            (flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTPS)
            and not flow.sni
            and parsed.has_tcp
            and parsed.dest_port == 443
        ):
            offset, plen = _payload_offset_and_length(raw.data)
            if plen > 5 and parsed.payload_data:
                sni = SNIExtractor.extract(parsed.payload_data)
                if sni:
                    flow.sni = sni
                    flow.app_type = sni_to_app_type(sni)

        # HTTP Host for port 80
        if (
            (flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTP)
            and not flow.sni
            and parsed.has_tcp
            and parsed.dest_port == 80
        ):
            if parsed.payload_data:
                host = HTTPHostExtractor.extract(parsed.payload_data)
                if host:
                    flow.sni = host
                    flow.app_type = sni_to_app_type(host)

        # DNS
        if flow.app_type == AppType.UNKNOWN and (
            parsed.dest_port == 53 or parsed.src_port == 53
        ):
            flow.app_type = AppType.DNS

        # Port-based fallback
        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443:
                flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                flow.app_type = AppType.HTTP

        # Blocking
        if not flow.blocked:
            flow.blocked = rules.is_blocked(tuple_.src_ip, flow.app_type, flow.sni)
            if flow.blocked and verbose:
                print(
                    f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} "
                    f"({app_type_to_string(flow.app_type)}: {flow.sni or '-'})"
                )

        app_stats[flow.app_type] = app_stats.get(flow.app_type, 0) + 1

        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            out.write(raw.header.to_bytes())
            out.write(raw.data)

    reader.close()
    out.close()

    # Report
    if verbose:
        _print_report(total_packets, forwarded, dropped, len(flows), app_stats, flows)

    return True


def _print_report(
    total: int,
    forwarded: int,
    dropped: int,
    num_flows: int,
    app_stats: Dict[AppType, int],
    flows: Dict[FiveTuple, Flow],
) -> None:
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                      PROCESSING REPORT                       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Total Packets:      {total:>10}                             ║")
    print(f"║ Forwarded:          {forwarded:>10}                             ║")
    print(f"║ Dropped:            {dropped:>10}                             ║")
    print(f"║ Active Flows:       {num_flows:>10}                             ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║                    APPLICATION BREAKDOWN                     ║")
    print("╠══════════════════════════════════════════════════════════════╣")

    sorted_apps = sorted(app_stats.items(), key=lambda x: -x[1])
    for app, count in sorted_apps:
        pct = 100.0 * count / total if total else 0
        bar_len = int(pct / 5)
        bar = "#" * bar_len
        name = app_type_to_string(app)
        print(f"║ {name:<15} {count:>8} {pct:>5.1f}% {bar:<20}  ║")

    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    print("[Detected Applications/Domains]")
    seen_snis: Dict[str, AppType] = {}
    for f in flows.values():
        if f.sni:
            seen_snis[f.sni] = f.app_type
    for sni, app in sorted(seen_snis.items()):
        print(f"  - {sni} -> {app_type_to_string(app)}")
