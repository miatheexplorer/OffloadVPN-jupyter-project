#!/usr/bin/env python3
"""
p4runtime_controller.py
- Push Offload.p4 pipeline to BMv2 simple_switch_grpc
- Install whitelist + forwarding rules
- Install ARP handling rules
- Optional: install per-flow override in flow_policy (TCP 5-tuple)

Requirements:
- p4runtime_lib from p4lang/tutorials/utils must be importable, e.g.:
    git clone https://github.com/p4lang/tutorials.git ~/p4tutorials
    export PYTHONPATH=~/p4tutorials/utils:$PYTHONPATH
- Run with sudo -E to preserve PYTHONPATH:
    sudo -E python3 p4runtime_controller.py --p4info build/Offload.p4info.txt --bmv2-json build/Offload.json --addr 127.0.0.1:50051
"""

import argparse
import os
import sys
import time
from typing import Optional

# Add the local utils directory to Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
utils_path = os.path.join(script_dir, 'utils')
if utils_path not in sys.path:
    sys.path.insert(0, utils_path)
    print(f"[INFO] Added utils path: {utils_path}")

# p4lang tutorial helpers - FIXED IMPORTS
try:
    # Import Bmv2SwitchConnection from bmv2.py, not switch.py
    from p4runtime_lib.bmv2 import Bmv2SwitchConnection
    from p4runtime_lib.switch import ShutdownAllSwitchConnections
    from p4runtime_lib.helper import P4InfoHelper
    print("[INFO] Successfully imported p4runtime_lib")
except ModuleNotFoundError as e:
    print(
        "\n[ERROR] Could not import p4runtime_lib.\n"
        f"Current Python path: {sys.path}\n"
        "Fix:\n"
        "  git clone https://github.com/p4lang/tutorials.git ~/p4tutorials\n"
        "  export PYTHONPATH=~/p4tutorials/utils:$PYTHONPATH\n"
        "Or make sure the utils directory exists in this location:\n"
        f"  {utils_path}\n"
        "Then run with:\n"
        "  sudo -E python3 p4runtime_controller.py ...\n",
        file=sys.stderr,
    )
    sys.exit(1)


def require_file(path: str) -> None:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Required file not found: {path}")


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def install_whitelist(p4info_helper: P4InfoHelper, sw: Bmv2SwitchConnection, src: str, dst: str) -> None:
    entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.whitelist",
        match_fields={
            "hdr.ipv4.srcAddr": src,
            "hdr.ipv4.dstAddr": dst,
        },
        action_name="MyIngress.allow_pair",
        action_params={},
    )
    sw.WriteTableEntry(entry)
    print(f"[OK] whitelist allow {src} -> {dst}")


def install_fwd_entry(p4info_helper: P4InfoHelper, sw: Bmv2SwitchConnection,
                      table: str, dst_ip: str, prefix_len: int,
                      dst_mac: str, src_mac: str, port: int) -> None:
    """Generic helper to install an LPM forwarding entry."""
    entry = p4info_helper.buildTableEntry(
        table_name=table,
        match_fields={"hdr.ipv4.dstAddr": (dst_ip, prefix_len)},
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dst": dst_mac,
            "src": src_mac,
            "port": port,
        },
    )
    sw.WriteTableEntry(entry)
    print(f"[OK] {table}: {dst_ip}/{prefix_len} -> port{port} (MAC {dst_mac})")


def install_base_rules(p4info_helper: P4InfoHelper, sw: Bmv2SwitchConnection) -> None:
    # ---- Whitelist: allow all valid src->dst pairs (bidirectional) ----
    install_whitelist(p4info_helper, sw, "10.0.1.1", "10.0.2.2")   # h1 -> h2
    install_whitelist(p4info_helper, sw, "10.0.2.2", "10.0.1.1")   # h2 -> h1 (return)
    install_whitelist(p4info_helper, sw, "10.0.1.1", "10.0.3.3")   # h1 -> hgw
    install_whitelist(p4info_helper, sw, "10.0.3.3", "10.0.1.1")   # hgw -> h1 (return)
    install_whitelist(p4info_helper, sw, "10.0.2.2", "10.0.3.3")   # h2 -> hgw
    install_whitelist(p4info_helper, sw, "10.0.3.3", "10.0.2.2")   # hgw -> h2

    # ---- fwd_normal: direct path forwarding ----
    # To h2 (port 2)
    install_fwd_entry(p4info_helper, sw,
                      "MyIngress.fwd_normal", "10.0.2.2", 32,
                      "00:00:00:00:02:02", "00:00:00:00:01:01", 2)
    # To h1 (port 1) — return path
    install_fwd_entry(p4info_helper, sw,
                      "MyIngress.fwd_normal", "10.0.1.1", 32,
                      "00:00:00:00:01:01", "00:00:00:00:02:02", 1)
    # To hgw (port 3)
    install_fwd_entry(p4info_helper, sw,
                      "MyIngress.fwd_normal", "10.0.3.3", 32,
                      "00:00:00:00:03:03", "00:00:00:00:01:01", 3)

    # ---- fwd_vpn: VPN gateway path forwarding ----
    # To hgw (port 3) — VPN path for h2-bound traffic
    install_fwd_entry(p4info_helper, sw,
                      "MyIngress.fwd_vpn", "10.0.2.2", 32,
                      "00:00:00:00:03:03", "00:00:00:00:01:01", 3)
    # To h1 (port 1) — return path via VPN
    install_fwd_entry(p4info_helper, sw,
                      "MyIngress.fwd_vpn", "10.0.1.1", 32,
                      "00:00:00:00:01:01", "00:00:00:00:03:03", 1)
    # To hgw (port 3) — direct to gateway
    install_fwd_entry(p4info_helper, sw,
                      "MyIngress.fwd_vpn", "10.0.3.3", 32,
                      "00:00:00:00:03:03", "00:00:00:00:01:01", 3)


def setup_arp_handling(p4info_helper: P4InfoHelper, sw: Bmv2SwitchConnection) -> None:
    """
    Install ARP handling rules:
    - Rate limiting per port
    - Forwarding based on target IP
    """
    print("[*] Installing ARP handling rules...")
    
    # Add ARP rate limit entries (allow ARP on all ports)
    for port in [1, 2, 3]:
        entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.arp_rate_limit",
            match_fields={"standard_metadata.ingress_port": port},
            action_name="NoAction",
            action_params={},
        )
        sw.WriteTableEntry(entry)
        print(f"[OK] ARP rate limit for port {port} - allowed")
    
    # Add ARP forwarding entries for known hosts
    # For h2 (10.0.2.2) reachable via port 2
    entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.arp_forwarding",
        match_fields={"hdr.arp.target_proto_addr": "10.0.2.2"},
        action_name="MyIngress.arp_forward",
        action_params={"port": 2},
    )
    sw.WriteTableEntry(entry)
    print("[OK] ARP forwarding for 10.0.2.2 -> port 2")
    
    # For hgw (10.0.3.3) reachable via port 3
    entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.arp_forwarding",
        match_fields={"hdr.arp.target_proto_addr": "10.0.3.3"},
        action_name="MyIngress.arp_forward",
        action_params={"port": 3},
    )
    sw.WriteTableEntry(entry)
    print("[OK] ARP forwarding for 10.0.3.3 -> port 3")
    
    # For h1 (10.0.1.1) reachable via port 1
    entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.arp_forwarding",
        match_fields={"hdr.arp.target_proto_addr": "10.0.1.1"},
        action_name="MyIngress.arp_forward",
        action_params={"port": 1},
    )
    sw.WriteTableEntry(entry)
    print("[OK] ARP forwarding for 10.0.1.1 -> port 1")


def add_flow_override_tcp(
    p4info_helper: P4InfoHelper,
    sw: Bmv2SwitchConnection,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    use_vpn: int,
) -> None:
    """
    Installs an exact TCP 5-tuple policy entry in MyIngress.flow_policy:
      set_use_vpn(1) => steer via VPN
      set_use_vpn(0) => force normal path

    Note: Your P4 applies flow_policy only when hdr.tcp.isValid().
    """
    entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.flow_policy",
        match_fields={
            "hdr.ipv4.srcAddr": src_ip,
            "hdr.ipv4.dstAddr": dst_ip,
            "hdr.ipv4.protocol": 6,  # TCP
            "hdr.tcp.srcPort": sport,
            "hdr.tcp.dstPort": dport,
        },
        action_name="MyIngress.set_use_vpn",
        action_params={"v": use_vpn},
    )
    sw.WriteTableEntry(entry)
    print(f"[OK] flow_policy TCP: {src_ip}:{sport} -> {dst_ip}:{dport} use_vpn={use_vpn}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", default="build/Offload.p4info.txt")
    parser.add_argument("--bmv2-json", default="build/Offload.json")
    parser.add_argument("--addr", default="127.0.0.1:50051")
    parser.add_argument("--device-id", type=int, default=0)

    # Optional one-shot flow override
    parser.add_argument("--override-src", default=None, help="override src IP (e.g., 10.0.1.1)")
    parser.add_argument("--override-dst", default=None, help="override dst IP (e.g., 10.0.2.2)")
    parser.add_argument("--override-sport", type=int, default=None, help="override TCP src port")
    parser.add_argument("--override-dport", type=int, default=None, help="override TCP dst port")
    parser.add_argument("--override-use-vpn", type=int, choices=[0, 1], default=None, help="0=normal, 1=vpn")

    # Keep-alive
    parser.add_argument("--keepalive", action="store_true", help="keep running (useful for future dynamic rules)")
    args = parser.parse_args()

    require_file(args.p4info)
    require_file(args.bmv2_json)
    ensure_dir("logs")

    p4info_helper = P4InfoHelper(args.p4info)

    sw = Bmv2SwitchConnection(
        name="s1",
        address=args.addr,
        device_id=args.device_id,
        proto_dump_file="logs/s1-p4runtime-requests.txt",
    )

    try:
        print("[*] MasterArbitrationUpdate...")
        sw.MasterArbitrationUpdate()

        print("[*] Setting pipeline config...")
        sw.SetForwardingPipelineConfig(
            p4info=p4info_helper.p4info,
            bmv2_json_file_path=args.bmv2_json,
        )
        print("[OK] Pipeline set.")

        print("[*] Installing base rules...")
        install_base_rules(p4info_helper, sw)

        print("[*] Installing ARP handling rules...")
        setup_arp_handling(p4info_helper, sw)

        # Optional: install one TCP override rule
        if all(
            v is not None
            for v in (args.override_src, args.override_dst, args.override_sport, args.override_dport, args.override_use_vpn)
        ):
            add_flow_override_tcp(
                p4info_helper,
                sw,
                src_ip=args.override_src,
                dst_ip=args.override_dst,
                sport=args.override_sport,
                dport=args.override_dport,
                use_vpn=args.override_use_vpn,
            )

        print("[DONE] Controller finished installing rules.")

        if args.keepalive:
            print("[*] keepalive enabled; press Ctrl+C to stop.")
            while True:
                time.sleep(2)

        return 0

    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        return 130
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    finally:
        ShutdownAllSwitchConnections()


if __name__ == "__main__":
    raise SystemExit(main())