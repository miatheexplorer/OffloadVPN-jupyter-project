#!/usr/bin/env python3
import argparse
import os
import sys
import time

script_dir = os.path.dirname(os.path.abspath(__file__))
utils_path = os.path.join(script_dir, "utils")
if utils_path not in sys.path:
    sys.path.insert(0, utils_path)
    print(f"[INFO] Added utils path: {utils_path}")

try:
    from p4runtime_lib.bmv2 import Bmv2SwitchConnection
    from p4runtime_lib.switch import ShutdownAllSwitchConnections
    from p4runtime_lib.helper import P4InfoHelper
    print("[INFO] Successfully imported p4runtime_lib")
except ModuleNotFoundError:
    print("[ERROR] Could not import p4runtime_lib", file=sys.stderr)
    sys.exit(1)


def require_file(path: str) -> None:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Required file not found: {path}")


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def install_whitelist(p4info, sw, src, dst):
    entry = p4info.buildTableEntry(
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


def install_fwd_entry(p4info, sw, table, dst_ip, prefix_len, dst_mac, src_mac, port):
    entry = p4info.buildTableEntry(
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
    print(f"[OK] {table}: {dst_ip}/{prefix_len} -> port{port}")


def install_base_rules_vpn_only(p4info, sw):
    install_whitelist(p4info, sw, "10.0.1.1", "10.0.2.2")
    install_whitelist(p4info, sw, "10.0.2.2", "10.0.1.1")
    install_whitelist(p4info, sw, "10.0.1.1", "10.0.3.3")
    install_whitelist(p4info, sw, "10.0.3.3", "10.0.1.1")
    install_whitelist(p4info, sw, "10.0.2.2", "10.0.3.3")
    install_whitelist(p4info, sw, "10.0.3.3", "10.0.2.2")

    # normal path after packet returns from gateway
    install_fwd_entry(
        p4info, sw, "MyIngress.fwd_normal",
        "10.0.2.2", 32,
        "00:00:00:00:02:02", "00:00:00:00:03:03", 2
    )
    install_fwd_entry(
        p4info, sw, "MyIngress.fwd_normal",
        "10.0.1.1", 32,
        "00:00:00:00:01:01", "00:00:00:00:03:03", 1
    )
    install_fwd_entry(
        p4info, sw, "MyIngress.fwd_normal",
        "10.0.3.3", 32,
        "00:00:00:00:03:03", "00:00:00:00:01:01", 3
    )

    # VPN first hop
    install_fwd_entry(
        p4info, sw, "MyIngress.fwd_vpn",
        "10.0.2.2", 32,
        "00:00:00:00:03:03", "00:00:00:00:01:01", 3
    )
    install_fwd_entry(
        p4info, sw, "MyIngress.fwd_vpn",
        "10.0.1.1", 32,
        "00:00:00:00:03:03", "00:00:00:00:02:02", 3
    )
    install_fwd_entry(
        p4info, sw, "MyIngress.fwd_vpn",
        "10.0.3.3", 32,
        "00:00:00:00:03:03", "00:00:00:00:01:01", 3
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", default="build/Offload_VPNOnly.p4info.txt")
    parser.add_argument("--bmv2-json", default="build/Offload_VPNOnly.json/Offload_VPNOnly.json")
    parser.add_argument("--addr", default="127.0.0.1:50051")
    parser.add_argument("--device-id", type=int, default=0)
    parser.add_argument("--keepalive", action="store_true")
    args = parser.parse_args()

    require_file(args.p4info)
    require_file(args.bmv2_json)
    ensure_dir("logs")

    p4info = P4InfoHelper(args.p4info)

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
            p4info=p4info.p4info,
            bmv2_json_file_path=args.bmv2_json,
        )
        print("[OK] Pipeline set.")

        print("[*] Installing VPN-only baseline rules...")
        install_base_rules_vpn_only(p4info, sw)

        print("[DONE] VPN-only controller finished installing rules.")

        if args.keepalive:
            while True:
                time.sleep(2)

        return 0

    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    finally:
        ShutdownAllSwitchConnections()


if __name__ == "__main__":
    raise SystemExit(main())