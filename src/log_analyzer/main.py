import sys
from pathlib import Path
from collections import Counter, defaultdict
import csv

TOP_N_DEFAULT = 10

def parse_dhcp_line(line: str) -> dict | None:
    parts = line.split()
    if len(parts) < 10:
        return None
    return {
        "ts": parts[0],
        "uid": parts[1],
        "orig_h": parts[2],
        "orig_p": parts[3],
        "resp_h": parts[4],
        "resp_p": parts[5],
        "mac": parts[6],
        "assigned_ip": parts[7],
        "lease_time": parts[8],
        "trans_id": parts[9],
    }

def write_counter_csv(path: Path, header_a: str, header_b: str, rows) -> None:
    # "w" overwrites existing files
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([header_a, header_b])
        w.writerows(rows)

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python main.py <logfile>")
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"Error: file not found: {log_path}")
        sys.exit(1)

    total_lines = 0
    preview: list[str] = []

    mac_counts = Counter()
    ip_counts = Counter()
    assignment_counts = Counter()

    mac_to_ips = defaultdict(set)
    ip_to_macs = defaultdict(set)

    bad_lines = 0

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue

            total_lines += 1
            if len(preview) < 5:
                preview.append(line)

            row = parse_dhcp_line(line)
            if row is None:
                bad_lines += 1
                continue

            mac = row["mac"]
            assigned_ip = row["assigned_ip"]
            orig_h = row["orig_h"]

            mac_counts[mac] += 1
            ip_counts[assigned_ip] += 1
            assignment_counts[(orig_h, assigned_ip)] += 1

            mac_to_ips[mac].add(assigned_ip)
            ip_to_macs[assigned_ip].add(mac)

    # ---- Console output (Top 10 only) ----
    print("Preview (first 5 lines):")
    for pl in preview:
        print(pl)

    unique_macs = len(mac_counts)
    unique_ips = len(ip_counts)

    print(f"\nTotal lines read: {total_lines}")
    print(f"Unparsed/short lines: {bad_lines}")
    print(f"Unique MAC addresses: {unique_macs}")
    print(f"Unique assigned IPs: {unique_ips}")

    mac_ip_variety = sorted(
        ((mac, len(ips)) for mac, ips in mac_to_ips.items()),
        key=lambda x: x[1],
        reverse=True
    )
    ip_mac_variety = sorted(
        ((ip, len(macs)) for ip, macs in ip_to_macs.items()),
        key=lambda x: x[1],
        reverse=True
    )

    stable = sum(1 for _, n in mac_ip_variety if n == 1)
    churny = sum(1 for _, n in mac_ip_variety if n > 1)

    print("\nLease stability summary:")
    print(f"Stable devices (1 IP): {stable}")
    print(f"Churny devices (>1 IP): {churny}")

    print(f"\nTop {TOP_N_DEFAULT} MAC addresses (most DHCP events):")
    for mac, cnt in mac_counts.most_common(TOP_N_DEFAULT):
        print(f"{mac}: {cnt}")

    print(f"\nTop {TOP_N_DEFAULT} assigned IPs (most leases/events):")
    for ip, cnt in ip_counts.most_common(TOP_N_DEFAULT):
        print(f"{ip}: {cnt}")

    print(f"\nTop {TOP_N_DEFAULT} assignments (orig_h -> assigned_ip):")
    for (orig_h, ip), cnt in assignment_counts.most_common(TOP_N_DEFAULT):
        print(f"{orig_h} -> {ip}: {cnt}")

    print(f"\nTop {TOP_N_DEFAULT} MACs by number of different IPs received (possible churn):")
    for mac, n in mac_ip_variety[:TOP_N_DEFAULT]:
        print(f"{mac}: {n} unique IPs")

    print(f"\nTop {TOP_N_DEFAULT} IPs by number of different MACs seen (possible conflict/spoofing):")
    for ip, n in ip_mac_variety[:TOP_N_DEFAULT]:
        print(f"{ip}: {n} unique MACs")

    # ---- CSV export (ALL rows) ----
    out_dir = Path.cwd() / "data"
    out_dir.mkdir(exist_ok=True)

    mac_csv = out_dir / "dhcp_top_macs.csv"
    ip_csv = out_dir / "dhcp_top_ips.csv"
    churn_csv = out_dir / "dhcp_mac_ip_variety.csv"

    write_counter_csv(mac_csv, "mac", "dhcp_events", mac_counts.most_common())
    write_counter_csv(ip_csv, "assigned_ip", "dhcp_events", ip_counts.most_common())
    write_counter_csv(
        churn_csv,
        "mac",
        "unique_ips_received",
        sorted(mac_ip_variety, key=lambda x: x[1], reverse=True)
    )

    print("\nCSV files written (overwritten if existed):")
    print(f"- {mac_csv}")
    print(f"- {ip_csv}")
    print(f"- {churn_csv}")

if __name__ == "__main__":
    main()
