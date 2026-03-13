import argparse
from pathlib import Path
from scapy.all import PcapReader, PcapWriter
from scapy.layers.inet import IP


def load_device_packets(pcap_path, device_ip):
    packets = []
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if src_ip == device_ip or dst_ip == device_ip:
                packets.append(pkt)
    return packets


def split_candidate_bursts(packets, gap_threshold=1.0):
    if not packets:
        return []

    bursts = []
    current_burst = [packets[0]]

    for i in range(1, len(packets)):
        prev_pkt = packets[i - 1]
        curr_pkt = packets[i]
        gap = float(curr_pkt.time) - float(prev_pkt.time)

        if gap > gap_threshold:
            bursts.append(current_burst)
            current_burst = [curr_pkt]
        else:
            current_burst.append(curr_pkt)

    bursts.append(current_burst)
    return bursts


def select_top_5_bursts(bursts):
    indexed_bursts = [(i, burst) for i, burst in enumerate(bursts)]
    indexed_bursts.sort(key=lambda x: len(x[1]), reverse=True)
    top5 = indexed_bursts[:5]
    top5.sort(key=lambda x: x[0])
    return [burst for _, burst in top5]


def rebase_burst_timestamps(burst):
    if not burst:
        return burst

    start_time = float(burst[0].time)
    rebased_packets = []

    for pkt in burst:
        pkt_copy = pkt.copy()
        pkt_copy.time = float(pkt.time) - start_time
        rebased_packets.append(pkt_copy)

    return rebased_packets


def save_bursts_as_pcaps(bursts, output_dir, base_name):
    output_dir.mkdir(parents=True, exist_ok=True)

    for idx, burst in enumerate(bursts, start=1):
        rebased_burst = rebase_burst_timestamps(burst)
        out_file = output_dir / f"{base_name}_burst_{idx}.pcap"
        writer = PcapWriter(str(out_file), append=False, sync=True)
        for pkt in rebased_burst:
            writer.write(pkt)
        writer.close()
        print(f"Saved {out_file} ({len(rebased_burst)} packets)")


def process_single_file(pcap_path, device_ip, output_dir, gap_threshold):
    print(f"\nProcessing: {pcap_path.name}")
    packets = load_device_packets(pcap_path, device_ip)
    print(f"  Device-related packets found: {len(packets)}")

    candidate_bursts = split_candidate_bursts(packets, gap_threshold=gap_threshold)
    candidate_sizes = [len(burst) for burst in candidate_bursts]

    print(f"  Candidate bursts detected: {len(candidate_bursts)}")
    print(f"  Candidate burst sizes: {candidate_sizes}")

    if len(candidate_bursts) < 5:
        print("  Warning: fewer than 5 candidate bursts detected.")
        selected_bursts = candidate_bursts
    else:
        selected_bursts = select_top_5_bursts(candidate_bursts)

    print(f"  Selected bursts kept: {len(selected_bursts)}")
    print(f"  Selected burst sizes: {[len(burst) for burst in selected_bursts]}")

    save_bursts_as_pcaps(selected_bursts, output_dir, pcap_path.stem)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_path")
    parser.add_argument("device_ip")
    parser.add_argument("--output-dir", default="burst_pcaps")
    parser.add_argument("--gap-threshold", type=float, default=1.0)
    args = parser.parse_args()

    input_path = Path(args.input_path)
    output_dir = Path(args.output_dir)

    if input_path.is_file():
        pcap_files = [input_path]
    elif input_path.is_dir():
        pcap_files = sorted(input_path.glob("*.pcap"))
    else:
        raise FileNotFoundError(f"Input path not found: {input_path}")

    if not pcap_files:
        print("No pcap files found.")
        return

    print("Starting burst split...")
    print(f"Input path      : {input_path}")
    print(f"Target device IP: {args.device_ip}")
    print(f"Output dir      : {output_dir}")
    print(f"Gap threshold   : {args.gap_threshold} s")

    for pcap_file in pcap_files:
        process_single_file(
            pcap_path=pcap_file,
            device_ip=args.device_ip,
            output_dir=output_dir,
            gap_threshold=args.gap_threshold,
        )

    print("\nDone.")


if __name__ == "__main__":
    main()
