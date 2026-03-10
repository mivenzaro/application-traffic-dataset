import os
import csv
from scapy.all import PcapReader


def count_packets_in_pcap(pcap_path):
    count = 0
    try:
        with PcapReader(pcap_path) as packets:
            for _ in packets:
                count += 1
    except Exception as e:
        print(f"Error reading {pcap_path}: {e}")
    return count


def generate_csv_from_pcap_folder(input_folder, output_csv):
    pcap_extensions = (".pcap", ".pcapng", ".cap")

    with open(output_csv, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["pcap name", "count"])

        for file_name in os.listdir(input_folder):
            if file_name.lower().endswith(pcap_extensions):
                full_path = os.path.join(input_folder, file_name)
                packet_count = count_packets_in_pcap(full_path)
                writer.writerow([file_name, packet_count])

    print(f"CSV file created successfully: {output_csv}")


if __name__ == "__main__":
    input_folder = r"."
    output_csv = r"per_packet_count.csv"

    generate_csv_from_pcap_folder(input_folder, output_csv)
