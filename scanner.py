from scapy.all import sniff
from datetime import datetime
from termcolor import colored

# Define protocols
protocols = {
    6: "TCP",
    17: "UDP",
}

def packet_callback(packet):
    try:
        # Check if the packet has an IP layer
        if packet.haslayer("IP"):
            src = packet.getlayer("IP").src
            dest = packet.getlayer("IP").dst
            proto = protocols.get(packet.getlayer("IP").proto, "Other")
            length = len(packet)
            current_time = datetime.now()
            formatted_time = current_time.strftime("%H:%M:%S")

            # Set colors
            colored_time = colored(formatted_time, "cyan")
            colored_proto = colored(proto, "green" if proto == "TCP" else "yellow" if proto == "UDP" else "red")
            colored_ips = colored(f"{src} > {dest}", "magenta")  # Change to pink/magenta
            colored_length = colored(f"Length: {length}", "red")

            # Format the output to ensure alignment
            print(f"{colored_time:<10} {colored_proto:<6} {colored_ips:<45} {colored_length}")

    except Exception as e:
        # Print error messages in red
        print(colored(f"Error processing packet: {e}", "red"))

if __name__ == "__main__":
    print("Listening for packets... Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_callback)
    except KeyboardInterrupt:
        print(colored("\nStopping packet sniffing.", "cyan"))

