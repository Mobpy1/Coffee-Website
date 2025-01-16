from scapy.all import IP, TCP, Raw, send

# Server details
server_ip = "81.100.22.102"
server_port = 25565

# Chat payload (protocol 0x03)
payload_data = b"\x03\x00\x12/Hello from Scapy!"  # Example chat packet

# Craft packet
packet = IP(dst=server_ip)/TCP(dport=server_port)/Raw(load=payload_data)

# Send packet
send(packet)
print("Chat packet sent!")
