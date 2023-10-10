from nfstream import NFPlugin
import scapy.all as scapy
import logging
import random

class FakeHandshake(NFPlugin):
    def on_init(self, packet, flow):
        pass

    def on_update(self, packet, flow):
        # THRESHOLDS
        DURATION = 4000
        SRC2DST_BYTES = 1000
        DST2SRC_BYTES = 4000
        SRC2DST_PACKETS = 2
        DST2SRC_PACKETS = 4

        def do_handshake():
            src2dst_packets = flow.src2dst_packets >= SRC2DST_PACKETS - 1 
            dst2src_packets = flow.dst2src_packets >= DST2SRC_PACKETS - 1 
            src2dst_bytes = flow.src2dst_bytes >= SRC2DST_BYTES - 54 
            dst2src_bytes = flow.dst2src_bytes >= DST2SRC_BYTES - 54 
            duration = flow.bidirectional_duration_ms >= DURATION - 1
            
            # vlan_id == 777 indicates the flow has "logically" expired
            return ((src2dst_packets + dst2src_packets) + (src2dst_bytes + dst2src_bytes) + duration >= 1) & (flow.vlan_id != 777) 
        
        # ZEEK
        if packet.syn and not packet.ack:
            # NFStream will logically count this packet to the old flow, but this works best 
            # (when expiration is set on packet reception, not sending)
            flow.expiration_id = -1 

        def send_fake_handshake(src_ip, dst_ip, src_port, dst_port, interface, fin_syn):
            print("PERFORMING HANDSHAKE")

            if fin_syn == 'FIN':
                # FIN, ACK packet from A to B
                fin_seq_a = random.randint(0, (2**32) - 1)  
                fin_ack_b = random.randint(0, (2**32) - 1)  
                fin_a = scapy.Ether() / scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port, flags='FA', seq=fin_seq_a, ack=fin_ack_b)
                scapy.sendp(fin_a, iface=interface)

            elif fin_syn == 'SYN':
                # New handshake should start with a new sequence number
                new_syn_seq = 0  

                # SYN packet
                syn = scapy.Ether() / scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port, flags='S', seq=new_syn_seq)
                scapy.sendp(syn, iface=interface)

                # Fake SYN-ACK response
                # syn_ack_seq = new_syn_seq + 1  
                # syn_ack_ack = new_syn_seq + 1
                # syn_ack = scapy.Ether() / scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, flags='SA', seq=syn_ack_seq, ack=syn_ack_ack)
                # scapy.sendp(syn_ack, iface=interface)

                # Fake ACK packet
                # ack_seq = syn_ack_seq + 1  
                # ack_ack = syn_ack_seq + 1
                # ack = scapy.Ether() / scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port, flags='A', seq=ack_seq, ack=ack_ack)
                # scapy.sendp(ack, iface=interface)
                # return new_syn_seq  # Return the new sequence number for future use

            else:
                print('[ERROR] Invalid fin_syn value!')

        if do_handshake():
            # Expiration will be set automatically when sending the handshake, not when sniffing, to avoid errors
            flow.vlan_id = 777 # TODO: temporary solution
            send_fake_handshake(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, self.interface, 'SYN') 

    def on_expire(self, flow):
        print("expired")
