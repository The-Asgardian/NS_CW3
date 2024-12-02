#include <rte_arp.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include <base.h>
#include <net-config.h>

static int eth_out(struct rte_mbuf *pkt_buf, uint16_t h_proto,
                   struct rte_ether_addr *dst_haddr, uint16_t iplen)
{
    // fill the ethernet header 
    struct rte_ether_hdr *hdr =
        rte_pktmbuf_mtod(pkt_buf, struct rte_ether_hdr *);

    hdr->dst_addr = *dst_haddr;
    memcpy(&hdr->src_addr, local_mac, 6);
    hdr->ether_type = rte_cpu_to_be_16(h_proto);

    // Print the packet 
    // pkt_dump(pkt_buf);

    // enqueue the packet 
    pkt_buf->data_len = iplen + sizeof(struct rte_ether_hdr);
    pkt_buf->pkt_len = pkt_buf->data_len;
    dpdk_out(pkt_buf);

    return 0;
}

static void arp_reply(struct rte_mbuf *pkt, struct rte_arp_hdr *arph)
{
    arph->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

    // fill arp body 
    arph->arp_data.arp_tip = arph->arp_data.arp_sip;
    arph->arp_data.arp_sip = rte_cpu_to_be_32(local_ip);

    arph->arp_data.arp_tha = arph->arp_data.arp_sha;
    memcpy(&arph->arp_data.arp_sha, local_mac, 6);

    eth_out(pkt, RTE_ETHER_TYPE_ARP, &arph->arp_data.arp_tha,
            sizeof(struct rte_arp_hdr));
}

static void arp_in(struct rte_mbuf *pkt)
{
    struct rte_arp_hdr *arph = rte_pktmbuf_mtod_offset(
        pkt, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

    // process only arp for this address 
    if (rte_be_to_cpu_32(arph->arp_data.arp_tip) != local_ip)
        goto OUT;

    switch (rte_be_to_cpu_16(arph->arp_opcode)) {
    case RTE_ARP_OP_REQUEST:
        arp_reply(pkt, arph);
        break;
    default:
        fprintf(stderr, "arp: Received unknown ARP op");
        goto OUT;
    }

    return;

OUT:
    rte_pktmbuf_free(pkt);
    return;
}

static struct rte_ether_addr *get_mac_for_ip(uint32_t ip)
{
    return &mac_addresses[(ip & 0xf) - 1];
}

static uint32_t get_target_ip(uint32_t src_ip, uint16_t src_port, uint16_t dst_port)
{
    // Simple load balancing policy: hash based on 5-tuple
    uint32_t hash = (src_ip ^ src_port ^ dst_port) % 2;
    return targets[hash];
}

static void lb_in(struct rte_mbuf *pkt_buf)
{
    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod_offset(
        pkt_buf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt_buf, struct rte_ether_hdr *);
    struct rte_tcp_hdr *tcph = (struct rte_tcp_hdr *)((unsigned char *)iph + sizeof(struct rte_ipv4_hdr));

    // Check if the packet is coming from the client
    if (iph->src_addr == rte_cpu_to_be_32(0x0A000001)) { // 10.0.0.1
        uint32_t target_ip = get_target_ip(iph->src_addr, tcph->src_port, tcph->dst_port);
        struct rte_ether_addr *target_mac = get_mac_for_ip(target_ip);

        // Update IP and MAC addresses for backend server
        iph->src_addr = rte_cpu_to_be_32(0x0A00000A); // Load balancer IP
        iph->dst_addr = target_ip;

        memcpy(&eth_hdr->src_addr, local_mac, sizeof(struct rte_ether_addr));
        eth_hdr->dst_addr = *target_mac;

        // Recalculate checksums
        tcph->cksum = 0;
        tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);
        iph->hdr_checksum = 0;
        iph->hdr_checksum = rte_ipv4_cksum(iph);

        // Forward the packet to the backend 
        eth_out(pkt_buf, RTE_ETHER_TYPE_IPV4, &eth_hdr->dst_addr, ntohs(iph->total_length));
    } 
    // Packet coming from backend
    else {
        iph->src_addr = rte_cpu_to_be_32(0x0A00000A); // Load balancer IP
        iph->dst_addr = rte_cpu_to_be_32(0x0A000001); // Client IP

        memcpy(&eth_hdr->src_addr, local_mac, sizeof(struct rte_ether_addr));
        eth_hdr->dst_addr = *get_mac_for_ip(rte_cpu_to_be_32(0x0A000001));

        // Recalculate checksums 
        tcph->cksum = 0;
        tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);
        iph->hdr_checksum = 0;
        iph->hdr_checksum = rte_ipv4_cksum(iph);

        // Forward the packet to the client 
        eth_out(pkt_buf, RTE_ETHER_TYPE_IPV4, &eth_hdr->dst_addr, ntohs(iph->total_length));
    }
}

void eth_in(struct rte_mbuf *pkt_buf)
{
    unsigned char *payload = rte_pktmbuf_mtod(pkt_buf, unsigned char *);
    struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)payload;

    if (hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
        arp_in(pkt_buf);
    } else if (hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        lb_in(pkt_buf);
    } else {
        // printf("Unknown ether type: %" PRIu16 "\n",
        //       rte_be_to_cpu_16(hdr->ether_type));
        rte_pktmbuf_free(pkt_buf);
    }
}
