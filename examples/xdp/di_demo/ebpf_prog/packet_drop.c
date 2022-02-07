
#include "bpf_helpers.h"

// Ethernet header
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));


// eBPF map to store XDP decision
// max entry to 2 since we only use XDP_PASS and XDP_DROP
BPF_MAP_DEF(packets_action_count) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 2,
};
BPF_MAP_ADD(packets_action_count);


// eBPF map to store deny_ip_list
// max entry to 1024 for demo, limit is u32, which is 4,294,967,295
BPF_MAP_DEF(deny_ip_list) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};
BPF_MAP_ADD(deny_ip_list);


static __always_inline enum xdp_action report_action(u32 action)
{
    __u64 *count = bpf_map_lookup_elem(&packets_action_count, &action);
    if (count){
        (*count)++;
    }

    return action;
}

SEC("xdp")
int packet_drop(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

    // for demo, only do ipv4
	struct ethhdr *ether = data;
	if (data + sizeof(*ether) > data_end) {
        return XDP_ABORTED;
    }

    if (ether->h_proto != 0x08U) {  // htons(ETH_P_IP) -> 0x08U
        // Non IPv4 traffic
        return XDP_PASS;
    }

    data += sizeof(*ether);
    struct iphdr *ip = data;
    if (data + sizeof(*ip) > data_end) {
        // Malformed IPv4 header
        return XDP_ABORTED;
    }

    struct {
        __u32 prefixlen;
        __u32 saddr;
    } key;

    key.prefixlen = 32;
    key.saddr = ip->saddr;

    __u32 *deny = bpf_map_lookup_elem(&deny_ip_list, &key);
    if (deny) {
        report_action(XDP_DROP);
        return XDP_DROP;
    }

    report_action(XDP_PASS);
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";