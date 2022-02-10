#include "bpf_helpers.h"

#define SAMPLE_SIZE 128u

BPF_MAP_DEF(sample_packet) = {
        .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u32),
        .max_entries = 256,
};
BPF_MAP_ADD(sample_packet);


SEC("xdp/sampling")
int xdp_sample_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (data < data_end) {

        /* Metadata will be in the perf event before the packet data. */
        struct {
            __u16 cookie;
            __u16 pkt_len;
        }  metadata;

        /* The XDP perf_event_output handler will use the upper 32 bits
         * of the flags argument as a number of bytes to include of the
         * packet payload in the event data. If the size is too big, the
         * call to bpf_perf_event_output will fail and return -EFAULT.
         *
         * See bpf_xdp_event_output in net/core/filter.c.
         *
         * The BPF_F_CURRENT_CPU flag means that the event output fd
         * will be indexed by the CPU number in the event map.
         */
        __u64 flags = BPF_F_CURRENT_CPU;

        metadata.cookie = 0xdddd;
        metadata.pkt_len = (__u16)(data_end - data);
        __u16 sample_size = metadata.pkt_len > SAMPLE_SIZE ? SAMPLE_SIZE : metadata.pkt_len;
        flags |= (__u64)sample_size << 32;

        int ret = bpf_perf_event_output(ctx, &sample_packet, flags, &metadata, sizeof(metadata));
        if (ret)
            bpf_printk("perf_event_output failed: %d\n", ret);
    }

    /* pass for now, need to add the tail call later */
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";