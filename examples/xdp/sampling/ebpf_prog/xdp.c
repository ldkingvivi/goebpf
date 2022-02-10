#include "bpf_helpers.h"

#define SAMPLE_SIZE 128ul

struct bpf_map_def SEC("sample_packet") samples = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u32),
        .max_entries = 256,
};


SEC("xdp_sampling")
int xdp_sample_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Metadata will be in the perf event before the packet data. */
    struct S {
        __u16 cookie;
        __u16 pkt_len;
    } __packed metadata;

    if (data < data_end) {
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
        __u16 sample_size;
        int ret;

        metadata.cookie = 0xdddd;
        metadata.pkt_len = (__u16)(data_end - data);
        sample_size = min(metadata.pkt_len, SAMPLE_SIZE);
        flags |= (__u64)sample_size << 32;

        ret = bpf_perf_event_output(ctx, &sample_packet, flags,
                                    &metadata, sizeof(metadata));
        if (ret)
            bpf_printk("perf_event_output failed: %d\n", ret);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";