#include "bpf_helpers.h"

#define SAMPLE_SIZE 128ul

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
} sample_packet SEC(".maps");


SEC("xdp_sampling")
int xdp_sample_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Metadata will be in the perf event before the packet data. */
    struct S {
        u16 cookie;
        u16 pkt_len;
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
        u64 flags = BPF_F_CURRENT_CPU;
        u16 sample_size;
        int ret;

        metadata.cookie = 0xdddd;
        metadata.pkt_len = (u16)(data_end - data);
        sample_size = min(metadata.pkt_len, SAMPLE_SIZE);
        flags |= (u64)sample_size << 32;

        ret = bpf_perf_event_output(ctx, &sample_packet, flags,
                                    &metadata, sizeof(metadata));
        if (ret)
            bpf_printk("perf_event_output failed: %d\n", ret);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";