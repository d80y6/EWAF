#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536); // Increased capacity
    __type(key, __u8[16]); // IPv6 address (also fits IPv4-mapped)
    __type(value, __u32);  // Action: 0 = PASS, 1 = DROP
} block_list SEC(".maps");

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        __u8 ip[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0};
        *(__u32 *)&ip[12] = iph->saddr;

        __u32 *action = bpf_map_lookup_elem(&block_list, &ip);
        if (action && *action == 1) {
            return XDP_DROP;
        }
    } else if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        __u32 *action = bpf_map_lookup_elem(&block_list, &ip6h->saddr);
        if (action && *action == 1) {
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
