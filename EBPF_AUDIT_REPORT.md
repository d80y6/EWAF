# eBPF Audit Report - Sentinel WAF

## 1. Logic Verification
- **IPv4 Handling**: Correctly extracts saddr and looks up in the 16-byte map key.
- **IPv6 Handling**: **IMPLEMENTED**. Contrary to some previous reports, `pkg/ebpf/c/xdp_fw.c` contains explicit IPv6 handling:
  ```c
  } else if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {
      struct ipv6hdr *ip6h = (void *)(eth + 1);
      // ... lookup ip6h->saddr ...
  }
  ```
- **Limitation**: Still lacks VLAN (802.1Q) handling. Tagged packets will bypass the IP checks.

## 2. Map Safety
- **Size**: 65,536 entries.
- **Concurrency**: Safe.
- **Verifier**: Simple logic, passes verifier easily.

## 3. Kernel Integration
- **Finding**: The eBPF program requires `CAP_NET_ADMIN` and `CAP_BPF` to load. The provided K8s manifests lack these privileges, meaning eBPF protection will **fail to start** in standard Kubernetes environments.
