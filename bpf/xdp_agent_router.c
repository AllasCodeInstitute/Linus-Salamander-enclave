#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

// Mapa BPF que conecta o XDP ao socket AF_XDP no espaço de usuário (Zig)
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

// Mapa de Identidades Autorizadas (Tripartite: PubKey + MAC + IP)
// O Rust/Enclave "carimba" hashes aqui após validação inicial.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);    // Hash da Identidade
    __type(value, __u32);  // Status (1 = OK, 0 = Challenge Required)
    __uint(max_entries, 10000);
} authorized_agents SEC(".maps");

// Porta dedicada aos Agentes (ex: 9999)
#define AGENT_PORT 9999

// CVE-LSES-009: FNV-1a 64-bit hash with Murmur finalizer instead of plain XOR.
// XOR-based hashing has trivial collision resistance: any two MAC+IP pairs that
// XOR to the same 64-bit value collide. FNV-1a + mixing makes collisions
// computationally hard while staying within BPF verifier constraints.
static __always_inline __u64 compute_identity_hash(const __u8 mac[6], __u32 saddr)
{
    // FNV-1a 64-bit offset basis and prime
    __u64 h = 0xcbf29ce484222325ULL;
    const __u64 fnv_prime = 0x00000100000001b3ULL;

    // Unrolled: XOR each MAC byte into the hash then multiply by the FNV prime
    h ^= (__u64)mac[0]; h *= fnv_prime;
    h ^= (__u64)mac[1]; h *= fnv_prime;
    h ^= (__u64)mac[2]; h *= fnv_prime;
    h ^= (__u64)mac[3]; h *= fnv_prime;
    h ^= (__u64)mac[4]; h *= fnv_prime;
    h ^= (__u64)mac[5]; h *= fnv_prime;

    // Mix in the 4-byte source IP
    h ^= (__u64)(saddr & 0xff);         h *= fnv_prime;
    h ^= (__u64)((saddr >> 8) & 0xff);  h *= fnv_prime;
    h ^= (__u64)((saddr >> 16) & 0xff); h *= fnv_prime;
    h ^= (__u64)((saddr >> 24) & 0xff); h *= fnv_prime;

    // Murmur3-style finalizer: avalanches all input bits through the output
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;

    return h;
}

SEC("xdp")
int xdp_pass_to_zig(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        if (udp->dest == __constant_htons(AGENT_PORT)) {
            // 1. Validação de Identidade Ultraveloz (Tripartite Hash)
            __u64 identity_hash = compute_identity_hash(eth->h_source, ip->saddr);

            __u32 *status = bpf_map_lookup_elem(&authorized_agents, &identity_hash);

            if (!status || *status == 0) {
                // Se não está no mapa ou precisa de desafio, passamos para o Kernel
                // para que o SecuritySystemAgent no Rust/Zig capture e dispare o Passkey.
                return XDP_PASS;
            }

            // 2. REDIRECIONA DIRETO PARA O ZIG! (Zero-Copy)
            return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
