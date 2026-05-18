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
            // Simulação simplificada: Hash(MAC + IP)
            __u64 identity_hash = 0;
            // Combina os 6 bytes do MAC com os 4 bytes do IP para um hash rápido
            for(int i=0; i<6; i++) identity_hash ^= ((__u64)eth->h_source[i] << (i*8));
            identity_hash ^= ((__u64)ip->saddr << 32);

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
