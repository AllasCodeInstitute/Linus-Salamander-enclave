# LSES — Implementação Técnica Detalhada

> **Linus Salamander Enclave System v0.1.0**  
> Documento de referência interna — todas as decisões técnicas, primitivas criptográficas e mitigações implementadas.

---

## Índice

1. [Filosofia e Objetivos](#1-filosofia-e-objetivos)
2. [Arquitetura em Camadas](#2-arquitetura-em-camadas)
3. [Camada BPF/XDP — Pré-filtragem de Identidade](#3-camada-bpfxdp--pré-filtragem-de-identidade)
4. [Enclave Rust — Motor de Comportamentos](#4-enclave-rust--motor-de-comportamentos)
5. [Motor Criptográfico Zig](#5-motor-criptográfico-zig)
6. [Envelope de Criptografia](#6-envelope-de-criptografia)
7. [Atestação Dual (Ed25519)](#7-atestação-dual-ed25519)
8. [Cadeia de Custódia — Epoch + Hash Chain](#8-cadeia-de-custódia--epoch--hash-chain)
9. [LinearAutoDestroy — RuntimeSecretStore](#9-linearautodestroy--runtimesecretstore)
10. [Gerenciamento de Chaves e Identidade Estável](#10-gerenciamento-de-chaves-e-identidade-estável)
11. [Registro de Chaves Confiáveis (TrustedKeyRegistry)](#11-registro-de-chaves-confiáveis-trustedkeyregistry)
12. [Assinaturas com Escopo — Anti-MIASMA](#12-assinaturas-com-escopo--anti-miasma)
13. [Prova de Posse de Chave — Challenge-Response](#13-prova-de-posse-de-chave--challenge-response)
14. [Integridade da Cadeia de Fornecimento](#14-integridade-da-cadeia-de-fornecimento)
15. [Mitigações por CVE](#15-mitigações-por-cve)
16. [Variáveis de Ambiente](#16-variáveis-de-ambiente)

---

## 1. Filosofia e Objetivos

O LSES é um motor de gerenciamento de segredos criptográficos construído sobre um único princípio central:

> **"Texto em claro só existe em RAM durante janelas de runtime autorizadas e é destruído de forma segura ao término de cada janela."**

Isso é chamado de filosofia **Purge-on-Write**. Diferente de cofres tradicionais (HashiCorp Vault, AWS Secrets Manager) que expõem segredos via API REST e dependem de controles de rede para proteção em trânsito, o LSES:

- Nunca persiste texto em claro — apenas ciphertext AES-256-GCM protegido por AAD
- Nunca expõe segredos via variáveis de ambiente
- Vincula criptograficamente cada snapshot a um par (Enclave, Consumer) via assinaturas Ed25519 independentes
- Impede rollbacks com uma cadeia de hash monotonicamente crescente
- Destrói automaticamente todo material de chave e segredos via `secureZero`

---

## 2. Arquitetura em Camadas

```
┌─────────────────────────────────────────────────────────────┐
│                    Aplicação do Usuário                       │
│              (Go, Rust, Python, TypeScript, Zig)             │
└─────────────────────────┬───────────────────────────────────┘
                          │ FFI / C ABI
┌─────────────────────────▼───────────────────────────────────┐
│              Zig Storage Layer (zig/storage.zig)             │
│  StorageEnclave · buildPendingSnapshot · writeSecret         │
│  readSecret · persistEnvelope · RuntimeSecretStore           │
└─────────────────────────┬───────────────────────────────────┘
                          │ calls
┌─────────────────────────▼───────────────────────────────────┐
│              Zig Crypto Engine (zig/crypto.zig)              │
│  EnclaveCrypto · LocalDevKekProvider · KekProvider           │
│  canonicalizeAad · verifySnapshot · decryptVerifiedSnapshot  │
│  NonceRegistry · TrustedKeyRegistry · AccessPolicy           │
└─────────────────────────┬───────────────────────────────────┘
                          │ include! macro / C ABI
┌─────────────────────────▼───────────────────────────────────┐
│          Rust Enclave (rust/enclave/src/lib.rs)              │
│  QuarkBehaviors via include!() — comportamentos modulares    │
│  init_enclave_keys · generate_agent_key · seal_edge_packet   │
│  open_edge_packet · noise_sign_scoped_payload                │
│  verify_tripartite_identity · mark_replay_and_get_root_seed  │
└─────────────────────────┬───────────────────────────────────┘
                          │ BPF syscall / eBPF map lookup
┌─────────────────────────▼───────────────────────────────────┐
│              BPF/XDP Layer (bpf/xdp_agent_router.c)         │
│  FNV-1a hash identity · authorized_agents map · xsks_map    │
└─────────────────────────────────────────────────────────────┘
```

### QuarkBehaviors

Cada comportamento do Enclave Rust é um arquivo `.rs` autônomo incluído via macro `include!()` em `lib.rs`. Isso permite auditoria isolada de cada comportamento, sem dependências entre eles além das definidas em `lib.rs`.

```
quarkbehaviors/
├── init_enclave_keys/proccess.rs          ← inicializa chaves Ed25519 com OsRng
├── generate_agent_key/proccess.rs         ← HKDF-SHA256 com separação de domínio
├── verify_tripartite_identity/proccess.rs ← challenge-response Ed25519
├── noise_sign_payload/proccess.rs         ← [DEPRECATED] assinatura sem escopo
├── noise_sign_scoped_payload/proccess.rs  ← assinatura com escopo anti-MIASMA
├── seal_edge_packet/proccess.rs           ← AES-256-GCM + nonce aleatório
├── open_edge_packet/proccess.rs           ← AES-256-GCM decryptografado + AAD
├── choreograph_packet/proccess.rs         ← retransposição de chave de aresta
├── mark_replay_and_get_root_seed/proccess.rs ← bitmap de replay + Zeroizing
├── derive_edge_key/proccess.rs            ← HMAC-SHA256 para chave de aresta
└── edge_context_aad/proccess.rs           ← construção do AAD de contexto
```

---

## 3. Camada BPF/XDP — Pré-filtragem de Identidade

**Arquivo**: `bpf/xdp_agent_router.c`

O filtro XDP opera no kernel Linux com latência de nanossegundos, antes que o pacote suba para o espaço do usuário. Ele serve como **pré-filtro grosseiro** — não como autenticação definitiva — eliminando tráfego de origens desconhecidas antes de qualquer custo de processamento.

### Hash de Identidade FNV-1a + Finalizer Murmur3

```c
static __always_inline __u64 compute_identity_hash(const __u8 mac[6], __u32 saddr)
{
    __u64 h = 0xcbf29ce484222325ULL; // FNV offset basis
    const __u64 fnv_prime = 0x00000100000001b3ULL;

    // Unrolled: XOR cada byte MAC no hash, depois multiplica pelo FNV prime
    h ^= (__u64)mac[0]; h *= fnv_prime;
    // ... (6 bytes MAC + 4 bytes IP)

    // Finalizador Murmur3: propaga todos os bits de entrada pela saída
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}
```

**Por que FNV-1a em vez de XOR simples?** O XOR de múltiplos valores de 8 bits é trivialmente colidível — qualquer dois pares `(MAC, IP)` que produzam o mesmo XOR passam pelo filtro. O FNV-1a com finalizer Murmur3 torna colisões computacionalmente dispendiosas sem violar as restrições do verificador BPF (sem loops variáveis, sem chamadas externas).

**Importante**: a autenticação criptográfica real ocorre no `verify_tripartite_identity` na camada Rust. O BPF apenas economiza CPU eliminando tráfego claramente não autorizado.

---

## 4. Enclave Rust — Motor de Comportamentos

### Estado Global Protegido

```rust
struct EnclaveState {
    signing_key: Option<SigningKey>,   // Ed25519 — gerada com OsRng na init
    replay_bitmap: [u64; 1024],        // 65.536 slots de replay
    root_seed: [u8; 32],               // semente para derivação de chaves de aresta
    pqc_sessions: [Option<PQCSession>; 16], // reservado para ML-KEM futuro
}
```

O estado é protegido por um `Mutex<EnclaveState>` dentro de um `OnceLock`, garantindo que:
1. Apenas uma thread acessa o estado por vez
2. O estado é inicializado exatamente uma vez (ver CVE-LSES-004)

### Guard de Inicialização Única

```rust
static ENCLAVE_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub extern "C" fn init_enclave_keys() {
    if ENCLAVE_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return; // silenciosamente ignora reinicializações
    }
    if let Ok(mut guard) = state().lock() {
        guard.signing_key = Some(SigningKey::generate(&mut OsRng));
        guard.replay_bitmap = [0; 1024];
        OsRng.fill_bytes(&mut guard.root_seed); // entropia verdadeira do SO
    }
}
```

**Problema resolvido**: antes desta correção, `init_enclave_keys` era chamável múltiplas vezes, zerando o bitmap de replay a cada chamada e permitindo replay de sessions_ids antigos. O `compare_exchange` atômico garante que apenas a primeira chamada seja efetiva.

### Bitmap de Replay

```rust
fn try_mark_replay(&mut self, session_id: u64) -> bool {
    let index = (session_id % 65536) as usize;
    let word = index / 64;
    let bit  = index % 64;
    let mask = 1u64 << bit;
    if (self.replay_bitmap[word] & mask) != 0 { return false; }
    self.replay_bitmap[word] |= mask;
    true
}
```

O bitmap armazena 65.536 IDs de sessão. IDs são vinculados ao enclave pela derivação HKDF — um session_id só é válido no contexto da instância de enclave que o gerou.

### Derivação de Chave de Agente (HKDF-SHA256)

```rust
// Informação codificada com comprimento prefixado de 4 bytes para evitar ataques de extensão
fn encode_field_len_prefixed(buf: &mut Vec<u8>, field: &[u8]) {
    let len = (field.len() as u32).to_be_bytes();
    buf.extend_from_slice(&len);
    buf.extend_from_slice(field);
}

// Separação de domínio obrigatória
hkdf::Hkdf::<sha2::Sha256>::new(Some(b"LSES-AGENT-KEY-V1\x00"), root_seed)
    .expand(&info_block, &mut okm)
```

**Antes**: SHA-256 direto sobre concatenação — `SHA256(root_seed || name || caps || plane || semantics)` — sem separação de campos, permitindo ataques de extensão de comprimento.  
**Depois**: HKDF com label de domínio + campos prefixados por comprimento, tornando cada agente criptograficamente separado mesmo com nomes similares.

---

## 5. Motor Criptográfico Zig

### CSPRNG Multiplataforma

```zig
pub fn randomBytes(buffer: []u8) void {
    if (builtin.os.tag == .windows) {
        // RtlGenRandom (SystemFunction036) — CSPRNG do Windows
        SystemFunction036(buffer.ptr, @intCast(buffer.len));
    } else {
        std.posix.getrandom(buffer) catch unreachable; // getrandom(2) no Linux
    }
}
```

**Nunca** usa `rand()` da libc, `Math.random()`, ou qualquer PRNG determinístico em código de produção.

### Canonicalização — LSES-CANON-V1

Toda serialização de dados assinados usa um formato canônico determinístico para evitar ambiguidades de parsing:

```
LSES-CANON-V1;campo=<len>:<valor>;campo=hex:<bytes_hex>;campo=u64:<numero>;
```

Exemplo de AAD canonicalizado:
```
project=9:allascode;environment=4:prod;snapshot_type=6:secret;
operation=12:write_secret;epoch=u64:1;
previous_snapshot_hash=hex:0000...0000;
```

Isso elimina ataques de ambiguidade onde dois inputs diferentes produzem a mesma representação serializada.

### NonceRegistry com Limite Superior

```zig
const MAX_NONCE_REGISTRY_SIZE: u32 = 100_000;

pub fn checkAndRecord(self: *NonceRegistry, ...) !void {
    // Fail-closed: nega novos entries quando o registro está cheio
    if (self.seen.count() >= MAX_NONCE_REGISTRY_SIZE) {
        return LsesError.NonceReused;
    }
    // registra nonce...
}
```

O nonce key é `SHA256("LSES-NONCE-KEY-V1" || kind || context || nonce)`, garantindo que nonces do mesmo valor em contextos diferentes sejam tratados independentemente.

### Codificação Hexadecimal Determinística

```zig
// ANTES (bugado): "{x}" para [32]u8 não zero-padding bytes < 0x10
// 0x0a → "a" em vez de "0a" → assinatura com comprimento variável

// DEPOIS: bytesToHex garante sempre 64 chars para 32 bytes
const hex_id = std.fmt.bytesToHex(snapshot_id, .lower);
```

Esta correção eliminou assinaturas com comprimentos incorretos (127, 125 chars em vez de 128) que impediam a verificação.

---

## 6. Envelope de Criptografia

Cada snapshot é protegido por um envelope de dois níveis:

```
┌──────────────────────────────────────────────────────────────┐
│                    SnapshotEnvelope                           │
│                                                              │
│  snapshot_id  = SHA-256(canonical_body)                     │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                  SnapshotBody                         │   │
│  │                                                      │   │
│  │  sealed_payload = AES-256-GCM(                       │   │
│  │      plaintext  = segredos serializados,             │   │
│  │      key        = DEK  (32 bytes aleatórios),        │   │
│  │      nonce      = random 12 bytes,                   │   │
│  │      aad        = canonical_aad(snapshot context)    │   │
│  │  )                                                   │   │
│  │                                                      │   │
│  │  wrapped_dek = AES-256-GCM(                         │   │
│  │      plaintext  = DEK,                               │   │
│  │      key        = KEK  (do blob selado — sealed_state),│   │
│  │      nonce      = random 12 bytes,                   │   │
│  │      aad        = canonical_aad  ← MESMO AAD!        │   │
│  │  )                                                   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  attestations.enclave_signature     = Ed25519(enclave_sk)  │
│  attestations.consumer_countersig   = Ed25519(consumer_sk) │
└──────────────────────────────────────────────────────────────┘
```

### Por que o DEK wrapped usa o mesmo AAD que o payload?

Antes da correção (CVE-LSES-012), o `wrapped_dek` usava apenas `provider.key_id` como AAD. Isso permitia que um DEK válido de um snapshot fosse reutilizado em outro snapshot diferente (mesmo KEK = mesma AAD = autenticação aceita). Ao usar o `canonical_aad` completo — que inclui `project`, `environment`, `epoch`, `previous_snapshot_hash` — o DEK fica criptograficamente vinculado a exatamente um snapshot.

---

## 7. Atestação Dual (Ed25519)

### Input de Assinatura Canônico

```
LSES-SIGNATURE-INPUT-V1;
snapshot_id=<64 chars hex, zero-padded por byte>;
snapshot_body=<len>:<canonical_body>;
```

**Ambos** Enclave e Consumer assinam este mesmo input independentemente:

```zig
const enclave_sig  = try crypto.signEd25519(signature_input, self.enclave_identity.private_key.?);
const consumer_sig = try crypto.signEd25519(signature_input, self.consumer_identity.private_key.?);
```

### Verificação `verify_strict`

Todas as verificações Ed25519 usam `verify_strict` (ed25519-dalek) em vez de `verify`:

- Rejeita pontos de baixa ordem (cofactor attacks)
- Rejeita encodings não-canônicos
- Previne ataques de subgrupo pequeno
- Previne related-key attacks

---

## 8. Cadeia de Custódia — Epoch + Hash Chain

```
Snapshot 1                 Snapshot 2                 Snapshot 3
epoch=1                    epoch=2                    epoch=3
prev_hash=000...0          prev_hash=SHA256(body_1)   prev_hash=SHA256(body_2)
     │                          │                          │
     └──────────────────────────┘──────────────────────────┘
              hash chain monotônica
```

### Proteção contra Rollback

```zig
// CVE-LSES-018: epoch deve ser ESTRITAMENTE maior que o último aceito
if (envelope.snapshot_body.epoch <= ctx.last_accepted_epoch) {
    return LsesError.RollbackDetected;
}
```

Sem esta verificação (antes da correção), um atacante poderia apresentar um snapshot antigo com epoch=1 e ele seria aceito indefinidamente.

### Modo Estrito vs. Recovery Limited

```zig
.mode = if (self.trusted_chain_head != null) .strict else .recovery_limited,
```

- **Strict**: requer que o hash anterior do snapshot seja exatamente o `trusted_chain_head`. Qualquer gap na cadeia → `ChainHeadMismatch`.
- **Recovery Limited**: aceita o primeiro snapshot sem âncora de confiança (apenas para primeiro boot ou recuperação).

---

## 9. LinearAutoDestroy — RuntimeSecretStore

O `LinearAutoDestroy` é o **Semantic Behavior Type (SBT)** central do LSES. Define que todo segredo/token é um recurso linear — acessível exatamente uma vez dentro de uma janela de tempo — e é destruído automaticamente após o uso ou expiração.

```
Segredo em Plaintext
       │
       ▼
  ┌─────────────────────┐
  │   sealPayload()     │  ← AES-256-GCM com DEK efêmero
  └─────────┬───────────┘
            │ ciphertext (em disco/git)
            ▼
  ┌─────────────────────┐
  │  decryptVerified    │  ← verifica tudo (chain, epoch, assinaturas)
  │    Snapshot()       │
  └─────────┬───────────┘
            │ plaintext_decriptografado (RAM apenas)
            ▼
  ┌─────────────────────────────────────────────────────┐
  │          RuntimeSecretStore.insert()                │
  │                                                     │
  │  handle_id = OsRng(32 bytes)  ← token opaco        │
  │  expires_at = now + TTL       ← destruição automática│
  │  consumed = false             ← uso único           │
  └─────────────────────────────────────────────────────┘
            │ RuntimeSecretHandle (apenas o handle_id)
            ▼
  ┌─────────────────────┐
  │  RuntimeSecretStore │  ← único ponto onde plaintext existe
  │  .get(handle_id)    │
  └─────────┬───────────┘
            │ plaintext (por milissegundos, em RAM)
            ▼
  ┌─────────────────────┐
  │   secureZero()      │  ← memória zerada com escrita atômica
  │   consumed = true   │     não otimizável pelo compilador
  └─────────────────────┘
```

### Propriedades do LinearAutoDestroy

| Propriedade | Implementação |
|-------------|---------------|
| **Linear** | `consumed: bool` — o handle só pode ser resolvido uma vez |
| **Auto** | `expires_at: i64` — verificado a cada `get()` sem ação do caller |
| **Destroy** | `secureZero(&secret)` via `std.crypto.secureZero(u8, bytes)` |
| **Opacidade** | O caller recebe apenas `handle_id: [32]u8`, nunca o plaintext |
| **Isolamento** | O plaintext nunca aparece em logs, dumps de stack, ou serialização JSON |

### Por que `secureZero` e não `memset`?

`memset` pode ser otimizado e eliminado pelo compilador quando ele detecta que o buffer não é mais usado (dead-store elimination). `std.crypto.secureZero` usa escrita volátil ou barreiras de memória para garantir que o zero seja efetivamente gravado antes que o ponteiro seja descartado.

No lado Rust, `zeroize::Zeroizing<[u8;32]>` é usado para o `root_seed` — ao ser descartado do stack, o destrutor zero a memória automaticamente.

---

## 10. Gerenciamento de Chaves e Identidade Estável

### Variáveis de Ambiente de Identidade

| Variável | Tipo | Descrição |
|----------|------|-----------|
| `LSES_TRUSTED_ENCLAVE_KEYS` | CSV de 64 hex chars | Chaves públicas de enclaves confiáveis (não-secreta, segura para env) |
| `LSES_STATE_DIR` | path | Diretório do blob selado — padrão: `~/.local/share/lses/` (não-secreta) |

> **KEK, ENCLAVE_SEED e CONSUMER_SEED não existem como variáveis de ambiente.**
> São gerados por `lses bootstrap` via CSPRNG do SO, selados em disco como blob
> AES-256-GCM ligado à identidade desta máquina (`zig/sealed_state.zig`), e
> carregados na memória do processo via `unsealKeys()`. O operador nunca vê os
> valores — apenas a chave pública Ed25519 resultante para registrar em
> `LSES_TRUSTED_ENCLAVE_KEYS`.

### Por que Seeds em vez de Chaves Geradas Aleatoriamente?

Sem seeds, cada restart do processo gera um novo par de chaves. Um worm ou substituto de supply chain que reinicia o processo obtém um par de chaves **novo** — que passa em todas as verificações criptográficas porque o consumidor não tem âncora para comparar.

Com seeds determinísticas:

```zig
const enc_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(enc_seed);
```

O enclave sempre apresenta **a mesma chave pública**. Operadores registram essa chave em `LSES_TRUSTED_ENCLAVE_KEYS` nos consumidores. Um substituto malicioso que gere uma chave diferente é rejeitado imediatamente.

### Primeiro Boot

No primeiro boot sem `LSES_ENCLAVE_SEED`:
```
[LSES SETUP] LSES_ENCLAVE_SEED não configurada. Seed gerada: a3f7c2...
             Defina LSES_ENCLAVE_SEED=a3f7c2... para persistir a identidade.
[LSES] Enclave public key (adicione a LSES_TRUSTED_ENCLAVE_KEYS): 9f2a8b...
```

O operador salva esses valores no gerenciador de segredos e configura nos consumidores. A partir do segundo boot, a identidade é estável e pinável.

---

## 11. Registro de Chaves Confiáveis (TrustedKeyRegistry)

```zig
pub const TrustedKeyRegistry = struct {
    keys: []const [32]u8,

    pub fn isTrusted(self: TrustedKeyRegistry, key: [32]u8) bool {
        for (self.keys) |trusted| {
            if (std.mem.eql(u8, &trusted, &key)) return true;
        }
        return false;
    }
};
```

O `verifySnapshot` verifica o registry no passo 9.5, **após** a verificação de assinatura Ed25519:

```zig
if (ctx.trusted_enclave_keys) |registry| {
    if (!registry.isTrusted(ctx.verification_keys.enclave_public_key)) {
        return LsesError.UnauthorizedConsumer;
    }
}
```

**Fluxo de proteção**: mesmo que um atacante produza um snapshot com assinaturas Ed25519 matematicamente válidas (chave correta para aquela assinatura), se a chave pública não estiver no registry do consumidor, o snapshot é rejeitado. Isso é a segunda camada de autenticação fora de banda.

---

## 12. Assinaturas com Escopo — Anti-MIASMA

### O Problema com Assinaturas Sem Escopo

`noise_sign_payload` (depreciada) assina bytes brutos sem contexto. Um worm que captura a chave de assinatura do agente A pode:
1. Assinar qualquer payload com a chave de A
2. Encaminhar o payload assinado para o agente C, fazendo parecer que veio de A
3. C aceita porque a assinatura é matematicamente válida

### Assinatura com Escopo

```rust
const SCOPED_SIG_DOMAIN: &[u8; 22] = b"LSES-SCOPED-SIG-V1\0\0\0\0";

// Input assinado:
// DOMAIN(22) + signer_pubkey(32) + recipient_pubkey(32) + operation(16) + session_id(8) + SHA256(payload)(32)
//                                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//                                  A assinatura de A para B é inválida em C
```

```rust
pub extern "C" fn noise_sign_scoped_payload(
    payload_ptr: *const u8, len: usize,
    scope: *const ScopedSignatureContext,  // { recipient_pubkey, operation }
    session_id: u64,
    out_sig: *mut u8,
) -> i32 { ... }
```

### Verificação com Escopo

```rust
pub extern "C" fn noise_verify_scoped_signature(...) -> i32 {
    // 1. Verifica que recipient_pubkey == NOSSA chave pública
    let intended_for_us: bool = scope_ref.recipient_pubkey.ct_eq(&our_pubkey).into();
    if !intended_for_us { return ERR_AUTHENTICATION; }

    // 2. Verifica assinatura Ed25519 com verify_strict
    match verifying_key.verify_strict(&signing_input, &signature) {
        Ok(_) => 0,
        Err(_) => ERR_AUTHENTICATION,
    }
}
```

**Resultado**: mesmo que o worm MIASMA capture a chave de A e tente encaminhar uma assinatura de A→B para C, a verificação falha em C porque `recipient_pubkey` não é a chave de C.

### ScopedSignatureContext

```rust
#[repr(C)]
pub struct ScopedSignatureContext {
    pub recipient_pubkey: [u8; 32], // chave pública do destinatário pretendido
    pub operation: [u8; 16],        // ex: b"seal_snapshot\0\0\0"
}
```

O campo `operation` de 16 bytes garante que uma assinatura para `"seal_snapshot"` não possa ser reutilizada para `"route_packet"` — cortando a capacidade do worm de escalar privilégios entre operações.

---

## 13. Prova de Posse de Chave — Challenge-Response

### O Problema com Hash de Identidade

A implementação anterior de `verify_tripartite_identity` computava `SHA-256(pub_key || mac || ip)` e comparava com um hash esperado. Qualquer observador de rede que veja esses três valores (todos visíveis em pacotes IP) pode pré-computar o hash e passar na verificação sem nunca ter a chave privada.

### Challenge-Response

```rust
const IDENTITY_PROOF_DOMAIN: &[u8; 22] = b"LSES-IDENTITY-PROOF-V1";

// Input assinado:
// DOMAIN(22) + challenge(32) + pub_key(32) + mac_addr(6) + ip_addr(4)
//              ^^^^^^^^^^^^^^
//              nonce fresh gerado pelo verificador — não reutilizável

pub extern "C" fn verify_tripartite_identity(
    id: *const TripartiteIdentity,
    challenge: *const u8,    // 32 bytes aleatórios gerados pelo verificador
    response_sig: *const u8, // Ed25519 signature do agente
) -> i32 {
    // ...
    match verifying_key.verify_strict(&signing_input, &signature) { ... }
}
```

**Protocolo**:
1. Verificador gera 32 bytes aleatórios (challenge)
2. Verificador envia challenge ao agente
3. Agente assina com sua chave privada: `sig = Ed25519.sign(privkey, DOMAIN || challenge || pub_key || mac || ip)`
4. Agente devolve `(TripartiteIdentity, sig)`
5. Verificador chama `verify_tripartite_identity(id, challenge, sig)`

**Proteção**: sem a chave privada, é computacionalmente infeasível produzir uma assinatura Ed25519 válida. Um atacante que observa uma verificação anterior não pode reutilizá-la porque o challenge é novo a cada vez.

---

## 14. Integridade da Cadeia de Fornecimento

### `deny.toml` (cargo-deny)

```toml
[advisories]
vulnerability = "deny"   # bloqueia qualquer CVE publicado
yanked = "deny"          # rejeita versões removidas do crates.io

[bans]
multiple-versions = "deny"  # impede 2 versões do mesmo crate (ex: aes-gcm)
wildcards = "deny"          # impede "versão = *" nos Cargo.toml

[sources]
unknown-registry = "deny"   # apenas crates.io
unknown-git = "deny"        # sem git deps (bypass do audit trail)
```

Executar em CI:
```bash
cargo install cargo-deny
cargo deny check
```

### Comprometimento de Dependência → Impacto Limitado

Mesmo que uma dependência (ex: `sha2`) seja comprometida por um supply chain attack:

1. A dependência comprometida não tem acesso à KEK — ela nunca existe fora do blob selado em disco, inacessível a código de dependências em runtime
2. A dependência comprometida não pode regenerar as chaves Ed25519 (fixas pelo `LSES_ENCLAVE_SEED`)
3. Se a dependência enfraquecer o SHA-256, os hashes de snapshot mudariam — a verificação de `snapshot_id` falharia
4. `deny.toml` detecta CVEs publicados antes que a dependência comprometida chegue à produção

---

## 15. Mitigações por CVE

| CVE | Severidade | Vulnerabilidade | Correção |
|-----|-----------|-----------------|---------|
| CVE-LSES-001 | Crítico | `root_seed = "SALAMANDER..."` — constante pública | `OsRng.fill_bytes(&mut root_seed)` |
| CVE-LSES-002 | Crítico | `getrandom` com feature `"js"` em build nativo | `getrandom = { version = "0.2" }` |
| CVE-LSES-003 | Crítico | KEK hardcoded no código-fonte | Sealed state: KEK gerada por CSPRNG, selada em disco, nunca em env var |
| CVE-LSES-004 | Crítico | `init_enclave_keys` resetava bitmap de replay | `AtomicBool ENCLAVE_INITIALIZED` |
| CVE-LSES-005 | Alto | Secret demo triggava regra de detecção | Placeholder sem padrão sensível |
| CVE-LSES-006 | Alto | `choreograph_packet`: XOR sem autenticação | Guarda de invariante + doc de contrato AEAD |
| CVE-LSES-007 | Crítico | PQC stub com `is_quantum_resistant: true` falso | `ERR_NOT_IMPLEMENTED = -10` |
| CVE-LSES-008 | Alto | Comparação de HMAC em tempo variável | `subtle::ConstantTimeEq` |
| CVE-LSES-009 | Alto | Hash de identidade BPF por XOR trivial | FNV-1a + finalizer Murmur3 |
| CVE-LSES-010 | Alto | Derivação de chave por SHA-256 direto | HKDF-SHA256 com label de domínio |
| CVE-LSES-011 | Médio | `deterministicTestBytes` público em prod | Removido `pub` |
| CVE-LSES-012 | Crítico | DEK wrapped com AAD apenas `key_id` | AAD canônico completo em wrap e unwrap |
| CVE-LSES-013 | Alto | Sem bounds check em campos de agente | `AGENT_KEY_MAX_FIELD_LEN = 1024` |
| CVE-LSES-014 | Alto | NonceRegistry crescimento ilimitado | Cap `MAX_NONCE_REGISTRY_SIZE = 100_000` |
| CVE-LSES-015 | Alto | Hex sem zero-padding → assinaturas truncadas | `std.fmt.bytesToHex` |
| CVE-LSES-016 | Médio | `AccessPolicy.allows()` ignorava `operation` | Check de `export_plaintext` |
| CVE-LSES-017 | Médio | `.gitignore` mínimo (2 linhas) | Cobertura completa: `*.sealed.json`, `.env`, etc. |
| CVE-LSES-018 | Crítico | `readSecret` com `last_accepted_epoch = 0` | Propaga `self.last_accepted_epoch` + modo `.strict` |
| CVE-LSES-019 | Alto | `root_seed` retornado como `[u8; 32]` no stack | `Zeroizing<[u8;32]>` — zerado no drop |
| CVE-LSES-020 | Médio | Identidade git hardcoded no código | Removida; usar git config padrão |
| CVE-LSES-021 | Médio | Timestamps hardcoded `"2026-05-18T00:00:00Z"` | `isoTimestamp()` com relógio do sistema |
| CVE-LSES-022 | Baixo | Array `pqc_sessions[16]` só usa índice 0 | Documentado; reservado para ML-KEM futuro |

---

## 16. Variáveis de Ambiente

**Nenhuma variável de ambiente carrega material de chave (KEK, seeds).** Essas
chaves são geradas dentro do processo `lses-bootstrap` e armazenadas em um blob
selado com AES-256-GCM. Apenas a chave pública do enclave (não secreta) precisa
ser configurada nos consumidores.

| Variável | Sensível | Formato | Descrição |
|----------|----------|---------|-----------|
| `LSES_STATE_DIR` | Não | caminho | Diretório do `sealed_state.bin`. Padrão: `~/.local/share/lses/` |
| `LSES_TRUSTED_ENCLAVE_KEYS` | **Não** (chaves públicas) | CSV de 64 hex | Chaves públicas de enclaves autorizados. Saída do bootstrap. |
| `GIT_AUTHOR_NAME` | Não | string | Identidade git para commits de snapshot. |
| `GIT_AUTHOR_EMAIL` | Não | string | Email git para commits de snapshot. |

### Inicialização para Produção

```bash
# 1. Execute o bootstrap UMA VEZ (na máquina de produção, como o usuário do serviço)
LSES_STATE_DIR=/var/lib/lses ./scripts/lses-init.sh

# 2. O bootstrap imprime a chave pública do enclave — copie para os consumidores:
export LSES_TRUSTED_ENCLAVE_KEYS="9f2a8b3c4d5e6f7a8b9c0d1e2f3a4b5c..."

# 3. Inicie o serviço normalmente — sem nenhuma variável de segredo
./zig-out/bin/lses

# NUNCA faça:
# export LSES_KEK="..."           ← não existe mais
# export LSES_ENCLAVE_SEED="..."  ← não existe mais
# export LSES_CONSUMER_SEED="..."  ← não existe mais
```
