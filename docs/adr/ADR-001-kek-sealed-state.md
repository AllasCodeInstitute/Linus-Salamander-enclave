# ADR-001: KEK via Sealed State em Disco, sem Variável de Ambiente

**Status:** Aceito  
**Data:** 2026-06-26  
**Autores:** LSES Core Team  
**CVE relacionado:** CVE-LSES-003 (Use of Hard-coded Cryptographic Key)

---

## Contexto

O LSES (Linus Salamander Enclave System) usa um modelo de envelope encryption em duas camadas:

```
plaintext secret
  → cifrado com DEK (Data Encryption Key, gerada por snapshot)
      → DEK cifrada com KEK (Key Encryption Key, persistente)
          → envelope selado em disco
```

A KEK é o material mais sensível do sistema: quem a detém pode desempacotar qualquer DEK e, portanto, qualquer secret armazenado. A questão arquitetural é: **onde a KEK vive?**

### Opções avaliadas

#### Opção 1 — Hardcoded (estado anterior ao CVE-LSES-003)

```zig
// ❌ valor público, idêntico em todo deploy
.kek_provider = try crypto.LocalDevKekProvider.initFromHex(
    "local-dev-kek-001",
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
),
```

Qualquer pessoa com acesso ao código-fonte pode desempacotar todos os DEKs. Trivialmente comprometido. CVSS 9.8.

#### Opção 2 — Variável de Ambiente (mitigation intermediária documentada)

```bash
export LSES_KEK="$(openssl rand -hex 32)"
```

```zig
const kek_hex = std.process.getEnvVarOwned(allocator, "LSES_KEK") catch {
    return error.MissingKekEnvVar;
};
```

Melhor que hardcoded, mas a KEK ainda existe como valor legível em algum lugar: arquivo `.env`, CI/CD secrets, Kubernetes Secret (etcd sem envelope encryption), shell history, logs de processo, output de `printenv`. Um script `postinstall` malicioso, um dump de memória, ou um vazamento de pipeline expõe o valor diretamente.

#### Opção 3 — KMS Externo (HashiCorp Vault, AWS KMS, GCP Cloud KMS)

O processo solicita ao KMS que execute operações de wrap/unwrap. A KEK nunca é exportada — ela vive dentro do HSM/KMS. Requer dependência de rede em runtime, disponibilidade do KMS para operar, e configuração de autenticação (IAM role, Vault token).

Adequado para produção em cloud, mas introduz um ponto de falha externo e latência em cada operação criptográfica.

#### Opção 4 — Hardware Derivation (SGX Sealing Key, TPM PCR)

```c
// Intel SGX: chave derivada do hardware, binding ao MRENCLAVE
sgx_get_key(&KEYREQUEST_SEAL, &seal_key);
```

A KEK é computada pelo hardware a partir do hash do binário do enclave (MRENCLAVE) e da chave de plataforma. Nunca existe como valor armazenado. Requer hardware SGX ou TPM disponível.

#### Opção 5 — Sealed State em Disco (decisão adotada)

```zig
// zig/sealed_state.zig
pub fn bootstrap(allocator: std.mem.Allocator) !void {
    var kek: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &kek);
    std.crypto.random.bytes(&kek); // getrandom(2) / RtlGenRandom — entropia de hardware
    try sealToDisk(allocator, &kek, &enclave_seed, &consumer_seed);
    // saída: APENAS a chave pública Ed25519 — o operador nunca vê a KEK
}

fn sealToDisk(...) !void {
    var seal_key = machineBindingKey(); // SHA-256(machine-id || uid)
    defer std.crypto.secureZero(u8, &seal_key);
    // blob = nonce(12) || AES-256-GCM(kek || enclave_seed || consumer_seed) || tag(16)
    // permissão 0600 — somente o dono pode ler
}
```

```zig
// zig/storage.zig
const sealed = try sealed_state.unsealKeys(allocator);
var sk = sealed;
defer sk.deinit(); // secureZero em kek/seeds após derivação
const kek_provider = crypto.LocalDevKekProvider.initFromBytes("lses-kek", sk.kek);
```

---

## Decisão

**Adotamos a Opção 5 (Sealed State em Disco) como implementação padrão, com caminho de upgrade para Opção 3 (KMS externo) em produção cloud.**

A KEK não existe como variável de ambiente. Não existe em arquivo de configuração. Não existe em CI/CD secrets. Ela é:

1. **Gerada** uma vez por `lses bootstrap` via CSPRNG do SO (getrandom/RtlGenRandom)
2. **Selada** em disco como blob AES-256-GCM ligado à identidade da máquina
3. **Carregada** em RAM pelo processo enclave via `unsealKeys()` a cada boot
4. **Zerada** via `secureZero` após derivação dos pares de chaves Ed25519
5. **Nunca exportada** — o operador recebe apenas a chave pública Ed25519

### Binding à máquina

A chave de selagem é derivada de identidade não-secreta mas específica da máquina:

```zig
fn machineBindingKey() [32]u8 {
    var hasher = Sha256.init(.{});
    hasher.update("LSES-MACHINE-SEAL-V1\x00");
    hasher.update(machine_id);  // /etc/machine-id no Linux
    hasher.update(uid_bytes);   // isolamento por usuário em máquinas compartilhadas
    return hasher.final();
}
```

O blob copiado para outra máquina é inútil: a chave de selagem difere, o AES-GCM falha na autenticação com `SealedStateAuthFailed`.

### Variáveis de ambiente no modelo adotado

| Variável | Tipo | Sensível? | Propósito |
|---|---|---|---|
| `LSES_TRUSTED_ENCLAVE_KEYS` | CSV de hex | Não | Chaves públicas de enclaves registrados |
| `LSES_STATE_DIR` | path | Não | Localização do blob selado (padrão: `~/.local/share/lses/`) |

Nenhuma variável carrega material criptográfico secreto.

---

## Consequências

### Positivas

- **Eliminação da superfície de env var**: scripts `postinstall` maliciosos, dumps de `process.env`, logs de CI/CD e shell history não expõem material de chave
- **Machine binding nativo**: o blob selado é inútil fora da máquina onde foi gerado, sem dependência de HSM externo
- **Zero-knowledge operator**: o operador que provisiona o serviço nunca vê KEK, ENCLAVE_SEED ou CONSUMER_SEED — apenas registra a chave pública
- **Sem dependência de rede em runtime**: operações criptográficas não dependem de disponibilidade de Vault/KMS
- **Compatível com SGX futuro**: a função `sealToDisk` pode ser substituída por `sgx_get_key()` sem mudar a interface `unsealKeys()`

### Negativas / Tradeoffs

- **Perda do blob = perda de acesso**: se o arquivo `sealed_state.bin` for perdido sem backup, todos os snapshots ficam inacessíveis. Mitigação: backup do blob cifrado (permanece cifrado, seguro para armazenar externamente)
- **Rotação de KEK requer re-wrap**: mudar a KEK exige desempacotar e re-empacotar todos os DEKs. Mitigação: operação de manutenção planejada via `lses rotate-kek`
- **Machine binding impede migração trivial**: mover o serviço para nova máquina requer bootstrap novo ou export seguro do blob. Mitigação: `lses export-sealed --dest new-host` com verificação de identidade do destino
- **Não substitui KMS para alta disponibilidade**: em clusters com múltiplos nós, cada nó tem seu próprio blob — não há compartilhamento de KEK. Para esse cenário, a Opção 3 (KMS externo) é mais adequada e este código serve como camada de cache local

### Caminho de upgrade para KMS

O `KekProvider` em `zig/crypto.zig` é uma interface com vtable:

```zig
pub const KekProvider = struct {
    ctx: *anyopaque,
    wrap_fn:   *const fn(...) anyerror!WrappedDek,
    unwrap_fn: *const fn(...) anyerror![32]u8,
};
```

Substituir `LocalDevKekProvider` por um provider que delegue ao AWS KMS, GCP Cloud KMS, ou HashiCorp Vault Transit não altera nenhuma outra camada do sistema. A decisão de usar sealed state não fecha essa porta — ela define o piso de segurança aceitável sem infraestrutura externa.

---

## Alternativas Rejeitadas

### Por que não Opção 2 (env var) permanentemente?

A superfície de ataque de variáveis de ambiente é maior do que parece:

- `postinstall` scripts de dependências comprometidas têm acesso a `process.env` no mesmo processo de instalação
- Kubernetes Secrets são base64 no etcd — sem envelope encryption ativado, qualquer acesso ao etcd expõe o valor
- Shell history guarda o comando `export LSES_KEK=...`
- Logs de diagnóstico de processo frequentemente incluem env vars completas
- O modelo de exfiltração mais comum em supply chain attacks (xz-utils, event-source-polyfill, lodash.js) mira exatamente `process.env`

### Por que não Opção 4 (SGX/TPM) como padrão?

- Requer hardware específico (SGX: Intel Xeon, TPM: chip dedicado)
- Aumenta complexidade de deployment e debugging
- A Opção 5 é funcionalmente equivalente em ambientes sem SGX e se torna o *cache local* quando SGX está disponível

---

## Arquivos afetados

| Arquivo | Papel |
|---|---|
| `zig/sealed_state.zig` | Geração, selagem e leitura do blob |
| `zig/storage.zig` | Consumidor de `unsealKeys()`, provider da KEK |
| `zig/crypto.zig` | Interface `KekProvider` e `LocalDevKekProvider` |
| `zig/bootstrap_main.zig` | Ponto de entrada do comando `lses bootstrap` |
| `docs/MITIGATED-ATTACKS.md` | Documentação de mitigação atualizada |
| `docs/IMPLEMENTATIONpt..md` | Tabela de env vars e CVE-003 atualizados |
| `docs/HOW-TO-USE.md` | Exemplos K8s, Lambda, Go atualizados |
| `SECURITY_VULNERABILITIES.md` | Fix do CVE-LSES-003 atualizado |
