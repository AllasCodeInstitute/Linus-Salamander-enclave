# LSES — Ataques Mitigados e Análise de Ameaças

> **Linus Salamander Enclave System v0.1.0**  
> Todos os segredos gerenciados pelo LSES são do Semantic Behavior Type **LinearAutoDestroy (LAD)** — nenhum segredo permanece na RAM após o consumo, nenhum token é reutilizável.

---

## O Semantic Behavior Type LinearAutoDestroy (LAD)

### Definição Formal

Um segredo classificado como **LinearAutoDestroy** obedece ao seguinte contrato:

```
LAD(S) := ∀ segredo S gerenciado pelo LSES:
  1. S existe em plaintext APENAS dentro de uma RuntimeSecretHandle
  2. A handle só pode ser resolvida (consumida) UMA vez
  3. Após o consumo (ou expiração do TTL), secureZero(S) é chamado
  4. Nenhuma cópia de S é armazenada em log, variável de ambiente,
     arquivo, banco de dados, ou qualquer memória não-zerável
  5. O caller nunca recebe S diretamente — apenas recebe a handle opaca
```

### Por que "Linear"?

O termo vem da teoria dos tipos lineares: um recurso linear só pode ser usado exatamente uma vez. Uma vez consumido, é **destruído** — não retornado, não reusado.

```
Recursos normais:   copy(S) = [S, S, S...]   ← copiável infinitamente
Recursos lineares:  use(S)  = (result, ⊘)     ← S deixa de existir após uso
```

### Implicações Práticas

| Comportamento | Sistema Tradicional | LSES + LAD |
|---------------|--------------------|-----------| 
| Token vazado em log | Compromisso imediato | Token já consumido — inútil |
| Dump de memória | Revela todos os secrets | Apenas handles opacas — 32 bytes aleatórios sem valor |
| Variável de ambiente exposta | Compromisso de todos os serviços | Não aplicável — secrets não ficam em env vars |
| Secret em repositório git | Compromisso histórico | Secret cifrado por KEK + AAD + assinaturas |
| MITM entre serviços | Intercepção do token | Token é single-use — replay falha |
| Sessão comprometida | Acesso contínuo até rotação | Acesso encerrado no fim do TTL |

---

## Parte 1 — Categorias de Ataques Gerais Mitigados

### 1.1 Ataques de Roubo de Credenciais

#### Credential Stuffing
**Ataque**: Usar credenciais vazadas de um serviço para autenticar em outro.  
**Por que não funciona com LSES**: Credenciais gerenciadas pelo LSES são tokens de uso único. Mesmo que um token seja interceptado durante o uso, já estará marcado como consumido — um segundo uso produz `ERR_REPLAY`. O bitmap de replay no enclave Rust previne qualquer tentativa de reutilização dentro de uma sessão ativa.

#### Credential Exposure via Logs
**Ataque**: Developer ou sistema de logging captura o valor de uma variável de ambiente que contém um API key.  
**Por que não funciona com LSES**: O LSES nunca expõe plaintext em variáveis de ambiente ou logs. O que é passado entre componentes é sempre um `RuntimeSecretHandle` — uma array de 32 bytes aleatórios que não tem valor sem acesso ao `RuntimeSecretStore`. Mesmo que o log capture essa handle, o `consumed = true` já foi setado no momento do uso.

#### Memory Scraping / Cold Boot Attack
**Ataque**: Atacante lê a RAM do processo (via ptrace, /proc/mem, VM snapshot) para extrair credenciais.  
**Por que não funciona com LSES**: O segredo em plaintext existe em RAM apenas durante o ciclo `get(handle)` → `secureZero()`. O window de exposição é de microssegundos. Em contrapartida, sistemas tradicionais armazenam tokens em variáveis `string` pelo tempo de vida do processo (horas, dias). Após o `secureZero`, a memória zerada não contém padrões distinguíveis de dados válidos.

### 1.2 Ataques de Replay

#### Session Replay
**Ataque**: Capturar uma sessão autenticada e reproduzi-la para ganhar acesso.  
**Mitigação**: Bitmap de replay com 65.536 slots. Cada `session_id` é marcado permanentemente — uma segunda apresentação do mesmo ID retorna `ERR_REPLAY`.

#### Signed Packet Replay
**Ataque**: Capturar um pacote de aresta autenticado e reenviá-lo.  
**Mitigação**: O `choreograph_packet` inclui `sequence` no AAD do AEAD. Um pacote com o mesmo `sequence` em um contexto diferente é rejeitado como replay.

### 1.3 Ataques de Rollback

#### Snapshot Rollback
**Ataque**: Apresentar um snapshot antigo (com secrets anteriores) para sobrepor o estado atual.  
**Mitigação (CVE-LSES-018)**: `last_accepted_epoch` é propagado para o `VerificationContext`. Qualquer snapshot com `epoch ≤ last_accepted_epoch` é rejeitado com `LsesError.RollbackDetected`. A cadeia de hash (`previous_snapshot_hash`) garante que mesmo um epoch correto com hash incorreto seja rejeitado.

#### Key Material Downgrade
**Ataque**: Forçar um sistema a usar chaves mais fracas (ex: RSA-1024 em vez de RSA-4096).  
**Mitigação**: O LSES não possui modos de fallback de algoritmo. Ed25519, AES-256-GCM, HKDF-SHA256 são fixos — não há configuração de suite criptográfica.

### 1.4 Ataques Man-in-the-Middle

#### Token Interception
**Ataque**: MITM captura o token JWT/API key enquanto trafega entre serviços.  
**Mitigação**: Os tokens gerenciados pelo LSES são single-use (LAD). O primeiro uso pelo destinatário legítimo marca o token como `consumed`. A tentativa do atacante de usar o token capturado falha.

#### Key Exchange Compromise
**Ataque**: Atacante substitui uma chave pública durante o setup inicial.  
**Mitigação**: As chaves públicas do enclave são derivadas deterministicamente de seeds estáveis (`LSES_ENCLAVE_SEED`). A chave pública é fixada em `LSES_TRUSTED_ENCLAVE_KEYS` no consumidor. Qualquer chave pública diferente da pinada é rejeitada no passo 9.5 de `verifySnapshot`.

### 1.5 Ataques de Impersonação

#### Impersonação de Agente Autenticado (MIASMA WORM)
**Ataque**: Um agente comprometido captura chaves de assinatura e as usa para se passar por outros agentes confiáveis, propagando-se pela rede.  
**Mitigação**: `noise_sign_scoped_payload` vincula cada assinatura ao par (signer, recipient, operation). `noise_verify_scoped_signature` verifica que `recipient_pubkey == nossa chave pública` antes de aceitar. Uma assinatura gerada para o agente A não pode ser apresentada ao agente B — campos de escopo incompatíveis.

#### Impersonação via Hash de Identidade Observado
**Ataque**: Observar o triplo (pubkey, MAC, IP) em rede e pré-computar o hash para passar na verificação.  
**Mitigação (CVE-LSES-IDENTITY)**: `verify_tripartite_identity` agora usa challenge-response Ed25519. O verificador gera 32 bytes aleatórios novos a cada verificação. Sem a chave privada, é computacionalmente infeasível produzir uma assinatura válida.

### 1.6 Ataques a Código-Fonte

#### Secret em Repositório Git
**Ataque**: Commitar uma API key, senha, ou chave privada em repositório público ou privado.  
**Mitigação direta**: `.gitignore` abrangente bloqueia `*.key`, `*.pem`, `*.seed`, `*.secret`, `.env*`, `*.sealed.json`.  
**Mitigação sistêmica**: Secrets no LSES são sempre armazenados como envelopes AES-256-GCM com AAD que inclui contexto do projeto. Mesmo que o ciphertext seja exposto, ele é inútil sem a KEK — que nunca existe fora do processo enclave.

#### Secret Hardcoded
**Ataque**: Developer deixa um valor hardcoded para teste e ele chega à produção.  
**Mitigação**: A KEK **não existe em nenhum lugar externo** — nem em variável de ambiente, nem em arquivo de configuração, nem em segredos de CI/CD. Ela é gerada via `bootstrap` com `std.crypto.random` (getrandom/RtlGenRandom), selada em disco como blob AES-256-GCM ligado à identidade da máquina (`zig/sealed_state.zig`), e carregada na memória do processo enclave via `unsealKeys()` a cada inicialização. O operador nunca vê o valor — a única saída do bootstrap é a chave pública Ed25519 para registro. Não existe valor padrão, fallback, nem caminho de env var.

---

## Parte 2 — Ataques Recentes de Supply Chain

Os ataques abaixo são incidentes reais ocorridos no npm e GitHub. Cada um é analisado na perspectiva de um projeto que usa o LSES para gerenciar todos os tokens.

### 2.1 Sequestro do Pacote `event-source-polyfill` (2024)

**O que aconteceu**: Mantenedor teve conta npm comprometida. Atacante publicou versão maliciosa que exfiltrava variáveis de ambiente para servidor externo.

**Por que não funciona com LSES**:  
- Tokens não estão em variáveis de ambiente — o segredo está no `RuntimeSecretStore`, inacessível a código de dependências
- `deny.toml` com `multiple-versions = "deny"` e monitoramento de CVEs detectaria a versão maliciosa antes do deploy
- Mesmo que o código malicioso seja executado, ele só tem acesso a handles opacas — não aos valores em plaintext

### 2.2 Typosquatting do `lodash` — `lodash.js` malicioso

**O que aconteceu**: Pacote `lodash.js` (com ponto) no npm continha código de mineração de crypto e exfiltração de tokens de CI do `process.env`.

**Por que não funciona com LSES**:  
- `LSES_TRUSTED_ENCLAVE_KEYS` exige que o enclave que assinou o snapshot seja um enclave conhecido. Um enclave malicioso com nova chave é rejeitado
- `deny.toml` com `unknown-registry = "deny"` bloqueia qualquer dependência fora do crates.io
- Tokens não estão em `process.env` — exfiltração de variáveis de ambiente é inócua

### 2.3 Ataque ao `xz-utils` / `liblzma` (CVE-2024-3094)

**O que aconteceu**: Contribuidor malicioso (Jia Tan, ~2 anos de atividade) inseriu backdoor no processo de build do `xz-utils`, injetando código que comprometia o OpenSSH em sistemas Linux via `systemd`.

**Por que não funciona com LSES**:  
- O LSES usa `deny.toml` com `unknown-git = "deny"` — dependências de repositórios git arbitrários são bloqueadas
- Nenhum binário de build (autoconf, M4) é parte do codebase Zig — o build é determinístico via `build.zig`
- `cargo deny check advisories` detecta CVEs publicados antes que a versão comprometida chegue ao deploy
- As chaves de identidade do LSES são derivadas de seeds no blob selado — um backdoor que tenta extrair a KEK encontra apenas o blob cifrado em disco (AES-256-GCM + machine binding), e ainda precisaria produzir um envelope com AAD correto, epoch correto, e assinatura Ed25519 de um enclave registrado

### 2.4 Sequestro do `polyfill.io` (2024)

**O que aconteceu**: Domínio `polyfill.io` foi adquirido por entidade chinesa e o CDN passou a servir JavaScript malicioso para 100.000+ websites.

**Por que não funciona com LSES**:  
- LSES não usa CDNs para nenhuma dependência
- Dependências Rust são resolvidas exclusivamente via crates.io com checksums SHA-256 no `Cargo.lock`
- `unknown-registry = "deny"` bloqueia qualquer fonte alternativa

### 2.5 Vazamento de Token GitHub Actions (`GITHUB_TOKEN`)

**O que aconteceu**: Múltiplos projetos tiveram `GITHUB_TOKEN` e tokens de deploy expostos em logs de CI, workflows maliciosos, ou pull requests de contribuidores não confiáveis.

**Por que não funciona com LSES**:  
- Tokens gerenciados como LAD são single-use e TTL-bounded. Um token capturado de um log já foi consumido
- O LSES não injeta tokens diretamente em variáveis de ambiente — apenas handles opacas
- Workflows que precisam de tokens recebem uma `RuntimeSecretHandle` que expira após uso único

### 2.6 Comprometimento do `colors.js` e `faker.js` (2022)

**O que aconteceu**: Mantenedor Aaron Swartz deliberadamente inseriu loop infinito nas versões mais recentes para protestar contra uso corporativo.

**Por que não funciona com LSES**:  
- `deny.toml` com `wildcards = "deny"` impede `version = "*"` — o Cargo.lock fixa versões exatas
- `multiple-versions = "deny"` detecta quando um update tenta introduzir uma nova versão de um crate existente
- PRs que atualizam dependências passam por `cargo deny check` como gate de CI

### 2.7 Ataque `node_modules` com `__proto__` / Prototype Pollution

**O que aconteceu**: Pacotes como `minimist`, `merge`, `lodash` tinham vulnerabilidades de prototype pollution que permitiam modificar comportamento global de objetos JavaScript.

**Por que não funciona com LSES**:  
- LSES usa Rust e Zig — ambas linguagens compiladas sem prototype chain
- Acesso ao `RuntimeSecretStore` é por handle opaca validada com `subtle::ConstantTimeEq`
- Não existe superfície de injeção via parsing de objetos genéricos

### 2.8 Sequestro de GitHub Actions com `@v1` / Referências Mutáveis

**O que aconteceu**: Actions referenciadas por tag mutável (ex: `actions/checkout@v3`) podiam ser substituídas pelo mantenedor do repositório original com código malicioso.

**Por que não funciona com LSES**:  
- O ecossistema de build do LSES não depende de GitHub Actions para produzir os binários de enclave
- Qualquer novo snapshot precisa de assinatura Ed25519 de um enclave registrado — um binário malicioso com nova chave não passa na `TrustedKeyRegistry`

### 2.9 NPM Token Exfiltration via `install` Script

**O que aconteceu**: Pacotes com `postinstall` scripts extraíam `NPM_TOKEN`, `AWS_ACCESS_KEY`, e outras variáveis de CI durante a instalação.

**Por que não funciona com LSES**:  
- Tokens não ficam em variáveis de ambiente no modelo LAD
- Handles opacas exfiltradas são inúteis sem o `RuntimeSecretStore` local
- Nenhuma variável de ambiente sensível está presente — KEK/seeds vivem apenas no blob selado em disco, inacessível a scripts de instalação

### 2.10 GitHub Token Sprawl em `.env` Files Commitados

**O que aconteceu**: Pesquisas mostram que dezenas de milhares de repositórios GitHub contêm arquivos `.env` com credenciais reais, muitas vezes em projetos privados que se tornaram públicos por acidente.

**Por que não funciona com LSES**:  
- `.gitignore` abrangente: `.env`, `.env.*`, `.env.local`, `.env.production` são explicitamente ignorados
- Nenhum valor sensível existe em `.env` — KEK/seeds nunca passam por variáveis de ambiente; o único valor em `.env` seria `LSES_TRUSTED_ENCLAVE_KEYS` (chave pública, não-secreta)

---

## Parte 3 — Ataques Criptográficos

### 3.1 Length Extension Attack

**Ataque**: Em funções hash do tipo Merkle-Damgård (MD5, SHA-1, SHA-256), é possível estender uma mensagem sem conhecer o segredo, se a hash original for conhecida.

**Mitigação**: O LSES não usa `SHA256(key || message)` em nenhum lugar. Usa HKDF-SHA256 (com salt e info), HMAC-SHA256 (immune a length extension por definição), e AES-256-GCM (cipher autenticado). O `generate_agent_key` usa HKDF com campos prefixados por comprimento.

### 3.2 Nonce Reuse em AES-GCM

**Ataque**: Reutilizar o mesmo nonce com a mesma chave em AES-GCM revela o plaintext XOR entre as duas mensagens e compromete a autenticidade.

**Mitigação**: Todo nonce no LSES é gerado via CSPRNG (`randomBytes` → `getrandom(2)` ou `RtlGenRandom`). O `NonceRegistry` rastreia todos os nonces usados e rejeita duplicatas com cap de 100.000 entradas.

### 3.3 Birthday Attack em Nonces de 96 bits

**Ataque**: Com nonces aleatórios de 96 bits, a probabilidade de colisão atinge ~50% após ~2^48 mensagens com a mesma chave (birthday bound).

**Mitigação**: Cada snapshot tem seu próprio DEK efêmero gerado aleatoriamente. Mesmo que dois snapshots compartilhem o mesmo KEK, eles jamais compartilham o DEK. O DEK criptografa exatamente um payload.

### 3.4 Related-Key Attack em Ed25519

**Ataque**: Certas implementações de Ed25519 são vulneráveis a ataques onde chaves relacionadas permitem forjar assinaturas.

**Mitigação**: O LSES usa `verify_strict` (ed25519-dalek) que rejeita pontos de baixa ordem, encodings não-canônicos, e é resistente a related-key attacks. A geração de chaves usa `OsRng` (Rust) ou `LSES_ENCLAVE_SEED` via `generateDeterministic` (Zig).

### 3.5 Weak Hash Identity (XOR Collision)

**Ataque (CVE-LSES-009)**: A função de hash de identidade BPF era `XOR(mac[0..5], ip)` — trivialmente colidível. Qualquer par `(MAC, IP)` que produza o mesmo XOR passa no filtro.

**Mitigação**: Substituída por FNV-1a com finalizer Murmur3 — probabilidade de colisão acidental é ~2^{-64}, e colisão intencional requer inverter a função não-linear.

### 3.6 Timing Side-Channel em HMAC

**Ataque (CVE-LSES-008)**: Comparação de HMAC com `==` em Rust vaza timing information — loops que retornam false mais cedo ao encontrar o primeiro byte diferente permitem ataques de oráculo de timing.

**Mitigação**: `subtle::ConstantTimeEq::ct_eq()` — executa em tempo constante independente do conteúdo, eliminando o sinal de timing.

---

## Parte 4 — Ataques Específicos ao Modelo de Agentes de IA

### 4.1 MIASMA WORM

**Definição**: Um agente de IA comprometido que usa chaves de assinatura capturadas para propagar instruções maliciosas pela rede de agentes, se passando por agentes legítimos.

**Vetor de ataque**:
```
Agente A (legítimo) → compromisso → captura signing_key
Agente X (worm) usa signing_key de A para assinar payload
Agente B recebe payload "de A" → aceita
Agente B → compromisso → captura signing_key de B
...
```

**Por que não funciona com LSES**:
1. `noise_sign_scoped_payload` vincula `recipient_pubkey` ao destinatário correto
2. `noise_verify_scoped_signature` verifica que `recipient_pubkey == nossa chave` — forwarding para agente errado é rejeitado matematicamente
3. `operation[16]` distingue entre operações — uma assinatura de `"seal_snapshot\0"` não vale para `"route_packet\0"`
4. `session_id` previne replay — uma mensagem de sessão anterior não passa na sessão atual

### 4.2 Prompt Injection via Secret Value

**Ataque**: Um secret malicioso contém texto de prompt injection: `"ignore previous instructions and..."`. Um agente que lê o secret executa instruções maliciosas.

**Por que o LSES limita o dano**:
- O agente nunca recebe o valor raw do secret — recebe apenas uma `RuntimeSecretHandle`
- O valor é resolvido apenas no momento necessário, minimizando a superfície de injeção
- `AccessPolicy.allows()` verifica se a operação `"export_plaintext"` é permitida — por padrão, não é

### 4.3 Tool Poisoning via Snapshot Malicioso

**Ataque**: Um agente malicioso submete um snapshot com conteúdo modificado para substituir configurações de ferramentas de outros agentes.

**Por que não funciona com LSES**:
- Cada snapshot requer `attestations.enclave_signature` + `attestations.consumer_countersig`
- Ambas as assinaturas precisam ser de chaves no `TrustedKeyRegistry`
- Um agente malicioso com nova chave é rejeitado na etapa 9.5 de `verifySnapshot`
- A cadeia de hash monotônica detecta qualquer tentativa de inserir um snapshot no meio da cadeia

---

## Resumo Executivo

| Categoria de Ataque | Status com LSES |
|---------------------|-----------------|
| Credential stuffing | **Bloqueado** — tokens são single-use LAD |
| Memory scraping | **Minimizado** — janela de exposição em microssegundos + secureZero |
| Replay de sessão | **Bloqueado** — bitmap de replay 65K slots |
| Rollback de snapshot | **Bloqueado** — epoch chain monotônica |
| Man-in-the-middle | **Bloqueado** — tokens single-use + AEAD binding |
| Impersonação de agente | **Bloqueado** — scoped signatures + TrustedKeyRegistry |
| Supply chain npm/cargo | **Bloqueado** — deny.toml + checksums do Cargo.lock |
| Secret em repositório git | **Bloqueado** — .gitignore + envelope criptografado |
| Prototype pollution | **N/A** — Rust + Zig, não JavaScript |
| Length extension attack | **Bloqueado** — HKDF, HMAC, AEAD |
| Nonce reuse AES-GCM | **Bloqueado** — CSPRNG + NonceRegistry |
| Timing side-channel | **Bloqueado** — subtle::ConstantTimeEq |
| MIASMA WORM | **Bloqueado** — scoped signatures com recipient binding |
| Prompt injection | **Minimizado** — handles opacas, export_plaintext restrito |
| XZ-utils style backdoor | **Mitigado** — deny.toml + identidade estável via seeds |
