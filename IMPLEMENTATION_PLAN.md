# LSES — Plano para evoluir para State-of-the-Art (Secure Enclave para chaves privadas)

## Gap analysis (estado atual)
- PoC funcional de coreografia e identidade, porém sem TEE real (SGX/Nitro/SEV) e sem remote attestation verificável.
- Replay guard ainda local, sem ancoragem distribuída forte.
- Criptografia de payload em parte simulada (XOR na coreografia de pacote).
- Políticas de autorização ainda pouco formais (falta policy engine auditável com deny-by-default testado).
- Falta uma trilha completa de supply-chain hardening (SLSA, assinatura de artefatos, reproducible builds).

## Objetivo de referência (12 meses)
1. **Enclave real + attestation verificável** (hardware-backed quando disponível).
2. **Pipeline criptográfico formal**: envelope encryption, assinatura dual, rotação automática, anti-rollback.
3. **Operação production-grade**: observabilidade, chaos/security tests, resposta a incidentes, compliance.
4. **Interoperabilidade Zig + Rust** com fronteira FFI mínima e APIs estáveis.

## Arquitetura alvo (Zig + Rust)
- **Rust (core de segurança e políticas):**
  - KMS/TPM/HSM integration, assinatura/validação, policy engine, replay/rollback guard, auditoria.
- **Zig (runtime de alta performance):**
  - data plane, IO crítico, buffers, integração eBPF/AF_XDP, isolamento de caminhos quentes.
- **Contrato FFI:**
  - ABI C estável, versionada, com structs `repr(C)` validadas e fuzzing de fronteira.

## Backlog priorizado

### Fase 1 — Hardening base (semanas 1–4)
- [x] Remover `static mut` inseguro no core Rust, trocar por estado sincronizado (`OnceLock<Mutex<...>>`).
- [x] Adicionar validações de ponteiro nulo nas bordas FFI.
- [x] Trocar XOR de coreografia por AEAD (AES-GCM ou ChaCha20-Poly1305) por hop/contexto.
- [x] Zeroization de chaves e buffers sensíveis.
- [x] Testes unitários de erro e replay em API C.

### Fase 2 — Segurança criptográfica real (semanas 5–10)
- [ ] Implementar envelope completo (`snapshot_body`, `snapshot_id`, dual signatures).
- [ ] Introduzir monotonic counter/trust anchor externo para anti-rollback.
- [ ] Integrar rotação de KEK/DEK e política de expiração.
- [ ] Adicionar verificação canônica determinística (JSON canonicalization).

### Fase 3 — Enclave e attestation (semanas 11–18)
- [ ] Backend SGX/Nitro/SEV opcional por feature flag.
- [ ] Prova de attestation anexada ao envelope e validada no orchestrator.
- [ ] Modo degradação segura quando TEE indisponível.

### Fase 4 — Operação SOTA (semanas 19–26)
- [ ] Assinatura de artefatos, SBOM, proveniência SLSA.
- [ ] Fuzzing contínuo (FFI, parser, envelope).
- [ ] Chaos/security drills e SLOs de segurança.
- [ ] Runbooks de incidente, rotação emergencial e recuperação de cadeia.

## Início imediato (já iniciado neste commit)
1. **Hardening da base Rust FFI** (thread-safe state + checks de ponteiro).
2. **Preparar migração da coreografia XOR para AEAD por aresta**.
3. **Expandir suíte de testes de regressão e misuse cases**.
