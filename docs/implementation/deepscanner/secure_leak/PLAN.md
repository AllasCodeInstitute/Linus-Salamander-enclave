# Secure Leak Deep Scanner implementation plan

Este checklist acompanha a evolução do `linus deepscan secure_leaks <path...>` e da implementação Zig standalone. Cada item concluído inclui subitens com o que foi implementado e a função da funcionalidade.

## Checklist marcável

- [x] Definir contrato de CLI compatível com `linus deepscan secure_leaks`.
  - Implementado no Rust CLI em `rust/linus/src/main.rs` com parsing de `deepscan secure_leaks`.
  - A funcionalidade aceita múltiplos paths e flags compatíveis com o plano: `--git-history`, `--no-git-history`, `--staged`, `--since`, `--format`, `--baseline`, `--fail-on`, `--max-ram-mib`, `--project-concurrency`, `--scan-workers`, `--max-file-mib`, `--extract-archives`, `--validate-live` e `--provider`.
  - O scanner retorna `0` sem finding acima do limite, `1` com finding e `2` para erro de execução/configuração.

- [x] Garantir modo offline-first e bloquear validação live por padrão.
  - Implementado erro explícito quando `--validate-live` é usado nesta fase.
  - A funcionalidade impede qualquer chamada de rede acidental e deixa validação de provedores para uma etapa futura com allowlist e rate limit.

- [x] Implementar modelo de memória para 1 GiB/1 core.
  - Implementado cálculo `max_projects_by_ram = floor((max_ram_mib - 128) / 16)`.
  - Com `--max-ram-mib 1024`, o relatório mostra 896 MiB disponíveis e 56 projetos pelo orçamento de RAM.
  - A funcionalidade recusa `--project-concurrency` acima do orçamento e expõe `project_concurrency_used`, `scan_workers_used`, `chunk_size_bytes` e orçamento no resumo.

- [x] Implementar discovery de projeto e escopo Git.
  - Implementado `repo_root`, path relativo ao repo e coleta por `git ls-files -co --exclude-standard`.
  - A funcionalidade escaneia apenas arquivos visíveis ao Git e respeita `.gitignore` na árvore atual.

- [x] Implementar scan incremental de arquivos atuais.
  - Implementado leitor por chunks de 256 KiB com overlap de 4 KiB e limite por arquivo via `--max-file-mib`.
  - A funcionalidade evita carregar arquivos grandes inteiros em memória, detecta bytes NUL como binário e zeroiza buffers temporários.

- [x] Implementar scan de histórico Git profundo.
  - Implementado `git rev-list --objects --all` com deduplicação por blob SHA.
  - A funcionalidade cobre objetos alcançáveis por branches/tags e evita escanear o mesmo blob repetidamente.
  - `--since` limita o histórico quando informado.

- [x] Implementar ruleset inicial classificado.
  - Implementadas regras para AWS, GitHub, GitLab, OpenAI/LLM, Slack, Stripe, Google, npm, PyPI, segredo Linus, private key PEM, URI com credenciais, JWT/session token, assignment context e token em arquivo sensível.
  - A funcionalidade classifica `rule_id`, `secret_type`, `severity`, `confidence` e remediação específica.

- [x] Implementar detecção por contexto, entropy e filtros negativos.
  - Implementado `assignment_context` com palavras sensíveis, entropy Shannon, penalização de placeholders e filtros para UUID/checksum/constantes simbólicas.
  - A funcionalidade reduz falsos positivos óbvios sem descartar automaticamente achados em fixtures/testes.

- [x] Implementar fingerprint, masking e hashing seguro.
  - Implementado `fingerprint`, `masked_secret` com no máximo 4 primeiros e 4 últimos caracteres, e `secret_sha256` calculado sem dependências externas.
  - A funcionalidade não imprime o secret cru no output e permite deduplicação/baseline sem persistir o valor real.

- [x] Implementar metadados ricos por finding.
  - Cada finding armazena `fingerprint`, `rule_id`, `severity`, `confidence`, `secret_type`, `project`, `file`, `line`, `column`, `commit`, `masked_secret`, `secret_sha256`, contexto redigido, `asset_hint` e `remediation`.
  - A funcionalidade torna o relatório acionável para triagem e correção.

- [x] Implementar formatos de saída.
  - Implementados `text`, `json`, `ndjson` e `sarif` sem dependências externas.
  - A funcionalidade permite uso humano, pipelines streaming e integração com code scanning/SARIF.

- [x] Implementar baseline seguro.
  - Implementado `--baseline <file>` para suprimir fingerprints existentes e `baseline create` para gerar baseline.
  - A funcionalidade salva fingerprint, rule_id, arquivo e hash do secret, nunca secret cru.

- [x] Implementar testes automatizados iniciais.
  - Testes cobrem redaction, fingerprint/hash, URI parser, JWT detector, PEM detector, assignment context, cálculo de memória, limite de concorrência e placeholders.
  - A funcionalidade protege regressões básicas de segurança e precisão.

- [x] Documentar uso e comportamento.
  - README atualizado com comandos principais e formatos.
  - Este PLAN registra as tarefas, o que foi implementado e o que cada parte faz.

- [ ] Separar Rust em módulos internos (`cli`, `rules`, `walker`, `git_history`, `reporter`, `baseline`, `memory_budget`).
  - Próximo passo: dividir o arquivo único em módulos mantendo os testes.
  - Objetivo: facilitar manutenção sem alterar o contrato da CLI.

- [ ] Implementar extração segura de archives/binários.
  - Próximo passo: adicionar extractors limitados para zip/tar/jar/ipynb/sqlite e string extraction para binários.
  - Objetivo: cobrir artifacts sem risco de zip bomb ou uso excessivo de memória.

- [ ] Implementar correlacionador de assets completo.
  - Próximo passo: correlacionar host, bucket, project id, tenant id, endpoint e service name na seção/arquivo próximo.
  - Objetivo: priorizar secrets que apontam para assets reais sem expor credenciais.

- [ ] Implementar validators offline avançados e live opt-in.
  - Próximo passo: parse estrutural de PEM, JWT e service account JSON; validação live apenas com `--validate-live --provider ...`.
  - Objetivo: aumentar precisão mantendo o modo padrão offline.

- [ ] Completar implementação Zig modular.
  - Próximo passo: migrar `zig/secure_leaks.zig` para módulos `src/main.zig`, `src/cli.zig`, `src/rules.zig`, `src/walker.zig`, `src/git_history.zig`, `src/reporter.zig` e `src/memory_budget.zig` quando o toolchain Zig estiver disponível no ambiente.
  - Objetivo: alcançar paridade com a implementação Rust e testar compilação real.

- [ ] Expandir suíte de integração e segurança.
  - Próximo passo: fixtures para `.env`, secret removido do HEAD mas presente no histórico, Dockerfile/layer text fixture, sourcemap, archive, OOM, zip bomb e arquivo gigante.
  - Objetivo: validar cobertura deep scanner com limites de memória e sem vazamento no output.
