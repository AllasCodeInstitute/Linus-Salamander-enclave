# Implementation TODO

- [x] Implementar envelope AEAD por aresta para pacotes do enclave Rust
    - duration: 180
    - Início: 2026-05-31T01:27:34Z. Fim: 2026-05-31T01:30:34Z. Funcionalidade implementada: APIs FFI `seal_edge_packet` e `open_edge_packet` para selar e abrir frames com AES-256-GCM por `EdgeContext`, derivando a chave de aresta por HMAC-SHA256 a partir da seed do enclave e autenticando `intent_id`, `edge_id` e `sequence` como AAD. Como foi feito: adicionei constantes de erro e overhead AEAD, nonce aleatório de 96 bits via `OsRng`, frame no formato `nonce || ciphertext || tag`, validações de ponteiros/capacidade/replay e testes unitários serializados para roundtrip, rejeição de adulteração, rejeição de contexto errado, buffers pequenos, ponteiros nulos e replay.


- [x] Criar matriz completa de testes comportamentais e dashboard de resultados
    - duration: 260
    - Início: 2026-05-31T05:06:24Z. Fim: 2026-05-31T05:10:44Z. Funcionalidade implementada: testes unitários, carga, stress, chaos, security e benchmark para `QuarkBehaviors` (funções), `AtomicBehaviors` (funcionalidades) e `Project` (Intents compostos), cada teste emitindo um JSON único em `test-results/behavior-json/`, além de um `manifest.json` para descoberta. Como foi feito: substituí a suíte unitária simples por uma matriz de 18 testes serializados com geração de relatórios JSON, composição de fluxos comuns de Intents (`generate_agent_key` + AEAD seal/open + assinatura), cenários de adulteração/replay/buffer inválido e medições leves de benchmark; também criei `behavior-dashboard.html` com HTML/CSS/JS puros, Tailwind e animate.css, menu `QuarkBehaviors`, `AtomicBehaviors` e `Project`, filtros, cards de métricas/assertions e importação manual de JSONs. Os testes validam determinismo, carga repetida, stress de envelopes, rejeição chaos/security, latência média e composição completa do projeto.
