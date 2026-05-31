# Implementation TODO

- [x] Implementar envelope AEAD por aresta para pacotes do enclave Rust
    - duration: 180
    - Início: 2026-05-31T01:27:34Z. Fim: 2026-05-31T01:30:34Z. Funcionalidade implementada: APIs FFI `seal_edge_packet` e `open_edge_packet` para selar e abrir frames com AES-256-GCM por `EdgeContext`, derivando a chave de aresta por HMAC-SHA256 a partir da seed do enclave e autenticando `intent_id`, `edge_id` e `sequence` como AAD. Como foi feito: adicionei constantes de erro e overhead AEAD, nonce aleatório de 96 bits via `OsRng`, frame no formato `nonce || ciphertext || tag`, validações de ponteiros/capacidade/replay e testes unitários serializados para roundtrip, rejeição de adulteração, rejeição de contexto errado, buffers pequenos, ponteiros nulos e replay.
