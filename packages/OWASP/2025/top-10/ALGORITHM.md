# Algoritmo semântico compartilhado

Todos os pacotes implementados usam os mesmos nomes públicos em todas as linguagens:

1. Declarar `blocked_patterns` como a lista de marcadores perigosos do risco.
2. Declarar `replacement` como `[REMOVED]`.
3. `normalize_payload(payload)` converte `payload` para texto, remove bytes nulos e normaliza quebras de linha.
4. `remove_blocked_patterns(normalized_payload, blocked_patterns)` substitui cada marcador perigoso, sem diferenciar maiúsculas/minúsculas, por `replacement`.
5. `escape_output(cleaned_payload)` codifica caracteres de controle HTML e de comando (`<`, `>`, `&`, `"`, `'`, `` ` ``) quando necessário.
6. `clean(threat, payload)` seleciona o comportamento pelo nome semântico do risco e retorna o texto sanitizado.
7. `LLM_1ntruder.clean(threat, payload)` é a fachada de biblioteca usada por aplicações.

## Extensão para Prompt Injection em poesia

A solução de `Prompt Injection` também usa os mesmos nomes semânticos em TS, Python, Go, Rust e Zig:

1. Declarar `poetry_indicators` com palavras de instrução ocultáveis por acróstico, como `ignore`, `system`, `developer` e `reveal`.
2. `extract_poetry_acrostic(normalized_payload)` percorre as linhas do poema, coleta a primeira letra não vazia de cada verso e monta o acróstico em minúsculas.
3. `detect_poetry_prompt_injection(normalized_payload)` exige pelo menos três versos e verifica se o acróstico contém algum item de `poetry_indicators`.
4. `neutralize_poetry_prompt_injection(cleaned_payload, normalized_payload)` retorna `replacement` quando a poesia contém instrução oculta; caso contrário, preserva `cleaned_payload`.
5. `clean(threat, payload)` executa a remoção de padrões explícitos, aplica a neutralização poética e só então escapa a saída.
