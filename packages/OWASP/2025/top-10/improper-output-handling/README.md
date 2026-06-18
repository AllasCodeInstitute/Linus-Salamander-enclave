# LLM05:2025 Improper Output Handling

## Cenário vulnerável
Uma aplicação envia ou consome `payload` de LLM sem remover marcadores relacionados a **Improper Output Handling**. O arquivo `vulnerable.*` demonstra a passagem direta do dado perigoso.

## Exploração
O arquivo `exploit.*` monta um `payload` contendo `<script` para demonstrar como a falha aparece antes da sanitização.

## Solução
Use a biblioteca `LLM_1ntruder.clean("Improper Output Handling", payload)`. A implementação segue `../ALGORITHM.md`: normaliza o texto, remove padrões bloqueados e escapa saída perigosa.

## Testes
Cada linguagem contém um teste de vulnerabilidade que confirma que o cenário inseguro preserva o marcador e um teste de defesa que confirma que `LLM_1ntruder.clean` remove ou escapa o conteúdo.
