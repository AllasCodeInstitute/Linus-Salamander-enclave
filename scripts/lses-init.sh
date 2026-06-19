#!/usr/bin/env bash
# lses-init.sh — Bootstrap único do enclave LSES.
#
# Execute UMA VEZ antes do primeiro start do serviço (ou após uma rotação
# de chaves intencional). Após este script:
#   - O material de chave reside APENAS em ~/.local/share/lses/sealed_state.bin
#     (ou no diretório configurado por LSES_STATE_DIR), cifrado com AES-256-GCM
#     ligado à identidade desta máquina.
#   - Nenhum valor de chave/segredo é armazenado em variável de ambiente,
#     arquivo de configuração, histórico do shell, ou qualquer outro canal.
#   - O ÚNICO output é a chave pública Ed25519 do enclave, que deve ser
#     adicionada ao LSES_TRUSTED_ENCLAVE_KEYS nos consumidores.
#
# Uso:
#   ./scripts/lses-init.sh
#
# Para produção com diretório personalizado:
#   LSES_STATE_DIR=/var/lib/lses ./scripts/lses-init.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BOOTSTRAP_BIN="$PROJECT_ROOT/zig-out/bin/lses-bootstrap"

# Verifica instalação do Zig
if ! command -v zig &>/dev/null; then
    echo "[LSES ERRO] Zig não encontrado no PATH." >&2
    echo "[LSES ERRO] Instale Zig 0.14+ em https://ziglang.org/download/" >&2
    exit 1
fi

# Compila se necessário
if [ ! -f "$BOOTSTRAP_BIN" ]; then
    echo "[LSES] Compilando lses-bootstrap..."
    (cd "$PROJECT_ROOT" && zig build -Doptimize=ReleaseSafe 2>&1) || {
        echo "[LSES ERRO] Falha na compilação. Verifique os logs acima." >&2
        exit 1
    }
fi

# Toda a geração de material de chave acontece DENTRO do processo
# bootstrap — nenhum valor atravessa o shell
exec "$BOOTSTRAP_BIN"
