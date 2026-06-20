Feature: LSES — Linus Salamander Enclave System Security Behaviors

  # Este arquivo define os comportamentos de segurança do LSES em Gherkin.
  # Para rodar: substitua testes.feature por lses.feature em main.zig e crie
  # o contexto LsesContext com os campos e métodos correspondentes.

  Background:
    Given enclave_initialized = 0
    And nonce_count = 0
    But violations = 0

  Rule: LinearAutoDestroy — handle de uso único destruído no consumo

    Scenario: segredo é consumido e zerado na primeira leitura
      Given enclave_initialized = 1
      When consume_secret(1)
      Then secret_zeroed == 1
      And nonce_count == 0

    Scenario: segunda tentativa de consumo retorna erro
      Given enclave_initialized = 1
      When consume_secret(1)
      And consume_secret(1)
      Then error HandleAlreadyConsumed

    Scenario: TTL expirado rejeita consumo
      Given enclave_initialized = 1
      When expire_handle(1)
      Then error HandleExpired

  Rule: NonceRegistry — fail-closed no overflow de 100K entradas

    Scenario: nonce único é registrado com sucesso
      Given enclave_initialized = 1 and nonce_count = 0
      When register_nonce(1)
      Then nonce_count == 1
      And violations == 0

    Scenario: nonce duplicado é rejeitado
      Given enclave_initialized = 1 and nonce_count = 1
      When register_nonce(1)
      And register_nonce(1)
      Then error NonceReused

    Scenario Outline: overflow de <count> nonces ativa fail-closed
      Given enclave_initialized = 1 and nonce_count = <count>
      When register_nonce(1)
      Then error NonceRegistryFull
      And violations == 1

      Examples:
        | count  |
        | 100000 |

  Rule: Sealed State — chaves KEK/ENCLAVE_SEED vinculadas à máquina

    Scenario: seal produz blob AES-256-GCM com machine binding
      Given enclave_initialized = 1
      When seal_state(1)
      Then sealed == 1
      And violations == 0

    Scenario: unseal com machine key incorreta é rejeitado
      Given enclave_initialized = 1
      When seal_state(1)
      And tamper_machine_key(1)
      Then error SealedStateInvalid

  Rule: Scoped Signatures — binding a (domain, signer, recipient, op, session)

    Scenario: assinatura com escopo válido é aceita
      Given enclave_initialized = 1
      When sign_scoped(1)
      Then nonce_count == 1
      And violations == 0

    Scenario: assinatura com domínio errado é rejeitada
      Given enclave_initialized = 1
      When sign_scoped(1)
      And verify_wrong_domain(1)
      Then error SignatureScopeMismatch

  Rule: MIASMA WORM — anti-impersonação de agentes

    Scenario: agente com chave não pinada é bloqueado
      Given enclave_initialized = 1
      When verify_agent_identity(1)
      Then error AgentKeyNotTrusted
      And violations == 1

    Scenario: agente com chave pinada no TrustedKeyRegistry é aceito
      Given enclave_initialized = 1 and nonce_count = 1
      When pin_agent_key(1)
      And verify_agent_identity(1)
      Then nonce_count == 2
      And violations == 0
