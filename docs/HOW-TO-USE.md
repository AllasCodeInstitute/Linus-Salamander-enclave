# LSES — Guia de Uso por Arquitetura

> **Linus Salamander Enclave System v0.1.0**  
> Como integrar o LSES de forma segura em diferentes padrões arquiteturais.

---

## Índice

1. [Configuração Base](#1-configuração-base)
2. [Arquitetura Event-Driven](#2-arquitetura-event-driven)
3. [Domain-Driven Design (DDD)](#3-domain-driven-design-ddd)
4. [Clean Architecture](#4-clean-architecture)
5. [MVC (Model-View-Controller)](#5-mvc-model-view-controller)
6. [Microserviços / Service Mesh](#6-microserviços--service-mesh)
7. [Serverless / FaaS](#7-serverless--faas)
8. [CQRS + Event Sourcing](#8-cqrs--event-sourcing)
9. [Padrões Transversais](#9-padrões-transversais)
10. [Erros Comuns e Como Evitá-los](#10-erros-comuns-e-como-evitá-los)

---

## 1. Configuração Base

### Bootstrap — Uma Única Vez

O desenvolvedor ou operador **não precisa gerar, ver, ou armazenar nenhuma chave**.
Execute o script de bootstrap uma vez antes do primeiro start do serviço:

```bash
# Instalar Zig 0.14+ se necessário
# https://ziglang.org/download/

# Bootstrap — gera KEK, ENCLAVE_SEED e CONSUMER_SEED DENTRO do processo enclave.
# Nenhum segredo aparece no terminal, no histórico do shell, ou em variáveis de ambiente.
./scripts/lses-init.sh
```

Saída esperada:

```
[LSES] Bootstrap concluido com sucesso.
[LSES] Material de chave gerado e selado dentro do enclave.
[LSES] Nenhum segredo foi exposto fora do processo.

[LSES] Chave publica do enclave (adicione em LSES_TRUSTED_ENCLAVE_KEYS):
        9f2a8b3c4d5e6f7a8b9c0d1e2f3a4b5c...

[LSES] Execute o servico normalmente — sem variaveis de ambiente de segredos.
```

**Esta chave pública é a ÚNICA informação que você precisa registrar** — configure-a em cada serviço consumidor via a variável de ambiente `LSES_TRUSTED_ENCLAVE_KEYS` (que é uma lista de chaves públicas, não um segredo):

```bash
# Em cada consumidor — apenas a chave pública (não é segredo)
export LSES_TRUSTED_ENCLAVE_KEYS="9f2a8b3c4d5e6f7a8b9c0d1e2f3a4b5c..."
```

### O que acontece internamente

```
./scripts/lses-init.sh
        │
        ▼
lses-bootstrap (processo Zig)
        │
        ├── std.crypto.random.bytes(&kek)          ← getrandom(2) / RtlGenRandom
        ├── std.crypto.random.bytes(&enclave_seed)
        ├── std.crypto.random.bytes(&consumer_seed)
        │
        ├── AES-256-GCM(kek||enc_seed||con_seed, machine_binding_key)
        │           ↓
        └── ~/.local/share/lses/sealed_state.bin   ← modo 0600, só o dono acessa
                    (nenhum valor vaza para fora do processo)
```

### Onde o material fica após o bootstrap

| O que é | Onde fica | Quem pode ler |
|---------|-----------|---------------|
| KEK (plaintext) | **Nunca persiste** — zeroizado após derivar o kek_provider | Apenas o processo em execução |
| ENCLAVE_SEED | **Nunca persiste** — zeroizado após derivar o par Ed25519 | Apenas o processo em execução |
| CONSUMER_SEED | **Nunca persiste** — zeroizado após derivar o par Ed25519 | Apenas o processo em execução |
| Blob selado | `~/.local/share/lses/sealed_state.bin` (0600) | Apenas o usuário que fez o bootstrap, na mesma máquina |
| Chave pública enclave | Saída do bootstrap (stdout) | Público — deve ser pinada nos consumidores |

### Produção com diretório de sistema

```bash
# Para serviços que rodam como root ou usuário dedicado (ex: lses):
sudo mkdir -p /var/lib/lses
sudo chown lses:lses /var/lib/lses

LSES_STATE_DIR=/var/lib/lses ./scripts/lses-init.sh

# A variável LSES_STATE_DIR não é sensível — apenas indica localização
# Adicione ao arquivo de unidade systemd:
# Environment=LSES_STATE_DIR=/var/lib/lses
```

### Princípio Fundamental

> **Nunca passe o valor de um secret como argumento de função, retorno de método, ou campo de struct visível ao resto da aplicação. Passe sempre a `RuntimeSecretHandle`.**

```
❌ ERRADO:
   let token = lses.readSecret("github_token");
   http_client.set_header("Authorization", format!("Bearer {}", token));

✓ CORRETO:
   let handle = lses.readSecretHandle("github_token");
   // handle é [u8; 32] aleatório, sem valor semântico
   http_client.set_header_from_handle(&lses, handle, "Authorization", "Bearer {}");
   // LSES resolve o handle internamente e zero a memória após o envio
```

---

## 2. Arquitetura Event-Driven

### Contexto

Em sistemas event-driven (Kafka, RabbitMQ, NATS), serviços publicam e consomem eventos. Secrets precisam estar disponíveis nos handlers sem vazar entre eventos ou para o message broker.

### Padrão de Integração

```
Publisher                    Message Broker              Consumer
    │                            │                           │
    ├── lses.writeSecret()       │                           │
    │   (criptografa payload)    │                           │
    │                            │                           │
    ├── Publica evento com:      │                           │
    │   { secret_ref: "id",      ├──── entrega evento ──────►│
    │     snapshot_epoch: 5 }    │     (sem plaintext)       │
    │                            │                          ├── recebe evento
    │                            │                          ├── lses.readSecretHandle()
    │                            │                          │   (resolve por ID)
    │                            │                          ├── usa por microssegundos
    │                            │                          └── handle expirada (LAD)
```

### Implementação em Go

```go
// infrastructure/events/secret_publisher.go
type SecretPublisher struct {
    lses   *lses.Client
    broker MessageBroker
}

func (p *SecretPublisher) PublishWithSecret(ctx context.Context, secretName string, payload Event) error {
    // Escreve o secret no enclave, obtém uma referência
    ref, err := p.lses.WriteSecret(ctx, secretName, payload.SecretValue)
    if err != nil {
        return err
    }

    // Publica APENAS a referência — nunca o valor
    return p.broker.Publish(ctx, Event{
        Type:          payload.Type,
        SecretRef:     ref.ID,      // [16]byte opaco
        SnapshotEpoch: ref.Epoch,
        Timestamp:     time.Now(),
    })
}

// infrastructure/events/secret_consumer.go
type SecretConsumer struct {
    lses    *lses.Client
    handler func(ctx context.Context, handle lses.SecretHandle) error
}

func (c *SecretConsumer) HandleEvent(ctx context.Context, event Event) error {
    handle, err := c.lses.ReadSecretHandle(ctx, event.SecretRef, event.SnapshotEpoch)
    if err != nil {
        return fmt.Errorf("secret indisponível ou expirado: %w", err)
    }
    // O handle expira após este handler retornar — LAD garante destruição
    return c.handler(ctx, handle)
}
```

### Cuidados Específicos

**Mensagens mortas (DLQ)**: Se um evento vai para Dead Letter Queue, o secret referenciado pode já ter expirado pelo TTL do LAD. O consumer precisa tratar `ErrSecretExpired` e decidir se republicar o evento ou descartar.

**Particionamento**: Em Kafka com múltiplas partições, o consumer group pode processar eventos fora de ordem. O `snapshot_epoch` no evento garante que o consumer saiba a qual epoch o secret pertence — evitando confusão entre versões de um mesmo secret.

**Idempotência**: O LAD não é idempotente — consumir uma handle duas vezes falha. Garanta que o handler seja idempotente *antes* de resolver a handle:

```go
// Verificar idempotência antes de consumir
if alreadyProcessed(event.ID) {
    return nil // não tenta resolver o handle novamente
}
handle, err := c.lses.ReadSecretHandle(ctx, event.SecretRef, event.SnapshotEpoch)
```

---

## 3. Domain-Driven Design (DDD)

### Contexto

No DDD, os secrets de infraestrutura (tokens de API, chaves de banco, credenciais de serviços externos) ficam na camada de infraestrutura. O domínio não deve nunca enxergar um secret em plaintext.

### Organização de Camadas

```
domain/
├── aggregates/
│   └── payment.go          ← sem referência a LSES, sem tipos de secret
├── events/
│   └── payment_authorized.go
└── repositories/
    └── payment_repository.go  ← interface apenas; implementação na infra

application/
└── services/
    └── payment_service.go  ← recebe SecretHandle como dependency injection

infrastructure/
├── lses/
│   ├── lses_client.go      ← wrapper sobre a C ABI do LSES
│   └── secret_handle.go    ← tipos opacos que não vazam para o domínio
├── payment/
│   └── payment_gateway.go  ← usa handle para autenticar chamada de API
└── bootstrap/
    └── app.go              ← carrega seeds, inicializa enclave
```

### Aggregate sem Conhecimento de Secrets

```go
// domain/aggregates/payment.go
// O agregado Payment não tem ideia de como a autenticação acontece
type Payment struct {
    ID     PaymentID
    Amount Money
    Status PaymentStatus
}

func (p *Payment) Authorize() (PaymentAuthorized, error) {
    if p.Amount.IsZero() {
        return PaymentAuthorized{}, ErrZeroAmount
    }
    p.Status = StatusPendingAuthorization
    return PaymentAuthorized{PaymentID: p.ID, Amount: p.Amount}, nil
}
```

```go
// application/services/payment_service.go
// O serviço de aplicação recebe o handle via DI — nunca o plaintext
type PaymentService struct {
    gateway     PaymentGateway
    secretStore lses.SecretStore
}

func (s *PaymentService) ProcessPayment(ctx context.Context, p *Payment) error {
    event, err := p.Authorize()
    if err != nil {
        return err
    }

    // Obtém handle — não plaintext
    apiKeyHandle, err := s.secretStore.GetHandle(ctx, "stripe_api_key")
    if err != nil {
        return err
    }

    return s.gateway.Charge(ctx, event, apiKeyHandle)
}
```

```go
// infrastructure/payment/payment_gateway.go
type StripeGateway struct {
    lses *lses.Client
}

func (g *StripeGateway) Charge(ctx context.Context, event PaymentAuthorized, handle lses.SecretHandle) error {
    // ÚNICO lugar onde o plaintext existe — por microssegundos
    return g.lses.WithSecret(ctx, handle, func(apiKey []byte) error {
        defer lses.SecureZero(apiKey) // garante zeragem mesmo em panic
        return stripe.Charge(apiKey, event.Amount)
    })
}
```

### Domain Events com Referências de Secret

Se um Domain Event precisa de contexto de autenticação para ser processado depois:

```go
// domain/events/payment_authorized.go
type PaymentAuthorized struct {
    PaymentID     PaymentID
    Amount        Money
    // Referência opaca — sem valor semântico fora do LSES
    WebhookTokenRef lses.SecretRef  // [16]byte
}
```

---

## 4. Clean Architecture

### Contexto

Na Clean Architecture (Ports & Adapters), as dependências apontam para dentro — o núcleo de casos de uso não depende de infraestrutura. O LSES vive exclusivamente nos adaptadores externos.

### Estrutura

```
           ┌────────────────────────────────────────┐
           │           Casos de Uso                  │
           │                                         │
           │  interface SecretPort {                 │
           │      GetHandle(name string) Handle      │
           │  }                                      │
           │                                         │
           └──────────────┬─────────────────────────┘
                          │ depende de (port)
           ┌──────────────▼─────────────────────────┐
           │           Adaptadores                   │
           │                                         │
           │  LsesSecretAdapter implements SecretPort│
           │      (acessa C ABI do LSES)             │
           │                                         │
           └────────────────────────────────────────┘
```

### Port (interface interna)

```typescript
// src/core/ports/secret.port.ts
export interface SecretPort {
  getHandle(name: string): Promise<SecretHandle>;
  withSecret<T>(handle: SecretHandle, fn: (secret: Uint8Array) => Promise<T>): Promise<T>;
}

// SecretHandle é opaco — apenas um ID sem valor semântico
export type SecretHandle = { readonly _tag: 'SecretHandle'; id: Uint8Array };
```

### Adaptador LSES

```typescript
// src/adapters/lses/lses.adapter.ts
export class LsesSecretAdapter implements SecretPort {
  constructor(private readonly lsesNative: LsesNativeBinding) {}

  async getHandle(name: string): Promise<SecretHandle> {
    const rawHandle = await this.lsesNative.readSecretHandle(name);
    return { _tag: 'SecretHandle', id: rawHandle };
  }

  async withSecret<T>(
    handle: SecretHandle,
    fn: (secret: Uint8Array) => Promise<T>
  ): Promise<T> {
    const plaintext = await this.lsesNative.resolveHandle(handle.id);
    try {
      return await fn(plaintext);
    } finally {
      plaintext.fill(0); // secureZero manual — NUNCA omitir o finally
    }
  }
}
```

### Caso de Uso

```typescript
// src/core/use-cases/send-notification.use-case.ts
export class SendNotificationUseCase {
  constructor(
    private readonly secrets: SecretPort,    // apenas a porta — não o adaptador
    private readonly emailService: EmailPort,
  ) {}

  async execute(notification: Notification): Promise<void> {
    const smtpHandle = await this.secrets.getHandle('smtp_password');

    await this.secrets.withSecret(smtpHandle, async (smtpPassword) => {
      await this.emailService.send({
        to: notification.recipient,
        subject: notification.subject,
        password: smtpPassword, // existe apenas dentro deste closure
      });
      // smtpPassword é zerado automaticamente no finally do adapter
    });
  }
}
```

### Por que a `finally` é Crítica

```typescript
// ❌ ERRADO — em caso de exceção, o plaintext fica na memória
async withSecret(handle, fn) {
  const plaintext = await this.resolve(handle.id);
  const result = await fn(plaintext);  // se jogar exceção aqui...
  plaintext.fill(0);                   // ...esta linha nunca executa
  return result;
}

// ✓ CORRETO — o finally garante zeragem mesmo em exceção
async withSecret(handle, fn) {
  const plaintext = await this.resolve(handle.id);
  try {
    return await fn(plaintext);
  } finally {
    plaintext.fill(0); // executa sempre — com ou sem exceção
  }
}
```

---

## 5. MVC (Model-View-Controller)

### Contexto

Em aplicações MVC tradicionais (Rails, Django, Laravel, ASP.NET), a tentação é passar secrets como campos do Model ou variáveis de sessão. Isso é um antipadrão.

### Antipadrão a Evitar

```python
# ❌ ERRADO — Django views típico
class PaymentView(View):
    def post(self, request):
        api_key = os.environ.get('STRIPE_KEY')  # plaintext em variável
        stripe.api_key = api_key                  # plaintext em módulo global
        stripe.Charge.create(amount=request.POST['amount'])
```

### Padrão com LSES

```python
# ✓ CORRETO — Python com LSES
import ctypes
import lses  # wrapper Python para a C ABI

# bootstrap/app.py — inicialização única
lses_client = lses.Client()  # carrega material de chave do estado selado em disco

# controllers/payment_controller.py
class PaymentController:
    def __init__(self, lses_client: lses.Client):
        self._lses = lses_client

    def process_payment(self, request):
        amount = validate_amount(request.POST['amount'])  # validar antes

        # handle = bytes de 32, sem valor semântico
        handle = self._lses.read_secret_handle("stripe_api_key")

        try:
            result = self._lses.with_secret(handle, lambda key: (
                stripe_charge(key, amount)  # plaintext apenas aqui
            ))
            return JsonResponse({'status': 'ok', 'charge_id': result['id']})
        except lses.SecretExpiredError:
            return JsonResponse({'error': 'secret_unavailable'}, status=503)
```

### Model sem Secrets

```python
# models/payment.py
class Payment(models.Model):
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, default='pending')
    charge_id = models.CharField(max_length=100, blank=True)
    # NUNCA armazenar api_key, token, ou secret aqui
    # NUNCA armazenar lses_handle aqui (o handle expira, mas o epoch de snapshot pode mudar)
```

### Sessões

```python
# ❌ ERRADO — armazenar handle em sessão
request.session['payment_key_handle'] = handle  # handles expiram; sessão não sabe

# ✓ CORRETO — re-obter handle a cada request que precisar
# O LSES é rápido o suficiente para resolver handles por request
handle = self._lses.read_secret_handle("stripe_api_key")
```

### Views e Templates

Views e templates **nunca** recebem informações de secret. Se o template precisar exibir que "pagamento está configurado", passe um booleano:

```python
# controller
has_payment_configured = self._lses.secret_exists("stripe_api_key")
return render(request, 'settings.html', {'payment_configured': has_payment_configured})
```

```html
<!-- template: sem secrets, sem handles, sem IDs de enclave -->
{% if payment_configured %}
  <span class="badge-green">Pagamento configurado</span>
{% else %}
  <a href="/settings/payment">Configurar pagamento</a>
{% endif %}
```

---

## 6. Microserviços / Service Mesh

### Contexto

Em arquiteturas de microserviços com service mesh (Istio, Linkerd), cada serviço se autentica com mTLS. O LSES complementa o mTLS adicionando binding de identidade de enclave às credenciais de aplicação.

### Topologia com LSES

```
             ┌──────────────────────────────────────────────┐
             │              Operador                         │
             │  executa `lses bootstrap` por serviço         │
             │  coleta chave pública Ed25519 no primeiro boot│
             │  configura LSES_TRUSTED_ENCLAVE_KEYS          │
             └──────────────────────┬───────────────────────┘
                                    │ configura (fora de banda)
     ┌──────────────────────────────▼──────────────────────────────────┐
     │                      Config Service                               │
     │   (Vault, K8s Secrets, AWS SSM — apenas LSES_TRUSTED_ENCLAVE_KEYS│
     │    KEK/seeds vivem no blob selado em disco, nunca aqui)          │
     └──────┬───────────────────────┬──────────────────────────────────┘
            │                       │
     ┌──────▼──────┐         ┌──────▼──────┐
     │  Serviço A  │         │  Serviço B  │
     │  + LSES     │         │  + LSES     │
     │  enclave    │─mTLS───►│  enclave    │
     │  seed_A     │         │  seed_B     │
     └─────────────┘         └─────────────┘
```

### Identidade por Serviço

Cada microserviço executa `lses bootstrap` uma vez no provisionamento — gera seu próprio blob selado com KEK, ENCLAVE_SEED e CONSUMER_SEED exclusivos. Isso garante que:

1. Um segredo do Serviço A não pode ser lido pelo Serviço B (chaves diferentes por blob)
2. Um enclave comprometido do Serviço A não pode impersonar o Serviço B

```yaml
# kubernetes/services/payment-service.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-service
spec:
  template:
    spec:
      initContainers:
      - name: lses-bootstrap
        # Executa uma vez se blob não existir; gera KEK+seeds via CSPRNG,
        # sela em disco — nenhum valor secreto passa por env var
        command: ["lses", "bootstrap", "--if-not-exists"]
        volumeMounts:
        - name: lses-state
          mountPath: /var/lib/lses
      containers:
      - name: payment-service
        env:
        - name: LSES_STATE_DIR        # não-secreta — só a localização do blob
          value: /var/lib/lses
        - name: LSES_TRUSTED_ENCLAVE_KEYS   # não-secreta — chaves públicas
          valueFrom:
            configMapKeyRef:
              name: lses-trusted-keys
              key: enclave_keys
      volumes:
      - name: lses-state
        persistentVolumeClaim:
          claimName: lses-state-payment
```

### Comunicação entre Serviços

Quando o Serviço A precisa chamar o Serviço B com um secret:

```rust
// Serviço A — nunca envia o plaintext
let handle = lses.read_secret_handle("service_b_token");
let scoped_proof = lses.noise_sign_scoped_payload(
    handle.as_bytes(),
    ScopedContext {
        recipient_pubkey: service_b_public_key,
        operation: b"call_payment_api\0",
    },
    session_id,
);

// Serviço B recebe a prova de escopo, verifica, e resolve localmente
let verified = lses.verify_scoped_signature(&scoped_proof, session_id);
// Serviço B tem seu próprio LSES e acessa o secret por sua chave
```

### Rotação de Secrets em Produção

```bash
# 1. Gerar novo secret no enclave
lses-cli write-secret --name "stripe_api_key" --value "$NEW_STRIPE_KEY"

# 2. Novo snapshot com epoch+1 — o antigo continua válido até o TTL da handle
# 3. Deploy gradual (rolling update) — novos pods pegam o epoch novo
# 4. Pods antigos com handles pendentes completam antes do TTL expirar
# 5. Após TTL: sem handles ativas apontando para epoch antigo
```

---

## 7. Serverless / FaaS

### Contexto

Em funções serverless (AWS Lambda, Google Cloud Functions, Azure Functions), o ambiente é efêmero — a função pode ser destruída e recriada a qualquer momento. O cold start inicializa o LSES do zero.

### Desafio do Cold Start

```
Cold Start:             Warm (reutilização):
init_enclave_keys()     [já inicializado - AtomicBool]
unsealKeys() do disco   [KEK/seeds já carregados]
derivar Ed25519 keys    [chaves já em memória]
handle request          handle request
```

O `AtomicBool ENCLAVE_INITIALIZED` garante que `init_enclave_keys()` execute apenas uma vez por processo — inclusive em warm starts.

### Implementação em Rust (Lambda)

```rust
use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use std::sync::OnceLock;

static LSES: OnceLock<LsesClient> = OnceLock::new();

async fn init_lses() -> LsesClient {
    // Carrega material de chave do blob selado em disco (via unsealKeys)
    // LSES_STATE_DIR aponta para o volume com o blob — não é um segredo
    LsesClient::new().expect("Falha ao inicializar LSES: execute lses bootstrap primeiro")
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Inicialização única por processo Lambda
    let lses = LSES.get_or_init(|| {
        tokio::runtime::Handle::current().block_on(init_lses())
    });

    run(service_fn(|event: LambdaEvent<Request>| async move {
        handle_request(event, lses).await
    })).await
}

async fn handle_request(event: LambdaEvent<Request>, lses: &LsesClient) -> Result<Response, Error> {
    // handles têm TTL curto — adequado para funções de vida efêmera
    let db_handle = lses.read_secret_handle("database_password").await?;

    lses.with_secret(db_handle, |password| async move {
        let conn = database::connect(password).await?;
        let result = conn.query(event.payload.query).await?;
        // password zerado automaticamente ao sair deste closure
        Ok(Response { data: result })
    }).await
}
```

### TTL no Lambda

O TTL do `RuntimeSecretHandle` deve ser menor que o timeout máximo da Lambda:

```
Timeout Lambda: 30 segundos
TTL do Handle:  20 segundos (margem de segurança)

Se a Lambda for invocada novamente no warm start antes do TTL:
→ O handle anterior já expirou → nova handle é gerada
→ Não há acúmulo de handles entre invocações
```

### Restrição de Concorrência

Em Lambda com concorrência reservada > 1, múltiplas instâncias paralelas do processo podem existir. Cada instância tem seu próprio `RuntimeSecretStore` — handles não são compartilhadas entre instâncias. Isso é comportamento correto e esperado.

---

## 8. CQRS + Event Sourcing

### Contexto

No padrão CQRS (Command Query Responsibility Segregation) com Event Sourcing, o estado da aplicação é reconstruído a partir de um log de eventos imutáveis. Secrets em eventos é um antipadrão grave — um evento persistido com um token compromete o token para sempre.

### Antipadrão: Secret no Event Log

```
❌ NUNCA FAÇA ISSO:
EventLog (imutável):
  [1] UserCreated { email: "...", api_key: "sk_live_1234..." }
  [2] PaymentConfigured { stripe_key: "sk_live_5678..." }
  ...
  Se o event log vazar, todos os tokens históricos estão comprometidos
```

### Padrão Correto: Referência no Event Log

```
✓ CORRETO:
EventLog (imutável):
  [1] UserCreated { email: "...", lses_secret_ref: "ref_0a1b2c..." }
  [2] PaymentConfigured { lses_secret_ref: "ref_d4e5f6...", epoch: 3 }

LSES (separado, mutável):
  snapshot_epoch_3: AES-256-GCM(stripe_key, aad={epoch:3,...})
```

### Command Handler

```go
// commands/configure_payment.go
type ConfigurePaymentCommandHandler struct {
    lses      *lses.Client
    eventBus  EventBus
}

func (h *ConfigurePaymentCommandHandler) Handle(ctx context.Context, cmd ConfigurePaymentCmd) error {
    // Escreve o secret — obtém referência imutável (epoch + ref ID)
    ref, err := h.lses.WriteSecret(ctx, "stripe_key", cmd.StripeApiKey)
    if err != nil {
        return err
    }

    // Publica evento SEM o valor — apenas a referência
    return h.eventBus.Publish(ctx, PaymentConfigured{
        UserID:      cmd.UserID,
        LsesRef:     ref.ID,
        LsesEpoch:   ref.Epoch,
        ConfiguredAt: time.Now(),
    })
}
```

### Query Handler (Read Side)

```go
// queries/get_payment_config.go
type PaymentConfigQueryHandler struct {
    lses      *lses.Client
    projection *PaymentConfigProjection
}

func (h *PaymentConfigQueryHandler) Handle(ctx context.Context, q GetPaymentConfigQuery) (*PaymentConfig, error) {
    proj := h.projection.GetForUser(q.UserID)
    if proj == nil {
        return nil, ErrNotConfigured
    }

    // Resolve o handle — LAD garante que o plaintext existe apenas durante esta chamada
    handle, err := h.lses.ReadSecretHandle(ctx, proj.LsesRef, proj.LsesEpoch)
    if err != nil {
        return nil, err
    }

    // Retorna ao caller uma versão que pode usar o handle — mas não o plaintext
    return &PaymentConfig{
        UserID:    q.UserID,
        KeyHandle: handle, // handle opaca — não o valor
    }, nil
}
```

### Event Sourcing e Replay de Eventos

Ao reconstruir estado a partir do event log (replay), references LSES com epochs antigos podem não existir mais:

```go
func (p *PaymentConfigProjection) Rebuild(events []Event) error {
    for _, event := range events {
        switch e := event.(type) {
        case PaymentConfigured:
            // Verifica se o secret ainda existe no LSES
            exists, err := p.lses.SecretRefExists(e.LsesRef, e.LsesEpoch)
            if err != nil || !exists {
                // Secret expirou — projeta como "configurado mas expirado"
                p.state[e.UserID] = PaymentState{Status: "expired"}
                continue
            }
            p.state[e.UserID] = PaymentState{
                Status:    "active",
                LsesRef:   e.LsesRef,
                LsesEpoch: e.LsesEpoch,
            }
        }
    }
    return nil
}
```

---

## 9. Padrões Transversais

### 9.1 Inicialização do Enclave

Em qualquer arquitetura, a inicialização segue o mesmo padrão:

```go
// bootstrap/lses.go
func InitLSES() (*lses.Client, error) {
    // 1. Inicializar o enclave — carrega KEK/seeds do blob selado em disco
    //    Falha com SealedStateNotFound se bootstrap ainda não foi executado.
    //    Nenhuma variável de ambiente de segredo é necessária ou aceita.
    client, err := lses.NewClient()
    if err != nil {
        return nil, fmt.Errorf("falha ao inicializar enclave LSES: %w\n"+
            "Execute 'lses bootstrap' para gerar o estado selado.", err)
    }

    // 2. Verificar conectividade básica (não expõe nenhum secret)
    if err := client.HealthCheck(); err != nil {
        return nil, fmt.Errorf("enclave LSES indisponível: %w", err)
    }

    return client, nil
}
```

### 9.2 Propagação de Contexto

Passe handles pelo contexto — nunca por variável global:

```go
// contexto carrega o handle, não o plaintext
type contextKey string
const secretHandleKey contextKey = "lses_handle"

func WithSecretHandle(ctx context.Context, handle lses.SecretHandle) context.Context {
    return context.WithValue(ctx, secretHandleKey, handle)
}

func SecretHandleFromContext(ctx context.Context) (lses.SecretHandle, bool) {
    handle, ok := ctx.Value(secretHandleKey).(lses.SecretHandle)
    return handle, ok
}
```

### 9.3 Observabilidade sem Vazamento

Logs, métricas e traces podem registrar metadados sobre operações de secret sem revelar valores:

```go
// ✓ CORRETO — registra o que é seguro
log.Info("secret acessado",
    "name", "stripe_api_key",
    "epoch", handle.Epoch,
    "handle_id", hex.EncodeToString(handle.ID[:8]), // apenas 8 bytes do ID para rastreio
    "success", true,
)

// ❌ NUNCA registrar
log.Info("stripe key", "value", plaintextKey)  // exposição direta
log.Info("stripe key", "handle", handle.ID)    // handle completa expõe identidade
```

### 9.4 Tratamento de Erros

```go
switch err {
case lses.ErrSecretExpired:
    // Handle expirou por TTL — obter novo handle é seguro
    handle, err = client.ReadSecretHandle(ctx, secretName)

case lses.ErrHandleConsumed:
    // Handle já foi usada (LAD enforced) — não tentar novamente com a mesma handle
    return fmt.Errorf("tentativa de duplo uso de handle de secret")

case lses.ErrRollbackDetected:
    // Snapshot com epoch regressivo — possível ataque; alertar imediatamente
    alerting.Critical("rollback de epoch detectado no LSES")
    return fmt.Errorf("integridade do enclave comprometida")

case lses.ErrUnauthorizedConsumer:
    // Chave de enclave não reconhecida — possível substituto malicioso
    alerting.Critical("enclave não reconhecido por TrustedKeyRegistry")
    return fmt.Errorf("enclave não autorizado")
}
```

---

## 10. Erros Comuns e Como Evitá-los

### Erro 1: Armazenar a Handle em Cache

```go
// ❌ ERRADO — handle expirada na próxima request
var cachedHandle lses.SecretHandle

func init() {
    cachedHandle, _ = lses.ReadSecretHandle("db_password")
}

func handleRequest(r *http.Request) {
    conn := lses.WithSecret(cachedHandle, ...) // falha após TTL
}

// ✓ CORRETO — obter nova handle por request
func handleRequest(r *http.Request) {
    handle, _ := lses.ReadSecretHandle("db_password")
    conn := lses.WithSecret(handle, ...)
}
```

### Erro 2: Serializar a Handle para JSON

```go
// ❌ ERRADO — handle em JSON pode vazar em logs ou responses
type Config struct {
    DBHandle lses.SecretHandle `json:"db_handle"` // expõe ID no JSON
}

// ✓ CORRETO — handles são opacas e não devem ser serializadas
// Serializar apenas metadados (nome do secret, epoch)
type Config struct {
    DBSecretName  string `json:"db_secret_name"`
    DBSecretEpoch uint64 `json:"db_secret_epoch"`
}
```

### Erro 3: Usar Handles em Goroutines Concorrentes

```go
// ❌ PERIGOSO — duas goroutines tentam consumir a mesma handle (LAD: apenas uma vence)
handle, _ := lses.ReadSecretHandle("api_key")
go func() { lses.WithSecret(handle, ...) }()
go func() { lses.WithSecret(handle, ...) }() // uma delas recebe ErrHandleConsumed

// ✓ CORRETO — uma handle por goroutine
for i := 0; i < numWorkers; i++ {
    go func() {
        handle, _ := lses.ReadSecretHandle("api_key") // handle individual
        lses.WithSecret(handle, ...)
    }()
}
```

### Erro 4: Não Configurar `LSES_TRUSTED_ENCLAVE_KEYS` em Produção

```bash
# ❌ ERRADO — sem keys configuradas, qualquer enclave é aceito
# (sem LSES_TRUSTED_ENCLAVE_KEYS — LSES_KEK não existe como env var)

# ✓ CORRETO — pin das chaves públicas conhecidas (não-secretas)
export LSES_TRUSTED_ENCLAVE_KEYS="9f2a8b...,3c4d5e..."
# A chave pública é impressa pelo 'lses bootstrap' no primeiro boot
```

Sem `LSES_TRUSTED_ENCLAVE_KEYS`, um enclave malicioso com chaves novas pode ser aceito. A variável é opcional para desenvolvimento mas **obrigatória em produção**.

### Erro 5: Ignorar Erros de Rollback

```go
// ❌ ERRADO — ignora erro de integridade
handle, _ := lses.ReadSecretHandle("api_key")

// ✓ CORRETO — qualquer erro da família de integridade deve parar o serviço
handle, err := lses.ReadSecretHandle("api_key")
if err != nil {
    if errors.Is(err, lses.ErrRollbackDetected) || errors.Is(err, lses.ErrChainHeadMismatch) {
        // Parar o serviço — possível compromisso de integridade
        log.Fatal("integridade do enclave comprometida:", err)
    }
    return fmt.Errorf("erro ao ler secret: %w", err)
}
```
