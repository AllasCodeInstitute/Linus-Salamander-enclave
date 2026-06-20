# Zig Comptime BDD Gherkin Runner

Mini-framework BDD para Zig que lê um arquivo `.feature` com `@embedFile`, faz parsing em `comptime` e executa os cenários contra uma struct Zig.

## Keywords suportadas

- `Feature`
- `Rule`
- `Background`
- `Scenario`
- `Example` como alias de `Scenario`
- `Scenario Outline`
- `Scenario Template` como alias de `Scenario Outline`
- `Examples`
- `Scenarios` como alias de `Examples`
- `Given`
- `When`
- `Then`
- `And`
- `But`
- `*`

## Semântica implementada

- `Feature` é obrigatória e deve aparecer antes das demais keywords primárias.
- Apenas uma `Feature` por arquivo é suportada.
- `Rule` cria um escopo lógico e reinicia o `Background` local da regra.
- `Background` fora de `Rule` roda antes de todos os cenários.
- `Background` dentro de `Rule` roda depois do `Background` da `Feature` e antes dos cenários daquela regra.
- `Scenario` e `Example` executam cenários comuns.
- `Scenario Outline` e `Scenario Template` expandem uma execução por linha de `Examples`/`Scenarios`.
- `And`, `But` e `*` herdam a keyword semântica anterior: `Given`, `When` ou `Then`.
- Linhas descritivas livres e comentários `#` são aceitos.

## Bindings executáveis suportados

### Given

```gherkin
Given saldo = 100
Given saldo = 100 and limite = 50
And limite = 20
```

### When

```gherkin
When transferir(30)
When transferir 30
And depositar(10)
```

### Then

```gherkin
Then saldo == 70
Then saldo expect 70
Then error SaldoInsuficiente
Then expect error ValorInvalido
```

Steps que não seguem esses formatos são tratados como documentais (`Doc`) e não alteram o estado.

## Executar

```bash
zig test main.zig
```

## Arquivo de validação

O `testes.feature` incluído valida todas as keywords suportadas, incluindo os aliases `Example`, `Scenario Template` e `Scenarios`, além de `And`, `But` e `*` em contextos diferentes.
