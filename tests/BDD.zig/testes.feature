Feature: Transferência bancária com Gherkin completo
  Este arquivo valida as keywords canônicas e aliases suportados pelo mini-runner Zig.
  Linhas descritivas livres devem ser aceitas e ignoradas pelo executor.

  # Background de Feature: roda antes de todo Scenario, Example e linha expandida de Outline.
  Background:
    Given saldo = 100
    And limite = 50
    But audit = 0

  Rule: Background de Rule sobrescreve parte do estado da Feature
    Esta Rule valida Rule + Background local + Scenario + And + But.

    Background:
      Given limite = 25
      And audit = 10

    Scenario: Scenario usa Background da Feature e da Rule
      When transferir(20)
      And depositar(5)
      Then saldo == 85
      And limite == 25
      But audit == 12

  Rule: Example é alias de Scenario

    Example: Example executa como cenário comum
      Given saldo = 40 and limite = 0
      When depositar 10
      Then saldo expect 50
      And audit == 1

  Rule: Asterisk herda a keyword semântica anterior

    Scenario: estrela funciona como Given, When e Then conforme contexto
      Given saldo = 10
      * limite = 0
      When depositar(5)
      * transferir(3)
      Then saldo == 12
      * limite == 0
      And audit == 2

  Rule: Scenario Outline com Examples

    Scenario Outline: transferência parametrizada de <valor>
      Given saldo = <saldo> and limite = <limite>
      When transferir(<valor>)
      Then saldo == <saldo_final>
      And audit == 1

      Examples:
        | saldo | limite | valor | saldo_final |
        | 100   | 50     | 30    | 70          |
        | 80    | 20     | 10    | 70          |

  Rule: Scenario Template com Scenarios

    Scenario Template: depósito parametrizado de <valor>
      Given saldo = <saldo> and limite = 0
      When depositar(<valor>)
      Then saldo == <saldo_final>
      And audit == 1

      Scenarios:
        | saldo | valor | saldo_final |
        | 60    | 15    | 75          |
        | 1     | 9     | 10          |

  Rule: erros nativos do Zig

    Scenario: Then error valida erro nativo retornado pela action
      Given saldo = 20 and limite = 10
      When transferir(50)
      Then error SaldoInsuficiente

    Scenario: Then expect error também é aceito
      Given saldo = 100 and limite = 0
      When transferir(-10)
      Then expect error ValorInvalido

  Rule: steps textuais documentais

    Scenario: Gherkin textual sem binding semântico continua aceito
      When zzz
      Then qqq
      And outro texto livre
      But ainda é apenas documentação
      * bullet step Gherkin aceito
