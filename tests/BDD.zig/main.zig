const std = @import("std");
const expect = std.testing.expect;

const NodeKind = enum { Feature, Rule, Scenario, Step };
const StepKeyword = enum { Given, When, Then };
const StepAction = enum { Doc, SetFields, CallAction, ExpectField, ExpectError };

const Passo = struct {
    kind: NodeKind,
    semantic_keyword: StepKeyword = .Given,
    shown_keyword: []const u8 = "",
    action: StepAction = .Doc,
    desc: []const u8 = "",
    rule: []const u8 = "",
    k1: []const u8 = "",
    v1: i32 = 0,
    k2: []const u8 = "",
    v2: i32 = 0,
    expected_error_name: []const u8 = "",
};

const RawStep = struct {
    semantic_keyword: StepKeyword,
    shown_keyword: []const u8,
    text: []const u8,
    line_no: usize,
};

const ParseMode = enum { None, FeatureBackground, RuleBackground, Scenario, ScenarioOutline, Examples };

const FieldPair = struct {
    key: []const u8,
    value: i32,
};

const Assignment = struct {
    k1: []const u8,
    v1: i32,
    k2: []const u8 = "",
    v2: i32 = 0,
};

const Quoted = struct {
    desc: []const u8,
    rest: []const u8,
};

fn failAt(comptime line_no: usize, comptime msg: []const u8) noreturn {
    @compileError(std.fmt.comptimePrint("Gherkin parse error at line {}: {s}", .{ line_no, msg }));
}

fn trim(comptime s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r");
}

fn startsWithKeyword(comptime line: []const u8, comptime keyword: []const u8) bool {
    if (!std.mem.startsWith(u8, line, keyword)) return false;
    if (line.len == keyword.len) return true;
    const c = line[keyword.len];
    return c == ':' or c == ' ' or c == '\t';
}

fn restAfterKeyword(comptime line: []const u8, comptime keyword: []const u8) []const u8 {
    const rest = trim(line[keyword.len..]);
    if (rest.len > 0 and rest[0] == ':') return trim(rest[1..]);
    return rest;
}

fn splitFirstWhitespace(comptime s: []const u8) ?usize {
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == ' ' or s[i] == '\t') return i;
    }
    return null;
}

fn splitQuoted(comptime text: []const u8, comptime line_no: usize) Quoted {
    const t = trim(text);
    if (t.len > 0 and t[0] == '"') {
        const end = std.mem.indexOfPos(u8, t, 1, "\"") orelse failAt(line_no, "descrição com aspas não foi fechada");
        return .{ .desc = t[1..end], .rest = trim(t[end + 1 ..]) };
    }

    return .{ .desc = t, .rest = t };
}

fn parseI32Maybe(comptime text: []const u8) ?i32 {
    return std.fmt.parseInt(i32, trim(text), 10) catch null;
}

fn parseFieldPair(comptime text: []const u8) ?FieldPair {
    const p = trim(text);
    if (p.len == 0) return null;

    if (std.mem.indexOf(u8, p, "=")) |idx_eq| {
        const key = trim(p[0..idx_eq]);
        const value = trim(p[idx_eq + 1 ..]);
        if (key.len == 0 or value.len == 0) return null;
        const parsed = parseI32Maybe(value) orelse return null;
        return .{ .key = key, .value = parsed };
    }

    if (splitFirstWhitespace(p)) |idx_space| {
        const key = trim(p[0..idx_space]);
        const value = trim(p[idx_space + 1 ..]);
        if (key.len == 0 or value.len == 0) return null;
        const parsed = parseI32Maybe(value) orelse return null;
        return .{ .key = key, .value = parsed };
    }

    return null;
}

fn parseAssignments(comptime text: []const u8) ?Assignment {
    const body = trim(text);
    if (body.len == 0) return null;

    if (std.mem.indexOf(u8, body, " and ")) |idx_and| {
        const p1 = parseFieldPair(body[0..idx_and]) orelse return null;
        const p2 = parseFieldPair(body[idx_and + 5 ..]) orelse return null;
        return .{ .k1 = p1.key, .v1 = p1.value, .k2 = p2.key, .v2 = p2.value };
    }

    const p1 = parseFieldPair(body) orelse return null;
    return .{ .k1 = p1.key, .v1 = p1.value };
}

fn parseCallAction(comptime text: []const u8) ?Passo {
    const body = trim(text);
    if (body.len == 0) return null;

    if (std.mem.indexOf(u8, body, "(")) |idx_open| {
        const idx_close = std.mem.lastIndexOf(u8, body, ")") orelse return null;
        if (idx_close <= idx_open) return null;
        const action_name = trim(body[0..idx_open]);
        const arg = trim(body[idx_open + 1 .. idx_close]);
        if (action_name.len == 0 or arg.len == 0) return null;
        const parsed = parseI32Maybe(arg) orelse return null;
        return .{ .kind = .Step, .semantic_keyword = .When, .shown_keyword = "When", .action = .CallAction, .desc = body, .k1 = action_name, .v1 = parsed };
    }

    if (splitFirstWhitespace(body)) |idx_space| {
        const action_name = trim(body[0..idx_space]);
        const arg = trim(body[idx_space + 1 ..]);
        if (action_name.len == 0 or arg.len == 0) return null;
        const parsed = parseI32Maybe(arg) orelse return null;
        return .{ .kind = .Step, .semantic_keyword = .When, .shown_keyword = "When", .action = .CallAction, .desc = body, .k1 = action_name, .v1 = parsed };
    }

    return null;
}

fn parseExpectedField(comptime text: []const u8) ?Passo {
    const body = trim(text);
    if (body.len == 0) return null;

    if (std.mem.indexOf(u8, body, "==")) |idx_eq| {
        const field = trim(body[0..idx_eq]);
        const value = trim(body[idx_eq + 2 ..]);
        if (field.len == 0 or value.len == 0) return null;
        const parsed = parseI32Maybe(value) orelse return null;
        return .{ .kind = .Step, .semantic_keyword = .Then, .shown_keyword = "Then", .action = .ExpectField, .desc = body, .k1 = field, .v1 = parsed };
    }

    if (std.mem.indexOf(u8, body, " expect ")) |idx_expect| {
        const field = trim(body[0..idx_expect]);
        const value = trim(body[idx_expect + 8 ..]);
        if (field.len == 0 or value.len == 0) return null;
        const parsed = parseI32Maybe(value) orelse return null;
        return .{ .kind = .Step, .semantic_keyword = .Then, .shown_keyword = "Then", .action = .ExpectField, .desc = body, .k1 = field, .v1 = parsed };
    }

    return null;
}

fn parseSemanticStep(comptime raw: RawStep) Passo {
    const quoted = splitQuoted(raw.text, raw.line_no);
    const desc = quoted.desc;
    const body = quoted.rest;

    switch (raw.semantic_keyword) {
        .Given => {
            const assignment_text = if (std.mem.startsWith(u8, body, "for ")) body[4..] else body;
            if (parseAssignments(assignment_text)) |parsed| {
                return .{ .kind = .Step, .semantic_keyword = .Given, .shown_keyword = raw.shown_keyword, .action = .SetFields, .desc = desc, .k1 = parsed.k1, .v1 = parsed.v1, .k2 = parsed.k2, .v2 = parsed.v2 };
            }
        },
        .When => {
            if (std.mem.startsWith(u8, body, "for action ")) {
                const rest = body[11..];
                const idx_with = std.mem.indexOf(u8, rest, " with args ") orelse return .{ .kind = .Step, .semantic_keyword = .When, .shown_keyword = raw.shown_keyword, .action = .Doc, .desc = desc };
                const action_name = trim(rest[0..idx_with]);
                const arg = trim(rest[idx_with + 11 ..]);
                if (parseI32Maybe(arg)) |parsed| {
                    return .{ .kind = .Step, .semantic_keyword = .When, .shown_keyword = raw.shown_keyword, .action = .CallAction, .desc = desc, .k1 = action_name, .v1 = parsed };
                }
            }

            if (parseCallAction(body)) |parsed| {
                return .{ .kind = .Step, .semantic_keyword = .When, .shown_keyword = raw.shown_keyword, .action = parsed.action, .desc = desc, .k1 = parsed.k1, .v1 = parsed.v1 };
            }
        },
        .Then => {
            if (std.mem.startsWith(u8, body, "for field ")) {
                const rest = body[10..];
                if (parseExpectedField(rest)) |parsed| {
                    return .{ .kind = .Step, .semantic_keyword = .Then, .shown_keyword = raw.shown_keyword, .action = parsed.action, .desc = desc, .k1 = parsed.k1, .v1 = parsed.v1 };
                }
            }

            if (std.mem.startsWith(u8, body, "expect error ")) {
                return .{ .kind = .Step, .semantic_keyword = .Then, .shown_keyword = raw.shown_keyword, .action = .ExpectError, .desc = desc, .expected_error_name = trim(body[13..]) };
            }

            if (std.mem.startsWith(u8, body, "error ")) {
                return .{ .kind = .Step, .semantic_keyword = .Then, .shown_keyword = raw.shown_keyword, .action = .ExpectError, .desc = desc, .expected_error_name = trim(body[6..]) };
            }

            if (parseExpectedField(body)) |parsed| {
                return .{ .kind = .Step, .semantic_keyword = .Then, .shown_keyword = raw.shown_keyword, .action = parsed.action, .desc = desc, .k1 = parsed.k1, .v1 = parsed.v1 };
            }
        },
    }

    return .{ .kind = .Step, .semantic_keyword = raw.semantic_keyword, .shown_keyword = raw.shown_keyword, .action = .Doc, .desc = desc };
}

fn parseStepLine(comptime line: []const u8, comptime line_no: usize, comptime last_semantic: ?StepKeyword) ?RawStep {
    if (startsWithKeyword(line, "Given")) {
        return .{ .semantic_keyword = .Given, .shown_keyword = "Given", .text = restAfterKeyword(line, "Given"), .line_no = line_no };
    }
    if (startsWithKeyword(line, "When")) {
        return .{ .semantic_keyword = .When, .shown_keyword = "When", .text = restAfterKeyword(line, "When"), .line_no = line_no };
    }
    if (startsWithKeyword(line, "Then")) {
        return .{ .semantic_keyword = .Then, .shown_keyword = "Then", .text = restAfterKeyword(line, "Then"), .line_no = line_no };
    }
    if (startsWithKeyword(line, "And")) {
        return .{ .semantic_keyword = last_semantic orelse failAt(line_no, "And precisa herdar Given, When ou Then"), .shown_keyword = "And", .text = restAfterKeyword(line, "And"), .line_no = line_no };
    }
    if (startsWithKeyword(line, "But")) {
        return .{ .semantic_keyword = last_semantic orelse failAt(line_no, "But precisa herdar Given, When ou Then"), .shown_keyword = "But", .text = restAfterKeyword(line, "But"), .line_no = line_no };
    }
    if (startsWithKeyword(line, "*")) {
        return .{ .semantic_keyword = last_semantic orelse failAt(line_no, "* precisa herdar Given, When ou Then"), .shown_keyword = "*", .text = restAfterKeyword(line, "*"), .line_no = line_no };
    }

    return null;
}

fn parseTableRow(comptime line: []const u8, comptime line_no: usize) []const []const u8 {
    const row = trim(line);
    if (row.len < 2 or row[0] != '|') failAt(line_no, "linha de Examples precisa usar tabela com pipes");

    var cells: []const []const u8 = &.{};
    var start: usize = 1;
    while (start < row.len) {
        const end = std.mem.indexOfPos(u8, row, start, "|") orelse row.len;
        const cell = trim(row[start..end]);
        cells = cells ++ .{cell};
        start = end + 1;
    }

    return cells;
}

fn lookupExampleValue(comptime key: []const u8, comptime headers: []const []const u8, comptime values: []const []const u8, comptime line_no: usize) []const u8 {
    if (headers.len != values.len) failAt(line_no, "linha de Examples possui quantidade diferente de colunas");

    inline for (headers, 0..) |header, i| {
        if (std.mem.eql(u8, header, key)) return values[i];
    }

    failAt(line_no, "placeholder não existe no cabeçalho de Examples");
}

fn replacePlaceholders(comptime text: []const u8, comptime headers: []const []const u8, comptime values: []const []const u8, comptime line_no: usize) []const u8 {
    var out: []const u8 = &.{};
    var i: usize = 0;
    while (i < text.len) {
        if (text[i] == '<') {
            const close = std.mem.indexOfPos(u8, text, i + 1, ">") orelse failAt(line_no, "placeholder <...> não foi fechado");
            const key = trim(text[i + 1 .. close]);
            out = out ++ lookupExampleValue(key, headers, values, line_no);
            i = close + 1;
        } else {
            out = out ++ text[i .. i + 1];
            i += 1;
        }
    }
    return out;
}

fn scenarioPasses(comptime name: []const u8, comptime rule_name: []const u8, comptime feature_background: []const RawStep, comptime rule_background: []const RawStep, comptime steps: []const RawStep) []const Passo {
    var out: []const Passo = &.{.{ .kind = .Scenario, .desc = name, .rule = rule_name }};

    inline for (feature_background) |step| {
        out = out ++ .{parseSemanticStep(step)};
    }
    inline for (rule_background) |step| {
        out = out ++ .{parseSemanticStep(step)};
    }
    inline for (steps) |step| {
        out = out ++ .{parseSemanticStep(step)};
    }

    return out;
}

fn outlineScenarioPasses(
    comptime name: []const u8,
    comptime rule_name: []const u8,
    comptime feature_background: []const RawStep,
    comptime rule_background: []const RawStep,
    comptime outline_steps: []const RawStep,
    comptime headers: []const []const u8,
    comptime values: []const []const u8,
    comptime line_no: usize,
) []const Passo {
    const expanded_name = replacePlaceholders(name, headers, values, line_no);
    var expanded_steps: []const RawStep = &.{};

    inline for (outline_steps) |step| {
        expanded_steps = expanded_steps ++ .{RawStep{
            .semantic_keyword = step.semantic_keyword,
            .shown_keyword = step.shown_keyword,
            .text = replacePlaceholders(step.text, headers, values, line_no),
            .line_no = step.line_no,
        }};
    }

    return scenarioPasses(expanded_name, rule_name, feature_background, rule_background, expanded_steps);
}

fn parseFeature(comptime text: []const u8) []const Passo {
    comptime {
        @setEvalBranchQuota(300000);

        var out: []const Passo = &.{};
        var mode: ParseMode = .None;

        var feature_seen = false;
        var feature_background: []const RawStep = &.{};
        var rule_background: []const RawStep = &.{};
        var current_rule: []const u8 = "";

        var outline_title: []const u8 = "";
        var outline_steps: []const RawStep = &.{};
        var outline_has_example_rows = false;
        var example_headers: []const []const u8 = &.{};

        var last_semantic: ?StepKeyword = null;
        var line_no: usize = 0;
        var lines = std.mem.tokenizeScalar(u8, text, '\n');

        while (lines.next()) |raw_line| {
            line_no += 1;
            const line = trim(raw_line);
            if (line.len == 0 or std.mem.startsWith(u8, line, "#")) continue;

            const entering_primary = startsWithKeyword(line, "Feature") or
                startsWithKeyword(line, "Rule") or
                startsWithKeyword(line, "Background") or
                startsWithKeyword(line, "Scenario Outline") or
                startsWithKeyword(line, "Scenario Template") or
                startsWithKeyword(line, "Examples") or
                startsWithKeyword(line, "Scenarios") or
                startsWithKeyword(line, "Scenario") or
                startsWithKeyword(line, "Example");

            if (entering_primary and (mode == .ScenarioOutline or mode == .Examples) and outline_title.len > 0 and !outline_has_example_rows and
                !(startsWithKeyword(line, "Examples") or startsWithKeyword(line, "Scenarios")))
            {
                failAt(line_no, "Scenario Outline precisa de pelo menos uma linha em Examples/Scenarios");
            }

            if (startsWithKeyword(line, "Feature")) {
                if (feature_seen) failAt(line_no, "apenas uma Feature por arquivo é suportada");
                feature_seen = true;
                const title = restAfterKeyword(line, "Feature");
                if (title.len == 0) failAt(line_no, "Feature precisa de título");
                out = out ++ .{Passo{ .kind = .Feature, .desc = title }};
                mode = .None;
                last_semantic = null;
                continue;
            }

            if (!feature_seen) failAt(line_no, "Feature precisa ser a primeira keyword primária do arquivo");

            if (startsWithKeyword(line, "Rule")) {
                current_rule = restAfterKeyword(line, "Rule");
                if (current_rule.len == 0) failAt(line_no, "Rule precisa de título");
                rule_background = &.{};
                out = out ++ .{Passo{ .kind = .Rule, .desc = current_rule }};
                mode = .None;
                last_semantic = null;
                continue;
            }

            if (startsWithKeyword(line, "Background")) {
                if (current_rule.len == 0) {
                    mode = .FeatureBackground;
                } else {
                    mode = .RuleBackground;
                }
                last_semantic = null;
                continue;
            }

            if (startsWithKeyword(line, "Scenario Outline") or startsWithKeyword(line, "Scenario Template")) {
                const keyword = if (startsWithKeyword(line, "Scenario Outline")) "Scenario Outline" else "Scenario Template";
                outline_title = restAfterKeyword(line, keyword);
                if (outline_title.len == 0) failAt(line_no, "Scenario Outline/Template precisa de título");
                outline_steps = &.{};
                outline_has_example_rows = false;
                example_headers = &.{};
                mode = .ScenarioOutline;
                last_semantic = null;
                continue;
            }

            if (startsWithKeyword(line, "Examples") or startsWithKeyword(line, "Scenarios")) {
                if (mode != .ScenarioOutline and mode != .Examples) failAt(line_no, "Examples/Scenarios precisa pertencer a um Scenario Outline/Template");
                if (outline_steps.len == 0) failAt(line_no, "Scenario Outline precisa ter steps antes de Examples/Scenarios");
                example_headers = &.{};
                mode = .Examples;
                last_semantic = null;
                continue;
            }

            if (startsWithKeyword(line, "Scenario") or startsWithKeyword(line, "Example")) {
                const keyword = if (startsWithKeyword(line, "Scenario")) "Scenario" else "Example";
                const title = restAfterKeyword(line, keyword);
                if (title.len == 0) failAt(line_no, "Scenario/Example precisa de título");
                out = out ++ scenarioPasses(title, current_rule, feature_background, rule_background, &.{});
                mode = .Scenario;
                last_semantic = null;
                continue;
            }

            if (mode == .Examples and line[0] == '|') {
                const cells = parseTableRow(line, line_no);
                if (cells.len == 0) failAt(line_no, "linha de Examples sem células");

                if (example_headers.len == 0) {
                    example_headers = cells;
                } else {
                    out = out ++ outlineScenarioPasses(outline_title, current_rule, feature_background, rule_background, outline_steps, example_headers, cells, line_no);
                    outline_has_example_rows = true;
                }
                continue;
            }

            if (parseStepLine(line, line_no, last_semantic)) |step| {
                last_semantic = step.semantic_keyword;
                switch (mode) {
                    .FeatureBackground => feature_background = feature_background ++ .{step},
                    .RuleBackground => rule_background = rule_background ++ .{step},
                    .Scenario => out = out ++ .{parseSemanticStep(step)},
                    .ScenarioOutline => outline_steps = outline_steps ++ .{step},
                    .Examples => failAt(line_no, "steps não podem aparecer dentro da tabela Examples/Scenarios"),
                    .None => failAt(line_no, "step precisa estar dentro de Background, Scenario ou Scenario Outline"),
                }
                continue;
            }

            // Linhas descritivas livres são parte da linguagem Gherkin. Elas são preservadas como documentação,
            // mas este mini-runner não as executa.
        }

        if ((mode == .ScenarioOutline or mode == .Examples) and outline_title.len > 0 and !outline_has_example_rows) {
            failAt(line_no, "Scenario Outline precisa de pelo menos uma linha em Examples/Scenarios");
        }

        return out;
    }
}

fn runBDD(comptime Contexto: type, comptime passos: []const Passo) !void {
    var ctx = Contexto.init();
    var err: ?anyerror = null;

    inline for (passos) |passo| {
        switch (passo.kind) {
            .Feature => {
                std.debug.print("\n\x1b[35mFeature:\x1b[0m {s}\n", .{passo.desc});
            },
            .Rule => {
                std.debug.print("\n  \x1b[36mRule:\x1b[0m {s}\n", .{passo.desc});
            },
            .Scenario => {
                if (passo.rule.len > 0) {
                    std.debug.print("\n    \x1b[33mScenario:\x1b[0m {s} \x1b[90m[{s}]\x1b[0m\n", .{ passo.desc, passo.rule });
                } else {
                    std.debug.print("\n    \x1b[33mScenario:\x1b[0m {s}\n", .{passo.desc});
                }
                ctx = Contexto.init();
                err = null;
            },
            .Step => {
                std.debug.print("      \x1b[32m{s}\x1b[0m {s}\n", .{ passo.shown_keyword, passo.desc });

                switch (passo.action) {
                    .Doc => {},
                    .SetFields => {
                        if (err == null) {
                            @field(ctx, passo.k1) = passo.v1;
                            if (passo.k2.len > 0) @field(ctx, passo.k2) = passo.v2;
                        }
                    },
                    .CallAction => {
                        if (err == null) {
                            const metodo = @field(Contexto, passo.k1);
                            if (@call(.auto, metodo, .{ &ctx, passo.v1 })) |_| {} else |e| {
                                err = e;
                            }
                        }
                    },
                    .ExpectField => {
                        if (err) |e| return e;
                        const real = @field(ctx, passo.k1);
                        try expect(real == passo.v1);
                    },
                    .ExpectError => {
                        const expected_error = @field(anyerror, passo.expected_error_name);
                        if (err) |e| {
                            try expect(e == expected_error);
                            err = null;
                        } else {
                            return error.TestExpectedErrorButNoneThrown;
                        }
                    },
                }
            },
        }
    }
}

const ContaBancaria = struct {
    saldo: i32 = 0,
    limite: i32 = 0,
    audit: i32 = 0,

    pub fn init() ContaBancaria {
        return .{};
    }

    pub fn transferir(self: *ContaBancaria, valor: i32) !void {
        if (valor <= 0) return error.ValorInvalido;
        if (valor > self.saldo + self.limite) return error.SaldoInsuficiente;
        self.saldo -= valor;
        self.audit += 1;
    }

    pub fn depositar(self: *ContaBancaria, valor: i32) !void {
        if (valor <= 0) return error.ValorInvalido;
        self.saldo += valor;
        self.audit += 1;
    }

    pub fn definirLimite(self: *ContaBancaria, valor: i32) !void {
        if (valor < 0) return error.ValorInvalido;
        self.limite = valor;
        self.audit += 1;
    }
};

pub fn main() !void {
    const feature_text = @embedFile("testes.feature");
    const compiled_steps = comptime parseFeature(feature_text);
    try runBDD(ContaBancaria, compiled_steps);
}

test "Executar especificações BDD Gherkin em comptime" {
    const feature_text = @embedFile("testes.feature");
    const compiled_steps = comptime parseFeature(feature_text);
    try runBDD(ContaBancaria, compiled_steps);
}
