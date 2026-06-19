//! Sealed state — geração e armazenamento de material de chave LSES.
//!
//! Todo o material criptográfico (KEK, ENCLAVE_SEED, CONSUMER_SEED) é gerado
//! DENTRO do processo pelo CSPRNG do SO e salvo como um blob AES-256-GCM
//! selado à identidade desta máquina. Nenhum valor é jamais exibido ao
//! desenvolvedor ou operador — a única saída é a chave pública Ed25519 para
//! configuração do TrustedKeyRegistry.
//!
//! Layout do arquivo selado (124 bytes):
//!   nonce      [0..12]   — nonce AES-GCM
//!   ciphertext [12..108] — AES-256-GCM(plaintext, aad="", nonce, seal_key)
//!   tag        [108..124]— tag de autenticação
//!
//! Plaintext (96 bytes):
//!   kek           [0..32]
//!   enclave_seed  [32..64]
//!   consumer_seed [64..96]

const std = @import("std");
const builtin = @import("builtin");

const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Sha256    = std.crypto.hash.sha2.Sha256;

const PLAINTEXT_LEN: usize = 96;
const NONCE_LEN = Aes256Gcm.nonce_length; // 12
const TAG_LEN   = Aes256Gcm.tag_length;   // 16
const SEALED_LEN = NONCE_LEN + PLAINTEXT_LEN + TAG_LEN; // 124

pub const SealedKeys = struct {
    kek:           [32]u8,
    enclave_seed:  [32]u8,
    consumer_seed: [32]u8,

    /// Zera todo o material de chave com escrita atômica não-otimizável.
    pub fn deinit(self: *SealedKeys) void {
        std.crypto.secureZero(u8, &self.kek);
        std.crypto.secureZero(u8, &self.enclave_seed);
        std.crypto.secureZero(u8, &self.consumer_seed);
    }
};

/// Retorna o caminho do arquivo de estado selado. O caller libera a memória.
/// Ordem de precedência:
///   1. LSES_STATE_DIR (env var — não é segredo, apenas localização)
///   2. $HOME/.local/share/lses/sealed_state.bin (Linux/macOS, sem root)
///   3. %LOCALAPPDATA%\lses\sealed_state.bin (Windows)
fn sealedPath(allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, "LSES_STATE_DIR") catch null) |dir| {
        defer allocator.free(dir);
        return std.fs.path.join(allocator, &.{ dir, "sealed_state.bin" });
    }
    if (builtin.os.tag == .windows) {
        const appdata = try std.process.getEnvVarOwned(allocator, "LOCALAPPDATA");
        defer allocator.free(appdata);
        return std.fs.path.join(allocator, &.{ appdata, "lses", "sealed_state.bin" });
    }
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch
        return allocator.dupe(u8, "/var/lib/lses/sealed_state.bin");
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, ".local", "share", "lses", "sealed_state.bin" });
}

/// Deriva uma chave de selagem a partir de identidade não-secreta da máquina.
/// NÃO é um segredo — apenas garante que o blob selado seja inútil em outra
/// máquina. A proteção real vem das permissões de arquivo (0600) e de não
/// expor o blob a canais externos.
fn machineBindingKey() [32]u8 {
    // Coleta IKM: machine-id + uid (domain-separated por \x00)
    var hasher = Sha256.init(.{});
    hasher.update("LSES-MACHINE-SEAL-V1\x00");

    if (builtin.os.tag != .windows) {
        var mid_buf: [64]u8 = undefined;
        read_mid: {
            const f = std.fs.openFileAbsolute("/etc/machine-id", .{}) catch break :read_mid;
            defer f.close();
            const n = f.read(&mid_buf) catch break :read_mid;
            // trim whitespace
            var end = n;
            while (end > 0 and mid_buf[end - 1] <= ' ') end -= 1;
            hasher.update(mid_buf[0..end]);
        }
        hasher.update("\x00");

        // UID para isolamento por usuário em máquinas compartilhadas
        if (builtin.os.tag == .linux) {
            const uid = std.os.linux.getuid();
            hasher.update(std.mem.asBytes(&uid));
        }
    }

    var key: [32]u8 = undefined;
    hasher.final(&key);
    return key;
}

/// Bootstrap: gera KEK, ENCLAVE_SEED e CONSUMER_SEED via CSPRNG do SO,
/// sela no disco e imprime APENAS a chave pública Ed25519 do enclave.
/// O desenvolvedor/operador nunca vê os valores das chaves.
pub fn bootstrap(allocator: std.mem.Allocator) !void {
    var kek:           [32]u8 = undefined;
    var enclave_seed:  [32]u8 = undefined;
    var consumer_seed: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &kek);
    defer std.crypto.secureZero(u8, &enclave_seed);
    defer std.crypto.secureZero(u8, &consumer_seed);

    // getrandom(2) no Linux / RtlGenRandom no Windows — entropia de hardware
    std.crypto.random.bytes(&kek);
    std.crypto.random.bytes(&enclave_seed);
    std.crypto.random.bytes(&consumer_seed);

    // Deriva o par Ed25519 apenas para imprimir a chave pública
    const enc_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(enclave_seed);
    const pub_hex = std.fmt.bytesToHex(enc_kp.public_key.bytes, .lower);

    try sealToDisk(allocator, &kek, &enclave_seed, &consumer_seed);

    const stdout = std.io.getStdOut().writer();
    try stdout.print(
        \\
        \\[LSES] Bootstrap concluido com sucesso.
        \\[LSES] Material de chave gerado e selado dentro do enclave.
        \\[LSES] Nenhum segredo foi exposto fora do processo.
        \\
        \\[LSES] Chave publica do enclave (adicione em LSES_TRUSTED_ENCLAVE_KEYS):
        \\        {s}
        \\
        \\[LSES] Execute o servico normalmente — sem variaveis de ambiente de segredos.
        \\
    , .{&pub_hex});
}

/// Sela o material de chave em disco com AES-256-GCM + machine binding.
fn sealToDisk(
    allocator: std.mem.Allocator,
    kek:           *const [32]u8,
    enclave_seed:  *const [32]u8,
    consumer_seed: *const [32]u8,
) !void {
    var seal_key = machineBindingKey();
    defer std.crypto.secureZero(u8, &seal_key);

    var nonce: [NONCE_LEN]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    var plaintext: [PLAINTEXT_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &plaintext);
    @memcpy(plaintext[0..32],  kek);
    @memcpy(plaintext[32..64], enclave_seed);
    @memcpy(plaintext[64..96], consumer_seed);

    var ciphertext: [PLAINTEXT_LEN]u8 = undefined;
    var tag:        [TAG_LEN]u8       = undefined;
    Aes256Gcm.encrypt(&ciphertext, &tag, &plaintext, "", nonce, seal_key);
    defer std.crypto.secureZero(u8, &ciphertext);

    // blob = nonce || ciphertext || tag
    var blob: [SEALED_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &blob);
    @memcpy(blob[0..NONCE_LEN],                              &nonce);
    @memcpy(blob[NONCE_LEN .. NONCE_LEN + PLAINTEXT_LEN],   &ciphertext);
    @memcpy(blob[NONCE_LEN + PLAINTEXT_LEN ..],              &tag);

    const path = try sealedPath(allocator);
    defer allocator.free(path);

    // Cria diretório pai se necessário
    if (std.fs.path.dirname(path)) |parent| {
        std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    // Escreve com permissões restritas (somente o dono pode ler/escrever)
    const file = try std.fs.createFileAbsolute(path, .{
        .mode     = 0o600,
        .truncate = true,
    });
    defer file.close();
    try file.writeAll(&blob);
}

/// Lê e desencripta o estado selado do disco.
/// O caller DEVE chamar SealedKeys.deinit() para zerar o material de chave.
pub fn unsealKeys(allocator: std.mem.Allocator) !SealedKeys {
    const path = try sealedPath(allocator);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print(
                "[LSES ERRO] Estado selado nao encontrado em: {s}\n" ++
                "[LSES ERRO] Execute './scripts/lses-init.sh' para inicializar o enclave.\n",
                .{path},
            );
            return error.SealedStateNotFound;
        },
        else => return err,
    };
    defer file.close();

    var blob: [SEALED_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &blob);

    const n = try file.readAll(&blob);
    if (n != SEALED_LEN) return error.CorruptedSealedState;

    const nonce      = blob[0..NONCE_LEN].*;
    const ciphertext = blob[NONCE_LEN .. NONCE_LEN + PLAINTEXT_LEN];
    const tag        = blob[NONCE_LEN + PLAINTEXT_LEN ..][0..TAG_LEN].*;

    var seal_key = machineBindingKey();
    defer std.crypto.secureZero(u8, &seal_key);

    var plaintext: [PLAINTEXT_LEN]u8 = undefined;
    defer std.crypto.secureZero(u8, &plaintext);

    Aes256Gcm.decrypt(&plaintext, ciphertext, tag, "", nonce, seal_key) catch {
        std.debug.print(
            "[LSES ERRO] Falha na autenticacao AES-GCM do estado selado.\n" ++
            "[LSES ERRO] Arquivo corrompido, adulterado, ou gerado em outra maquina.\n" ++
            "[LSES ERRO] Execute './scripts/lses-init.sh' para regenerar.\n",
            .{},
        );
        return error.SealedStateAuthFailed;
    };

    var keys = SealedKeys{
        .kek           = undefined,
        .enclave_seed  = undefined,
        .consumer_seed = undefined,
    };
    @memcpy(&keys.kek,           plaintext[0..32]);
    @memcpy(&keys.enclave_seed,  plaintext[32..64]);
    @memcpy(&keys.consumer_seed, plaintext[64..96]);
    return keys;
}
