const std = @import("std");
const crypto = @import("crypto.zig");
const git = @import("git.zig");
const sealed_state = @import("sealed_state.zig");

/// JSON Serialization Mappings
pub const SnapshotBodyJson = struct {
    schema_version: []const u8,
    project_id: []const u8,
    environment: []const u8,
    operation: []const u8,
    secret_ref: []const u8, // hex
    epoch: u64,
    previous_snapshot_hash: []const u8, // hex
    created_at: []const u8,
    algorithm: AlgorithmDescriptorJson,
    aad: SnapshotAadJson,
    nonce: []const u8, // hex
    sealed_payload: []const u8, // hex
    auth_tag: []const u8, // hex
    wrapped_dek: []const u8, // hex
    wrap_nonce: []const u8, // hex
    wrap_auth_tag: []const u8, // hex
    dek_wrapping_key_id: []const u8,
    enclave_public_key_id: []const u8,
    consumer_public_key_id: []const u8,
};

pub const AlgorithmDescriptorJson = struct {
    content_encryption: []const u8,
    key_wrapping: []const u8,
    enclave_signature: []const u8,
    consumer_signature: []const u8,
};

pub const SnapshotAadJson = struct {
    project: []const u8,
    environment: []const u8,
    snapshot_type: []const u8,
    operation: []const u8,
    epoch: u64,
    previous_snapshot_hash: []const u8, // hex
};

pub const AttestationsJson = struct {
    enclave_signature: []const u8, // hex
    consumer_countersignature: []const u8, // hex
};

pub const PersistenceReceiptJson = struct {
    provider: []const u8,
    repository: []const u8,
    branch: []const u8,
    commit_sha: ?[]const u8,
    committed_at: ?[]const u8,
};

pub const SnapshotEnvelopeJson = struct {
    snapshot_body: SnapshotBodyJson,
    snapshot_id: []const u8, // hex
    attestations: AttestationsJson,
    persistence_receipt: ?PersistenceReceiptJson,
};

/// Conversion helpers from runtime binary to JSON serialization structs
fn toHexAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex = try allocator.alloc(u8, bytes.len * 2);
    const chars = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        hex[i * 2] = chars[b >> 4];
        hex[i * 2 + 1] = chars[b & 0x0f];
    }
    return hex;
}

pub fn fromEnvelopeToJson(allocator: std.mem.Allocator, env: crypto.SnapshotEnvelope) !SnapshotEnvelopeJson {
    const body = env.snapshot_body;
    
    const secret_ref_hex = try toHexAlloc(allocator, &body.secret_ref);
    errdefer allocator.free(secret_ref_hex);
    
    const prev_hash_hex = try toHexAlloc(allocator, &body.previous_snapshot_hash);
    errdefer allocator.free(prev_hash_hex);

    const nonce_hex = try toHexAlloc(allocator, &body.nonce);
    errdefer allocator.free(nonce_hex);

    const auth_tag_hex = try toHexAlloc(allocator, &body.auth_tag);
    errdefer allocator.free(auth_tag_hex);

    const wrap_nonce_hex = try toHexAlloc(allocator, &body.wrap_nonce);
    errdefer allocator.free(wrap_nonce_hex);

    const wrap_auth_tag_hex = try toHexAlloc(allocator, &body.wrap_auth_tag);
    errdefer allocator.free(wrap_auth_tag_hex);

    const aad_prev_hash_hex = try toHexAlloc(allocator, &body.aad.previous_snapshot_hash);
    errdefer allocator.free(aad_prev_hash_hex);

    const snapshot_id_hex = try toHexAlloc(allocator, &env.snapshot_id);
    errdefer allocator.free(snapshot_id_hex);

    const enclave_sig_hex = try toHexAlloc(allocator, &env.attestations.enclave_signature);
    errdefer allocator.free(enclave_sig_hex);

    const consumer_sig_hex = try toHexAlloc(allocator, &env.attestations.consumer_countersignature);
    errdefer allocator.free(consumer_sig_hex);

    const wrapped_dek_hex = try allocator.dupe(u8, body.wrapped_dek);
    errdefer allocator.free(wrapped_dek_hex);

    const sealed_payload_hex = try allocator.dupe(u8, body.sealed_payload);
    errdefer allocator.free(sealed_payload_hex);

    var receipt_json: ?PersistenceReceiptJson = null;
    if (env.persistence_receipt) |pr| {
        receipt_json = PersistenceReceiptJson{
            .provider = try allocator.dupe(u8, pr.provider),
            .repository = try allocator.dupe(u8, pr.repository),
            .branch = try allocator.dupe(u8, pr.branch),
            .commit_sha = if (pr.commit_sha) |sha| try allocator.dupe(u8, sha) else null,
            .committed_at = if (pr.committed_at) |ca| try allocator.dupe(u8, ca) else null,
        };
    }

    return SnapshotEnvelopeJson{
        .snapshot_body = .{
            .schema_version = try allocator.dupe(u8, body.schema_version),
            .project_id = try allocator.dupe(u8, body.project_id),
            .environment = try allocator.dupe(u8, body.environment),
            .operation = try allocator.dupe(u8, body.operation),
            .secret_ref = secret_ref_hex,
            .epoch = body.epoch,
            .previous_snapshot_hash = prev_hash_hex,
            .created_at = try allocator.dupe(u8, body.created_at),
            .algorithm = .{
                .content_encryption = try allocator.dupe(u8, body.algorithm.content_encryption),
                .key_wrapping = try allocator.dupe(u8, body.algorithm.key_wrapping),
                .enclave_signature = try allocator.dupe(u8, body.algorithm.enclave_signature),
                .consumer_signature = try allocator.dupe(u8, body.algorithm.consumer_signature),
            },
            .aad = .{
                .project = try allocator.dupe(u8, body.aad.project),
                .environment = try allocator.dupe(u8, body.aad.environment),
                .snapshot_type = try allocator.dupe(u8, body.aad.snapshot_type),
                .operation = try allocator.dupe(u8, body.aad.operation),
                .epoch = body.aad.epoch,
                .previous_snapshot_hash = aad_prev_hash_hex,
            },
            .nonce = nonce_hex,
            .sealed_payload = sealed_payload_hex,
            .auth_tag = auth_tag_hex,
            .wrapped_dek = wrapped_dek_hex,
            .wrap_nonce = wrap_nonce_hex,
            .wrap_auth_tag = wrap_auth_tag_hex,
            .dek_wrapping_key_id = try allocator.dupe(u8, body.dek_wrapping_key_id),
            .enclave_public_key_id = try allocator.dupe(u8, body.enclave_public_key_id),
            .consumer_public_key_id = try allocator.dupe(u8, body.consumer_public_key_id),
        },
        .snapshot_id = snapshot_id_hex,
        .attestations = .{
            .enclave_signature = enclave_sig_hex,
            .consumer_countersignature = consumer_sig_hex,
        },
        .persistence_receipt = receipt_json,
    };
}

pub fn freeEnvelopeJson(allocator: std.mem.Allocator, env: *SnapshotEnvelopeJson) void {
    const sb = env.snapshot_body;
    allocator.free(sb.schema_version);
    allocator.free(sb.project_id);
    allocator.free(sb.environment);
    allocator.free(sb.operation);
    allocator.free(sb.secret_ref);
    allocator.free(sb.previous_snapshot_hash);
    allocator.free(sb.created_at);
    allocator.free(sb.algorithm.content_encryption);
    allocator.free(sb.algorithm.key_wrapping);
    allocator.free(sb.algorithm.enclave_signature);
    allocator.free(sb.algorithm.consumer_signature);
    allocator.free(sb.aad.project);
    allocator.free(sb.aad.environment);
    allocator.free(sb.aad.snapshot_type);
    allocator.free(sb.aad.operation);
    allocator.free(sb.aad.previous_snapshot_hash);
    allocator.free(sb.nonce);
    allocator.free(sb.sealed_payload);
    allocator.free(sb.auth_tag);
    allocator.free(sb.wrapped_dek);
    allocator.free(sb.wrap_nonce);
    allocator.free(sb.wrap_auth_tag);
    allocator.free(sb.dek_wrapping_key_id);
    allocator.free(sb.enclave_public_key_id);
    allocator.free(sb.consumer_public_key_id);
    allocator.free(env.snapshot_id);
    allocator.free(env.attestations.enclave_signature);
    allocator.free(env.attestations.consumer_countersignature);
    if (env.persistence_receipt) |pr| {
        allocator.free(pr.provider);
        allocator.free(pr.repository);
        allocator.free(pr.branch);
        if (pr.commit_sha) |sha| allocator.free(sha);
        if (pr.committed_at) |ca| allocator.free(ca);
    }
}

pub fn fromJsonToEnvelope(allocator: std.mem.Allocator, json: SnapshotEnvelopeJson) !crypto.SnapshotEnvelope {
    const sb = json.snapshot_body;
    
    var secret_ref: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret_ref, sb.secret_ref);
    
    var previous_snapshot_hash: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&previous_snapshot_hash, sb.previous_snapshot_hash);

    var aad_prev_hash: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&aad_prev_hash, sb.aad.previous_snapshot_hash);

    var nonce: [12]u8 = undefined;
    _ = try std.fmt.hexToBytes(&nonce, sb.nonce);

    var auth_tag: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&auth_tag, sb.auth_tag);

    var wrap_nonce: [12]u8 = undefined;
    _ = try std.fmt.hexToBytes(&wrap_nonce, sb.wrap_nonce);

    var wrap_auth_tag: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&wrap_auth_tag, sb.wrap_auth_tag);

    var snapshot_id: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&snapshot_id, json.snapshot_id);

    var enclave_signature: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&enclave_signature, json.attestations.enclave_signature);

    var consumer_signature: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&consumer_signature, json.attestations.consumer_countersignature);

    var pr: ?crypto.PersistenceReceipt = null;
    if (json.persistence_receipt) |pr_json| {
        pr = crypto.PersistenceReceipt{
            .provider = try allocator.dupe(u8, pr_json.provider),
            .repository = try allocator.dupe(u8, pr_json.repository),
            .branch = try allocator.dupe(u8, pr_json.branch),
            .commit_sha = if (pr_json.commit_sha) |sha| try allocator.dupe(u8, sha) else null,
            .committed_at = if (pr_json.committed_at) |ca| try allocator.dupe(u8, ca) else null,
        };
    }

    return crypto.SnapshotEnvelope{
        .snapshot_body = .{
            .schema_version = try allocator.dupe(u8, sb.schema_version),
            .project_id = try allocator.dupe(u8, sb.project_id),
            .environment = try allocator.dupe(u8, sb.environment),
            .operation = try allocator.dupe(u8, sb.operation),
            .secret_ref = secret_ref,
            .epoch = sb.epoch,
            .previous_snapshot_hash = previous_snapshot_hash,
            .created_at = try allocator.dupe(u8, sb.created_at),
            .algorithm = .{
                .content_encryption = try allocator.dupe(u8, sb.algorithm.content_encryption),
                .key_wrapping = try allocator.dupe(u8, sb.algorithm.key_wrapping),
                .enclave_signature = try allocator.dupe(u8, sb.algorithm.enclave_signature),
                .consumer_signature = try allocator.dupe(u8, sb.algorithm.consumer_signature),
            },
            .aad = .{
                .project = try allocator.dupe(u8, sb.aad.project),
                .environment = try allocator.dupe(u8, sb.aad.environment),
                .snapshot_type = try allocator.dupe(u8, sb.aad.snapshot_type),
                .operation = try allocator.dupe(u8, sb.aad.operation),
                .epoch = sb.aad.epoch,
                .previous_snapshot_hash = aad_prev_hash,
            },
            .nonce = nonce,
            .sealed_payload = try allocator.dupe(u8, sb.sealed_payload),
            .auth_tag = auth_tag,
            .wrapped_dek = try allocator.dupe(u8, sb.wrapped_dek),
            .wrap_nonce = wrap_nonce,
            .wrap_auth_tag = wrap_auth_tag,
            .dek_wrapping_key_id = try allocator.dupe(u8, sb.dek_wrapping_key_id),
            .enclave_public_key_id = try allocator.dupe(u8, sb.enclave_public_key_id),
            .consumer_public_key_id = try allocator.dupe(u8, sb.consumer_public_key_id),
        },
        .snapshot_id = snapshot_id,
        .attestations = .{
            .enclave_signature = enclave_signature,
            .consumer_countersignature = consumer_signature,
        },
        .persistence_receipt = pr,
    };
}

pub fn freeEnvelope(allocator: std.mem.Allocator, env: *crypto.SnapshotEnvelope) void {
    const sb = env.snapshot_body;
    allocator.free(sb.schema_version);
    allocator.free(sb.project_id);
    allocator.free(sb.environment);
    allocator.free(sb.operation);
    allocator.free(sb.created_at);
    allocator.free(sb.algorithm.content_encryption);
    allocator.free(sb.algorithm.key_wrapping);
    allocator.free(sb.algorithm.enclave_signature);
    allocator.free(sb.algorithm.consumer_signature);
    allocator.free(sb.aad.project);
    allocator.free(sb.aad.environment);
    allocator.free(sb.aad.snapshot_type);
    allocator.free(sb.aad.operation);
    allocator.free(sb.sealed_payload);
    allocator.free(sb.wrapped_dek);
    allocator.free(sb.dek_wrapping_key_id);
    allocator.free(sb.enclave_public_key_id);
    allocator.free(sb.consumer_public_key_id);
    if (env.persistence_receipt) |pr| {
        allocator.free(pr.provider);
        allocator.free(pr.repository);
        allocator.free(pr.branch);
        if (pr.commit_sha) |sha| allocator.free(sha);
        if (pr.committed_at) |ca| allocator.free(ca);
    }
}

pub const PendingSnapshot = struct {
    envelope: crypto.SnapshotEnvelope,
    snapshot_id: [32]u8,
    epoch: u64,
};

pub const CommittedSnapshot = struct {
    envelope: crypto.SnapshotEnvelope,
    snapshot_id: [32]u8,
    epoch: u64,
    persistence_receipt: crypto.PersistenceReceipt,
};

pub const SecretWriteRequest = struct {
    project_id: []const u8,
    environment: []const u8,
    secret_name: []const u8,
    secret_value: []const u8,
};

pub const SecretWriteResult = struct {
    snapshot_id: [32]u8,
    epoch: u64,
    purged: bool,
    persistence_receipt: crypto.PersistenceReceipt,
};

// CVE-LSES-021: Return the current wall-clock time as an RFC 3339 / ISO 8601
// timestamp string allocated into `allocator`. Must not be hardcoded.
fn isoTimestamp(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    const now_ns = io.vtable.now(io.userdata, .real).nanoseconds;
    const unix_secs: u64 = @intCast(@divTrunc(now_ns, 1_000_000_000));
    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = unix_secs };
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch_secs.getDaySeconds();
    return try std.fmt.allocPrint(
        allocator,
        "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
        .{
            year_day.year,
            month_day.month.numeric(),
            @as(u8, month_day.day_index) + 1,
            day_secs.getHoursIntoDay(),
            day_secs.getMinutesIntoHour(),
            day_secs.getSecondsIntoMinute(),
        },
    );
}

/// Linus Salamander Enclave Storage Engine
pub const StorageEnclave = struct {
    secrets: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,
    io: std.Io,
    git_sync: git.GitSync,

    // Cryptographic Elements
    kek_provider: crypto.LocalDevKekProvider,
    enclave_identity: crypto.SigningIdentity,
    consumer_identity: crypto.SigningIdentity,
    nonce_registry: crypto.NonceRegistry,
    runtime_store: crypto.RuntimeSecretStore,

    trusted_chain_head: ?[32]u8,
    last_accepted_epoch: u64,
    policy: crypto.AccessPolicy,
    // MIASMA-WORM: operator-pinned set of enclave public keys. Populated from
    // LSES_TRUSTED_ENCLAVE_KEYS (comma-separated 64-char hex values) at startup.
    // Snapshots signed by any key NOT in this registry are rejected even if the
    // signature is cryptographically valid.
    trusted_enclave_key_list: []const [32]u8,
    trusted_key_registry: crypto.TrustedKeyRegistry,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, repo_path: []const u8) !StorageEnclave {
        // ── Material de chave via armazenamento selado ──────────────────────
        // KEK, ENCLAVE_SEED e CONSUMER_SEED são gerados pelo `lses-bootstrap`
        // (via `./scripts/lses-init.sh`) DENTRO do processo enclave e salvos
        // como um blob AES-256-GCM ligado à identidade desta máquina.
        // Nenhum segredo atravessa variáveis de ambiente, shell, histórico,
        // ou qualquer canal externo — o operador vê APENAS a chave pública.
        const sealed = try sealed_state.unsealKeys(allocator);
        var sk = sealed;
        // secureZero nos seeds após derivação — apenas os pares de chaves
        // derivados (e o kek copiado no kek_provider) persistem em memória.
        defer sk.deinit();

        const enclave_identity = blk: {
            const enc_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(sk.enclave_seed);
            const enc_pk_hex = std.fmt.bytesToHex(enc_kp.public_key.bytes, .lower);
            std.debug.print("[LSES] Enclave public key: {s}\n", .{&enc_pk_hex});
            break :blk crypto.SigningIdentity{
                .key_id      = "enclave_pk_1",
                .public_key  = enc_kp.public_key.bytes,
                .private_key = enc_kp.secret_key.toBytes(),
            };
        };

        const consumer_identity = blk: {
            const cons_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(sk.consumer_seed);
            break :blk crypto.SigningIdentity{
                .key_id      = "consumer_pk_1",
                .public_key  = cons_kp.public_key.bytes,
                .private_key = cons_kp.secret_key.toBytes(),
            };
        };

        // Policy
        const allowed = try allocator.alloc([]const u8, 1);
        allowed[0] = "consumer_pk_1";
        const policy = crypto.AccessPolicy{
            .allow_plaintext_export = true,
            .allowed_consumers = allowed,
        };

        // KEK copiado por valor de sk.kek — sk.deinit() zera a origem,
        // kek_provider.kek persiste apenas enquanto o StorageEnclave existe.
        const kek_provider = crypto.LocalDevKekProvider.initFromBytes("lses-kek", sk.kek);

        // ── Trusted enclave key registry ────────────────────────────────────
        // MIASMA-WORM: parse LSES_TRUSTED_ENCLAVE_KEYS (comma-separated 64-char
        // hex public keys). If the variable is absent the registry is empty and
        // the TrustedKeyRegistry check in VerificationContext is still enforced
        // (null registry = check skipped). Operators SHOULD set this in production.
        const trusted_key_list = blk: {
            const keys_env = std.process.getEnvVarOwned(allocator, "LSES_TRUSTED_ENCLAVE_KEYS") catch null;
            if (keys_env == null) {
                std.debug.print(
                    "[LSES WARN] LSES_TRUSTED_ENCLAVE_KEYS not set — trusted-key pinning disabled.\n" ++
                    "            Set it to a comma-separated list of trusted enclave public key hex strings.\n",
                    .{},
                );
                break :blk try allocator.alloc([32]u8, 0);
            }
            defer allocator.free(keys_env.?);
            // Count commas to size the list.
            var count: usize = 1;
            for (keys_env.?) |c| { if (c == ',') count += 1; }
            const list = try allocator.alloc([32]u8, count);
            errdefer allocator.free(list);
            var i: usize = 0;
            var it = std.mem.splitScalar(u8, keys_env.?, ',');
            while (it.next()) |hex_key| {
                const trimmed = std.mem.trim(u8, hex_key, " \t\r\n");
                if (trimmed.len != 64) return error.InvalidTrustedKeyHex;
                _ = try std.fmt.hexToBytes(&list[i], trimmed);
                i += 1;
            }
            break :blk list;
        };

        return StorageEnclave{
            .secrets = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
            .io = io,
            .git_sync = git.GitSync.init(allocator, repo_path),

            .kek_provider = kek_provider,
            .enclave_identity = enclave_identity,
            .consumer_identity = consumer_identity,
            .nonce_registry = crypto.NonceRegistry.init(allocator),
            .runtime_store = crypto.RuntimeSecretStore.init(allocator),

            .trusted_chain_head = null,
            .last_accepted_epoch = 0,
            .policy = policy,
            .trusted_enclave_key_list = trusted_key_list,
            .trusted_key_registry = crypto.TrustedKeyRegistry{ .keys = trusted_key_list },
        };
    }

    pub fn deinit(self: *StorageEnclave) void {
        var it = self.secrets.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.secrets.deinit();
        self.nonce_registry.deinit();
        self.runtime_store.deinit();
        self.allocator.free(self.trusted_enclave_key_list);
        self.allocator.free(self.policy.allowed_consumers);
        // Zero all key material before releasing — prevents scraping from freed heap
        std.crypto.secureZero(u8, &self.kek_provider.kek);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.enclave_identity.private_key));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.consumer_identity.private_key));
    }

    pub fn buildPendingSnapshot(
        self: *StorageEnclave,
        allocator: std.mem.Allocator,
        request: SecretWriteRequest,
    ) !PendingSnapshot {
        // 1. Serialize data to raw plaintext
        var list = std.ArrayList(u8).empty;
        defer list.deinit(allocator);
        
        var it = self.secrets.iterator();
        while (it.next()) |entry| {
            try list.appendSlice(allocator, entry.key_ptr.*);
            try list.appendSlice(allocator, ":");
            try list.appendSlice(allocator, entry.value_ptr.*);
            try list.appendSlice(allocator, "\n");
        }

        // 2. Ephemeral symmetric key
        var dek: [32]u8 = undefined;
        crypto.EnclaveCrypto.randomBytes(&dek);
        defer crypto.secureZero(&dek);

        // 3. Nonce
        var nonce: [12]u8 = undefined;
        crypto.EnclaveCrypto.randomBytes(&nonce);

        var previous_snapshot_hash = [32]u8{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        if (self.trusted_chain_head) |head| {
            previous_snapshot_hash = head;
        }

        const next_epoch = self.last_accepted_epoch + 1;

        const aad_data = crypto.SnapshotAad{
            .project = request.project_id,
            .environment = request.environment,
            .snapshot_type = "secret",
            .operation = "write_secret",
            .epoch = next_epoch,
            .previous_snapshot_hash = previous_snapshot_hash,
        };
        const canonical_aad = try crypto.canonicalizeAad(allocator, aad_data);
        defer allocator.free(canonical_aad);

        const sealed = try crypto.sealPayload(allocator, list.items, &dek, nonce, canonical_aad);
        defer allocator.free(sealed.ciphertext);

        // 4. Wrap DEK — use the same canonical_aad that sealed the payload so the
        // wrapped DEK is cryptographically bound to this specific snapshot context.
        // CVE-LSES-012: was using kek_provider.key_id only, letting any same-KEK
        // snapshot reuse this wrapped DEK.
        const wrapped = try self.kek_provider.provider().wrap(allocator, &dek, canonical_aad);

        const sealed_payload_hex = try toHexAlloc(allocator, sealed.ciphertext);
        errdefer allocator.free(sealed_payload_hex);

        const wrapped_dek_hex = try toHexAlloc(allocator, &wrapped.wrapped_dek);
        errdefer allocator.free(wrapped_dek_hex);

        // 5. Derive secret_ref
        const secret_ref = crypto.computeSecretRef(request.project_id, request.environment, request.secret_name);

        const snapshot_body = crypto.SnapshotBody{
            .schema_version = try allocator.dupe(u8, "lses.snapshot.v1"),
            .project_id = try allocator.dupe(u8, request.project_id),
            .environment = try allocator.dupe(u8, request.environment),
            .operation = try allocator.dupe(u8, "write_secret"),
            .secret_ref = secret_ref,
            .epoch = next_epoch,
            .previous_snapshot_hash = previous_snapshot_hash,
            .created_at = try isoTimestamp(allocator, self.io), // CVE-LSES-021
            .algorithm = .{
                .content_encryption = try allocator.dupe(u8, "AES-256-GCM"),
                .key_wrapping = try allocator.dupe(u8, "LOCAL-DEV-AES-256-GCM"),
                .enclave_signature = try allocator.dupe(u8, "Ed25519"),
                .consumer_signature = try allocator.dupe(u8, "Ed25519"),
            },
            .aad = .{
                .project = try allocator.dupe(u8, request.project_id),
                .environment = try allocator.dupe(u8, request.environment),
                .snapshot_type = try allocator.dupe(u8, "secret"),
                .operation = try allocator.dupe(u8, "write_secret"),
                .epoch = next_epoch,
                .previous_snapshot_hash = previous_snapshot_hash,
            },
            .nonce = nonce,
            .sealed_payload = sealed_payload_hex,
            .auth_tag = sealed.auth_tag,
            .wrapped_dek = wrapped_dek_hex,
            .wrap_nonce = wrapped.wrap_nonce,
            .wrap_auth_tag = wrapped.wrap_auth_tag,
            .dek_wrapping_key_id = try allocator.dupe(u8, self.kek_provider.key_id),
            .enclave_public_key_id = try allocator.dupe(u8, self.enclave_identity.key_id),
            .consumer_public_key_id = try allocator.dupe(u8, self.consumer_identity.key_id),
        };
        errdefer {
            allocator.free(snapshot_body.schema_version);
            allocator.free(snapshot_body.project_id);
            allocator.free(snapshot_body.environment);
            allocator.free(snapshot_body.operation);
            allocator.free(snapshot_body.created_at);
            allocator.free(snapshot_body.algorithm.content_encryption);
            allocator.free(snapshot_body.algorithm.key_wrapping);
            allocator.free(snapshot_body.algorithm.enclave_signature);
            allocator.free(snapshot_body.algorithm.consumer_signature);
            allocator.free(snapshot_body.aad.project);
            allocator.free(snapshot_body.aad.environment);
            allocator.free(snapshot_body.aad.snapshot_type);
            allocator.free(snapshot_body.aad.operation);
            allocator.free(snapshot_body.dek_wrapping_key_id);
            allocator.free(snapshot_body.enclave_public_key_id);
            allocator.free(snapshot_body.consumer_public_key_id);
        }

        // 6. Compute snapshot_id
        const canonical_body = try crypto.canonicalizeSnapshotBody(allocator, snapshot_body);
        defer allocator.free(canonical_body);
        const snapshot_id = crypto.computeSnapshotId(canonical_body);

        // 7. Signature input & sign
        const signature_input = try crypto.canonicalizeSignatureInput(allocator, snapshot_id, snapshot_body);
        defer allocator.free(signature_input);

        const enclave_sig = try crypto.signEd25519(signature_input, self.enclave_identity.private_key.?);
        const consumer_sig = try crypto.signEd25519(signature_input, self.consumer_identity.private_key.?);

        const envelope = crypto.SnapshotEnvelope{
            .snapshot_body = snapshot_body,
            .snapshot_id = snapshot_id,
            .attestations = .{
                .enclave_signature = enclave_sig,
                .consumer_countersignature = consumer_sig,
            },
            .persistence_receipt = null,
        };

        return PendingSnapshot{
            .envelope = envelope,
            .snapshot_id = snapshot_id,
            .epoch = next_epoch,
        };
    }

    pub fn persistEnvelope(
        self: *StorageEnclave,
        allocator: std.mem.Allocator,
        envelope_without_receipt: crypto.SnapshotEnvelope,
    ) !crypto.PersistenceReceipt {
        const filename = "enclave.sealed.json";
        
        // 1. Write the initial envelope JSON (with null receipt) to disk
        var initial_env = envelope_without_receipt;
        initial_env.persistence_receipt = null;
        try self.saveEnvelopeJson(allocator, initial_env);

        // 2. Perform git commit/push if repo path is non-empty
        if (self.git_sync.repo_path.len > 0) {
            var sync = git.GitSync.init(allocator, self.git_sync.repo_path);
            
            // git add filename
            sync.runGit(self.io, &.{ "add", filename }) catch {
                return crypto.LsesError.PersistenceFailed;
            };

            // git commit — identity comes from system git config or the standard
            // GIT_AUTHOR_NAME / GIT_AUTHOR_EMAIL / GIT_COMMITTER_* env vars.
            // CVE-LSES-020: hardcoded identity strings were removed; operators must
            // configure git identity through the standard git config mechanism.
            var msg_buf: [128]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "feat(vault): persist snapshot epoch {d}", .{envelope_without_receipt.snapshot_body.epoch}) catch "feat(vault): snapshot update";
            _ = sync.runGit(self.io, &.{ "commit", "-m", msg }) catch {}; // Commit failure is soft

            // git push
            sync.runGit(self.io, &.{ "push", "origin", "main" }) catch {
                std.debug.print("[LSES Warning] Git push failed (offline/no remote origin). Snapshot committed locally.\n", .{});
            };

            // Query commit SHA (no identity flags needed — rev-parse is read-only)
            var sha_args = std.ArrayList([]const u8).empty;
            defer sha_args.deinit(allocator);
            try sha_args.append(allocator, "git");
            try sha_args.append(allocator, "rev-parse");
            try sha_args.append(allocator, "HEAD");

            const run_res = std.process.run(allocator, self.io, .{
                .argv = sha_args.items,
                .cwd = .{ .path = self.git_sync.repo_path },
                .reserve_amount = 64,
            }) catch {
                return crypto.PersistenceReceipt{
                    .provider = try allocator.dupe(u8, "github"),
                    .repository = try allocator.dupe(u8, "owner/repo"),
                    .branch = try allocator.dupe(u8, "main"),
                    .commit_sha = try allocator.dupe(u8, "unknown_sha"),
                    .committed_at = try isoTimestamp(allocator, self.io), // CVE-LSES-021
                };
            };
            defer allocator.free(run_res.stdout);
            defer allocator.free(run_res.stderr);

            var success = false;
            switch (run_res.term) {
                .exited => |code| {
                    if (code == 0 and run_res.stdout.len >= 40) {
                        success = true;
                    }
                },
                else => {},
            }

            const sha_str = if (success) try allocator.dupe(u8, run_res.stdout[0..40]) else try allocator.dupe(u8, "unknown_sha");

            return crypto.PersistenceReceipt{
                .provider = try allocator.dupe(u8, "github"),
                .repository = try allocator.dupe(u8, "owner/repo"),
                .branch = try allocator.dupe(u8, "main"),
                .commit_sha = sha_str,
                .committed_at = try isoTimestamp(allocator, self.io), // CVE-LSES-021
            };
        }

        // 3. Fallback / local dev persistence receipt — all fields allocated so
        // callers can safely free them uniformly (matches the allocated-string
        // contract of the git path above).
        return crypto.PersistenceReceipt{
            .provider = try allocator.dupe(u8, "local"),
            .repository = try allocator.dupe(u8, "local-dev"),
            .branch = try allocator.dupe(u8, "main"),
            .commit_sha = null,
            .committed_at = try isoTimestamp(allocator, self.io), // CVE-LSES-021
        };
    }

    pub fn saveEnvelopeJson(self: *StorageEnclave, allocator: std.mem.Allocator, envelope: crypto.SnapshotEnvelope) !void {
        var envelope_json = try fromEnvelopeToJson(allocator, envelope);
        defer freeEnvelopeJson(allocator, &envelope_json);

        const filename = "enclave.sealed.json";
        const file = try std.Io.Dir.cwd().createFile(self.io, filename, .{});
        defer file.close(self.io);
        var write_buf: [4096]u8 = undefined;
        var file_writer = file.writer(self.io, &write_buf);
        try std.json.Stringify.value(envelope_json, .{}, &file_writer.interface);
        try file_writer.flush();
    }

    pub fn writeSecret(
        self: *StorageEnclave,
        allocator: std.mem.Allocator,
        request: SecretWriteRequest,
    ) !SecretWriteResult {
        const dup_key = try self.allocator.dupe(u8, request.secret_name);
        const dup_val = try self.allocator.dupe(u8, request.secret_value);
        var committed_to_map = false;

        errdefer {
            if (!committed_to_map) {
                self.allocator.free(dup_key);
                self.allocator.free(dup_val);
            }
        }

        const old_val = try self.secrets.fetchPut(dup_key, dup_val);
        committed_to_map = true;

        errdefer {
            if (old_val) |ov| {
                _ = self.secrets.put(dup_key, ov.value) catch {};
                self.allocator.free(dup_val);
            } else {
                _ = self.secrets.remove(dup_key);
                self.allocator.free(dup_key);
                self.allocator.free(dup_val);
            }
        }

        const pending = try self.buildPendingSnapshot(allocator, request);
        errdefer {
            var env_to_free = pending.envelope;
            freeEnvelope(self.allocator, &env_to_free);
        }

        const receipt = try self.persistEnvelope(allocator, pending.envelope);
        errdefer {
            if (receipt.commit_sha) |sha| allocator.free(sha);
        }

        var committed_envelope = pending.envelope;
        committed_envelope.persistence_receipt = receipt;

        try self.saveEnvelopeJson(allocator, committed_envelope);

        // Update crypto states only after absolute success
        self.trusted_chain_head = pending.snapshot_id;
        self.last_accepted_epoch = pending.epoch;

        if (old_val) |ov| {
            self.allocator.free(ov.key);
            self.allocator.free(ov.value);
        }

        committed_envelope.persistence_receipt = null;
        freeEnvelope(self.allocator, &committed_envelope);

        return SecretWriteResult{
            .snapshot_id = pending.snapshot_id,
            .epoch = pending.epoch,
            .purged = true,
            .persistence_receipt = receipt,
        };
    }

    pub fn putSecret(self: *StorageEnclave, key: []const u8, value: []const u8) !void {
        const res = try self.writeSecret(self.allocator, .{
            .project_id = "allascode",
            .environment = "prod",
            .secret_name = key,
            .secret_value = value,
        });
        if (res.persistence_receipt.commit_sha) |sha| {
            self.allocator.free(sha);
        }
        self.allocator.free(res.persistence_receipt.provider);
        self.allocator.free(res.persistence_receipt.repository);
        self.allocator.free(res.persistence_receipt.branch);
        if (res.persistence_receipt.committed_at) |ca| {
            self.allocator.free(ca);
        }
    }

    pub fn readSecret(self: *StorageEnclave, expected_consumer: []const u8) !crypto.RuntimeSecretHandle {
        const filename = "enclave.sealed.json";
        const file = std.Io.Dir.cwd().openFile(self.io, filename, .{}) catch return error.FileNotFound;
        defer file.close(self.io);
        var read_buf: [4096]u8 = undefined;
        var r = file.reader(self.io, &read_buf);
        const json_data = try r.interface.allocRemaining(self.allocator, std.Io.Limit.limited(1024 * 1024));
        defer self.allocator.free(json_data);

        var parsed = try std.json.parseFromSlice(SnapshotEnvelopeJson, self.allocator, json_data, .{});
        defer parsed.deinit();

        var envelope = try fromJsonToEnvelope(self.allocator, parsed.value);
        defer freeEnvelope(self.allocator, &envelope);

        const providers = try self.allocator.alloc(crypto.KekProvider, 1);
        defer self.allocator.free(providers);
        providers[0] = self.kek_provider.provider();
        
        var kek_resolver = crypto.KekResolver{ .providers = providers };

        const vk = crypto.VerificationKeys{
            .enclave_key_id = self.enclave_identity.key_id,
            .enclave_public_key = self.enclave_identity.public_key,
            .consumer_key_id = self.consumer_identity.key_id,
            .consumer_public_key = self.consumer_identity.public_key,
        };

        // CVE-LSES-018: Propagate the last accepted epoch so the verifier can
        // detect rollback attacks (epoch must be strictly greater than this value).
        // Previously set to 0, which allowed an attacker to replay any old snapshot
        // regardless of the enclave's current epoch counter.
        //
        // Also switch to .strict mode when a chain head is known: without it the
        // verifier skips the MissingTrustAnchor check, allowing bootstrap of an
        // entirely forged chain against an enclave that already has a trust anchor.
        // MIASMA-WORM: pass the trusted key registry so verifySnapshot can reject
        // snapshots signed by any key that isn't in the operator-pinned set.
        // When the registry is empty (operator hasn't configured it) the trusted_enclave_keys
        // field is null and the check is skipped — operators SHOULD configure it.
        const registry_ptr: ?*const crypto.TrustedKeyRegistry =
            if (self.trusted_key_registry.keys.len > 0) &self.trusted_key_registry else null;

        var ctx = crypto.VerificationContext{
            .mode = if (self.trusted_chain_head != null) .strict else .recovery_limited,
            .trusted_chain_head = self.trusted_chain_head,
            .last_accepted_epoch = self.last_accepted_epoch,
            .verification_keys = vk,
            .policy = self.policy,
            .nonce_registry = &self.nonce_registry,
            .kek_resolver = &kek_resolver,
            .trusted_enclave_keys = registry_ptr,
        };

        const result = try crypto.readSecret(
            self.allocator,
            .{
                .project_id = "allascode",
                .environment = "prod",
                .secret_name = "secret",
                .consumer_id = expected_consumer,
                .export_plaintext = false,
            },
            envelope,
            &ctx,
            &self.runtime_store,
            @intCast(@divTrunc(self.io.vtable.now(self.io.userdata, .real).nanoseconds, 1_000_000_000)),
        );

        return result.handle;
    }

    pub fn takeSnapshot(self: *StorageEnclave) !crypto.PersistenceReceipt {
        std.debug.print("Linus Salamander: Triggering State-of-the-Art Snapshot...\n", .{});
        
        const pending = try self.buildPendingSnapshot(self.allocator, .{
            .project_id = "allascode",
            .environment = "prod",
            .secret_name = "secret",
            .secret_value = "",
        });
        var env_to_free = pending.envelope;
        defer freeEnvelope(self.allocator, &env_to_free);

        const receipt = try self.persistEnvelope(self.allocator, pending.envelope);

        var committed_envelope = pending.envelope;
        committed_envelope.persistence_receipt = receipt;

        try self.saveEnvelopeJson(self.allocator, committed_envelope);

        self.trusted_chain_head = pending.snapshot_id;

        return receipt;
    }
};
