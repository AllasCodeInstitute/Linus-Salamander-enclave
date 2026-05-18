const std = @import("std");
const crypto = @import("crypto.zig");
const git = @import("git.zig");

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
    algorithm: AlgorithmSpecJson,
    aad: AadSpecJson,
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

pub const AlgorithmSpecJson = struct {
    content_encryption: []const u8,
    key_wrapping: []const u8,
    enclave_signature: []const u8,
    consumer_signature: []const u8,
};

pub const AadSpecJson = struct {
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
    commit_sha: []const u8,
    committed_at: ?[]const u8,
};

pub const CryptographicEnvelopeJson = struct {
    snapshot_body: SnapshotBodyJson,
    snapshot_id: []const u8, // hex
    attestations: AttestationsJson,
    persistence_receipt: ?PersistenceReceiptJson,
};

/// Conversion helpers from runtime binary to JSON serialization structs
pub fn fromEnvelopeToJson(allocator: std.mem.Allocator, env: crypto.CryptographicEnvelope) !CryptographicEnvelopeJson {
    const body = env.snapshot_body;
    
    const secret_ref_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&body.secret_ref)});
    errdefer allocator.free(secret_ref_hex);
    
    const prev_hash_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&body.previous_snapshot_hash)});
    errdefer allocator.free(prev_hash_hex);

    const nonce_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&body.nonce)});
    errdefer allocator.free(nonce_hex);

    const auth_tag_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&body.auth_tag)});
    errdefer allocator.free(auth_tag_hex);

    const wrap_nonce_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&body.wrap_nonce)});
    errdefer allocator.free(wrap_nonce_hex);

    const wrap_auth_tag_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&body.wrap_auth_tag)});
    errdefer allocator.free(wrap_auth_tag_hex);

    const aad_prev_hash_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&body.aad.previous_snapshot_hash)});
    errdefer allocator.free(aad_prev_hash_hex);

    const snapshot_id_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&env.snapshot_id)});
    errdefer allocator.free(snapshot_id_hex);

    const enclave_sig_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&env.attestations.enclave_signature)});
    errdefer allocator.free(enclave_sig_hex);

    const consumer_sig_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&env.attestations.consumer_countersignature)});
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
            .commit_sha = try allocator.dupe(u8, pr.commit_sha),
            .committed_at = if (pr.committed_at) |ca| try allocator.dupe(u8, ca) else null,
        };
    }

    return CryptographicEnvelopeJson{
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

pub fn freeEnvelopeJson(allocator: std.mem.Allocator, env: *CryptographicEnvelopeJson) void {
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
        allocator.free(pr.commit_sha);
        if (pr.committed_at) |ca| allocator.free(ca);
    }
}

pub fn fromJsonToEnvelope(allocator: std.mem.Allocator, json: CryptographicEnvelopeJson) !crypto.CryptographicEnvelope {
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
            .commit_sha = try allocator.dupe(u8, pr_json.commit_sha),
            .committed_at = if (pr_json.committed_at) |ca| try allocator.dupe(u8, ca) else null,
        };
    }

    return crypto.CryptographicEnvelope{
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

pub fn freeEnvelope(allocator: std.mem.Allocator, env: *crypto.CryptographicEnvelope) void {
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
        allocator.free(pr.commit_sha);
        if (pr.committed_at) |ca| allocator.free(ca);
    }
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

    pub fn init(allocator: std.mem.Allocator, io: std.Io, repo_path: []const u8) !StorageEnclave {
        // Enclave keys
        var enc_seed: [32]u8 = undefined;
        crypto.EnclaveCrypto.randomBytes(&enc_seed);
        const enc_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(enc_seed);
        const enc_private = enc_kp.secret_key.toBytes();

        const enclave_identity = crypto.SigningIdentity{
            .key_id = "enclave_pk_1",
            .public_key = enc_kp.public_key.bytes,
            .private_key = enc_private,
        };

        // Consumer keys
        var cons_seed: [32]u8 = undefined;
        crypto.EnclaveCrypto.randomBytes(&cons_seed);
        const cons_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(cons_seed);
        const cons_private = cons_kp.secret_key.toBytes();

        const consumer_identity = crypto.SigningIdentity{
            .key_id = "consumer_pk_1",
            .public_key = cons_kp.public_key.bytes,
            .private_key = cons_private,
        };

        // Policy
        const allowed = try allocator.alloc([]const u8, 1);
        allowed[0] = "consumer_pk_1";

        const policy = crypto.AccessPolicy{
            .allow_plaintext_export = true,
            .allowed_consumers = allowed,
        };

        return StorageEnclave{
            .secrets = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
            .io = io,
            .git_sync = git.GitSync.init(allocator, repo_path),
            
            .kek_provider = try crypto.LocalDevKekProvider.initFromHex(
                "local-dev-kek-001",
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            ),
            .enclave_identity = enclave_identity,
            .consumer_identity = consumer_identity,
            .nonce_registry = crypto.NonceRegistry.init(allocator),
            .runtime_store = crypto.RuntimeSecretStore.init(allocator),
            
            .trusted_chain_head = null,
            .last_accepted_epoch = 0,
            .policy = policy,
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
        self.allocator.free(self.policy.allowed_consumers);
    }

    pub fn putSecret(self: *StorageEnclave, key: []const u8, value: []const u8) !void {
        try self.secrets.put(try self.allocator.dupe(u8, key), try self.allocator.dupe(u8, value));
        const receipt = try self.takeSnapshot();
        self.last_accepted_epoch += 1;
        // In a real system, the receipt's commit SHA would update our local state cache index
        _ = receipt;
    }

    pub fn readSecret(self: *StorageEnclave, expected_consumer: []const u8) !crypto.RuntimeSecretHandle {
        const filename = "enclave.sealed.json";
        const file = std.Io.Dir.cwd().openFile(self.io, filename, .{}) catch return error.FileNotFound;
        defer file.close(self.io);
        var read_buf: [4096]u8 = undefined;
        var r = file.reader(self.io, &read_buf);
        const json_data = try r.interface.allocRemaining(self.allocator, std.Io.Limit.limited(1024 * 1024));
        defer self.allocator.free(json_data);

        var parsed = try std.json.parseFromSlice(CryptographicEnvelopeJson, self.allocator, json_data, .{});
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

        var ctx = crypto.VerificationContext{
            .mode = .recovery_limited,
            .trusted_chain_head = self.trusted_chain_head,
            .last_accepted_epoch = 0,
            .verification_keys = vk,
            .policy = self.policy,
            .nonce_registry = &self.nonce_registry,
            .kek_resolver = &kek_resolver,
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
            std.time.timestamp(),
        );

        return result.handle;
    }

    pub fn takeSnapshot(self: *StorageEnclave) !crypto.PersistenceReceipt {
        std.debug.print("Linus Salamander: Triggering State-of-the-Art Snapshot...\n", .{});
        
        // 1. Serialize data to raw plaintext
        var list = std.ArrayList(u8).empty;
        defer list.deinit(self.allocator);
        
        var it = self.secrets.iterator();
        while (it.next()) |entry| {
            try list.appendSlice(self.allocator, entry.key_ptr.*);
            try list.appendSlice(self.allocator, ":");
            try list.appendSlice(self.allocator, entry.value_ptr.*);
            try list.appendSlice(self.allocator, "\n");
        }

        // 2. Generate ephemeral symmetric key (DEK)
        var dek: [32]u8 = undefined;
        crypto.EnclaveCrypto.randomBytes(&dek);
        defer crypto.secureZero(&dek);

        // 3. Encrypt payload with DEK under canonical AAD
        var nonce: [12]u8 = undefined;
        crypto.EnclaveCrypto.randomBytes(&nonce);

        var previous_snapshot_hash = [32]u8{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        if (self.trusted_chain_head) |head| {
            previous_snapshot_hash = head;
        }

        var payload_aad_buf = std.Io.Writer.Allocating.init(self.allocator);
        defer payload_aad_buf.deinit();
        const pw = payload_aad_buf.writer;
        try pw.print("3:aad=121:5:project=9:allascode;11:environment=4:prod;13:snapshot_type=6:secret;9:operation=12:write_secret;epoch={d};22:previous_snapshot_hash=64:", .{self.last_accepted_epoch + 1});
        for (previous_snapshot_hash) |b| {
            try pw.print("{x:0>2}", .{b});
        }
        try pw.writeAll(";;\n");
        const canonical_aad = try payload_aad_buf.toOwnedSlice();
        defer self.allocator.free(canonical_aad);

        const sealed = try crypto.sealPayload(self.allocator, list.items, &dek, nonce, canonical_aad);
        defer self.allocator.free(sealed.ciphertext);

        // 4. Wrap DEK with KEK provider
        const wrapped = try self.kek_provider.provider().wrap(self.allocator, &dek, self.kek_provider.key_id);

        // Convert byte slices to hex strings for SnapshotBody JSON formats
        const sealed_payload_hex = try std.fmt.allocPrint(self.allocator, "{s}", .{std.fmt.fmtSliceHexLower(sealed.ciphertext)});
        defer self.allocator.free(sealed_payload_hex);

        const wrapped_dek_hex = try std.fmt.allocPrint(self.allocator, "{s}", .{std.fmt.fmtSliceHexLower(&wrapped.wrapped_dek)});
        defer self.allocator.free(wrapped_dek_hex);

        // 5. Build finalized Snapshot Body
        const secret_ref_dummy = [32]u8{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        const snapshot_body = crypto.SnapshotBody{
            .schema_version = "lses.snapshot.v1",
            .project_id = "allascode",
            .environment = "prod",
            .operation = "write_secret",
            .secret_ref = secret_ref_dummy,
            .epoch = self.last_accepted_epoch + 1,
            .previous_snapshot_hash = previous_snapshot_hash,
            .created_at = "2026-05-18T00:00:00Z",
            .algorithm = .{
                .content_encryption = "AES-256-GCM",
                .key_wrapping = "LOCAL-DEV-AES-256-GCM",
                .enclave_signature = "Ed25519",
                .consumer_signature = "Ed25519",
            },
            .aad = .{
                .project = "allascode",
                .environment = "prod",
                .snapshot_type = "secret",
                .operation = "write_secret",
                .epoch = self.last_accepted_epoch + 1,
                .previous_snapshot_hash = previous_snapshot_hash,
            },
            .nonce = nonce,
            .sealed_payload = sealed_payload_hex,
            .auth_tag = sealed.auth_tag,
            .wrapped_dek = wrapped_dek_hex,
            .wrap_nonce = wrapped.wrap_nonce,
            .wrap_auth_tag = wrapped.wrap_auth_tag,
            .dek_wrapping_key_id = self.kek_provider.key_id,
            .enclave_public_key_id = self.enclave_identity.key_id,
            .consumer_public_key_id = self.consumer_identity.key_id,
        };

        // 6. Compute snapshot_id (deterministic canonical hash)
        const canonical_body = try crypto.canonicalizeSnapshotBody(self.allocator, snapshot_body);
        defer self.allocator.free(canonical_body);
        const snapshot_id = crypto.computeSnapshotId(canonical_body);
        self.trusted_chain_head = snapshot_id;

        // 7. Sign input
        const signature_input = try crypto.canonicalizeSignatureInput(self.allocator, snapshot_id, snapshot_body);
        defer self.allocator.free(signature_input);

        const enclave_sig = try crypto.signEd25519(signature_input, self.enclave_identity.private_key.?);
        const consumer_sig = try crypto.signEd25519(signature_input, self.consumer_identity.private_key.?);

        const envelope = crypto.CryptographicEnvelope{
            .snapshot_body = snapshot_body,
            .snapshot_id = snapshot_id,
            .attestations = .{
                .enclave_signature = enclave_sig,
                .consumer_countersignature = consumer_sig,
            },
            .persistence_receipt = null,
        };

        // Convert envelope to JSON serialization structure
        var envelope_json = try fromEnvelopeToJson(self.allocator, envelope);
        defer freeEnvelopeJson(self.allocator, &envelope_json);

        // 8. Save to file
        const filename = "enclave.sealed.json";
        const file = try std.Io.Dir.cwd().createFile(self.io, filename, .{});
        defer file.close(self.io);
        var write_buf: [4096]u8 = undefined;
        var file_writer = file.writer(self.io, &write_buf);
        try std.json.Stringify.value(envelope_json, .{}, &file_writer.interface);
        file.close(self.io);

        // 9. Push to GitHub
        try self.git_sync.commitAndPush(filename);

        // 10. We return receipt and simulate git info
        return crypto.PersistenceReceipt{
            .provider = "github",
            .repository = "owner/repo",
            .branch = "main",
            .commit_sha = "generated_commit_sha",
            .committed_at = "2026-05-18T00:00:05Z",
        };
    }
};
