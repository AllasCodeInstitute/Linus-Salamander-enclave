fn edge_context_aad(ctx: &EdgeContext) -> [u8; 24] {
    let mut aad = [0u8; 24];
    aad[0..8].copy_from_slice(&ctx.intent_id.to_le_bytes());
    aad[8..16].copy_from_slice(&ctx.edge_id.to_le_bytes());
    aad[16..24].copy_from_slice(&ctx.sequence.to_le_bytes());
    aad
}
