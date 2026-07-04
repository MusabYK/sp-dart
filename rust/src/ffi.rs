// rust/src/ffi.rs

use secp256k1::ecdh::shared_secret_point;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use std::sync::Arc; // constant-time ECDH — public API

// bitcoin_hashes for the BIP-352 tagged hash
use bitcoin_hashes::{sha256t_hash_newtype, Hash, HashEngine};

use sp_lib::utils::{sending::calculate_partial_secret, OutPoint as SpOutPoint};
use sp_lib::{Network as SpNetwork, SilentPaymentAddress as SpAddress, SpVersion};

// BIP352/SharedSecret tagged hash
// The spdk library defines SharedSecretHash as pub(crate), so we cannot
// call calculate_t_n() from outside the crate.
//
// We define the SAME tagged hash ourselves using the public macro.
// This is identical to what the library does internally.
//
// t_k = H_BIP0352/SharedSecret(ecdh_point.serialize_compressed() || k)
sha256t_hash_newtype! {
    struct SpSharedSecretTag = hash_str("BIP0352/SharedSecret");
    #[hash_newtype(forward)]
    struct SpSharedSecretHash(_);
}

/// t_k = H_BIP0352/SharedSecret(compressed_ecdh_point || k.to_be_bytes())
fn compute_t_n(ecdh_pubkey: &PublicKey, k: u32) -> Result<SecretKey, SilentPaymentError> {
    let mut engine = SpSharedSecretHash::engine();
    engine.input(&ecdh_pubkey.serialize()); // 33-byte compressed pubkey
    engine.input(&k.to_be_bytes());
    let hash = SpSharedSecretHash::from_engine(engine).to_byte_array();
    SecretKey::from_slice(&hash)
        .map_err(|e: secp256k1::Error| SilentPaymentError::CryptoError { msg: e.to_string() })
}

/// P_k = B_spend + t_k × G
fn compute_p_n(spend_public: &PublicKey, t_k: &SecretKey) -> Result<PublicKey, SilentPaymentError> {
    let secp = Secp256k1::verification_only();
    let scalar =
        Scalar::from_be_bytes(t_k.secret_bytes()).map_err(|_| SilentPaymentError::CryptoError {
            msg: "t_k bytes produced an out-of-range scalar".into(),
        })?;
    spend_public
        .add_exp_tweak(&secp, &scalar)
        .map_err(|e: secp256k1::Error| SilentPaymentError::CryptoError { msg: e.to_string() })
}

// BIP352/Label tagged hash
// We also define the BIP-352/Label tagged hash for the tweak index server.
sha256t_hash_newtype! {
    struct BIP0352LabelTag = hash_str("BIP0352/Label");
    #[hash_newtype(forward)]
    struct BIP0352LabelHash(_);
}

/// Compute H_BIP0352/Label(b_scan.secret_bytes() || m.to_be_bytes()).
/// Returns the raw 32-byte hash — treat it as a scalar, not a secret to expose.
fn compute_label_hash(b_scan: &SecretKey, m: u32) -> [u8; 32] {
    let mut engine = BIP0352LabelHash::engine();
    engine.input(&b_scan.secret_bytes());
    engine.input(&m.to_be_bytes());
    BIP0352LabelHash::from_engine(engine).to_byte_array()
}

/// label_pubkey_m = H_BIP0352/Label(b_scan || m) × G
///
/// This is the PUBLIC point added to expected outputs during scanning.
/// The underlying scalar (label hash) is never exposed outside this module.
fn compute_label_pubkey(b_scan: &SecretKey, m: u32) -> Result<PublicKey, SilentPaymentError> {
    let secp = Secp256k1::new();
    let label_hash = compute_label_hash(b_scan, m);

    // The hash bytes are used as a private scalar - same pattern as BDK's key derivation.
    // SecretKey::from_slice validates the scalar is in [1, n-1].
    let label_scalar = SecretKey::from_slice(&label_hash).map_err(|e: secp256k1::Error| {
        SilentPaymentError::CryptoError {
            msg: format!("Label {m} hash produced invalid scalar: {e}"),
        }
    })?;

    Ok(PublicKey::from_secret_key(&secp, &label_scalar))
}

//  Error
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SilentPaymentError {
    #[error("Invalid key: {msg}")]
    InvalidKey { msg: String },
    #[error("Invalid address: {msg}")]
    InvalidAddress { msg: String },
    #[error("Cryptography error: {msg}")]
    CryptoError { msg: String },
    #[error("Encoding error: {msg}")]
    EncodingError { msg: String },
}

impl From<sp_lib::Error> for SilentPaymentError {
    fn from(e: sp_lib::Error) -> Self {
        SilentPaymentError::InvalidAddress { msg: e.to_string() }
    }
}

impl From<secp256k1::Error> for SilentPaymentError {
    fn from(e: secp256k1::Error) -> Self {
        SilentPaymentError::CryptoError { msg: e.to_string() }
    }
}

// Network
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq)]
pub enum NetworkFFI {
    Mainnet,
    Testnet,
    Signet, // maps to SpNetwork::Testnet (both use "tsp" HRP per BIP-352)
    Regtest,
}

impl From<NetworkFFI> for SpNetwork {
    fn from(n: NetworkFFI) -> Self {
        match n {
            NetworkFFI::Mainnet => SpNetwork::Mainnet,
            NetworkFFI::Testnet | NetworkFFI::Signet => SpNetwork::Testnet,
            NetworkFFI::Regtest => SpNetwork::Regtest,
        }
    }
}

impl From<SpNetwork> for NetworkFFI {
    fn from(n: SpNetwork) -> Self {
        match n {
            SpNetwork::Mainnet => NetworkFFI::Mainnet,
            SpNetwork::Testnet => NetworkFFI::Testnet,
            SpNetwork::Regtest => NetworkFFI::Regtest,
        }
    }
}

impl std::fmt::Display for NetworkFFI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkFFI::Mainnet => write!(f, "mainnet"),
            NetworkFFI::Testnet => write!(f, "testnet"),
            NetworkFFI::Signet => write!(f, "signet"),
            NetworkFFI::Regtest => write!(f, "regtest"),
        }
    }
}

// Records

#[derive(uniffi::Record, Debug)]
pub struct SilentPaymentAddress {
    pub address: String,
    pub scan_pubkey_hex: String,
    pub spend_pubkey_hex: String,
    pub network: NetworkFFI,
}

#[derive(uniffi::Record, Debug)]
pub struct HexStringResult {
    pub value: String,
}

#[derive(uniffi::Record, Debug)]
pub struct FoundPayment {
    pub output_index: u32,
    pub tweak_hex: String,
    pub amount_sats: u64,

    /// Required for Labeled Adresses
    /// None = payment to the standard (unlabeled) address.
    /// Some(m) = payment to the labeled sub-address with label m.
    ///
    /// Wallets use this to route payments:
    ///   None = general receive wallet
    ///   Some(1) = donations
    ///   Some(2) = shop payments
    ///   etc.
    pub label: Option<u32>,
}

#[derive(uniffi::Record, Debug)]
pub struct ScanTransactionResult {
    pub payments: Vec<FoundPayment>,
}

#[derive(uniffi::Record, Debug)]
pub struct OutputWithKey {
    pub pubkey_hex: String,
    pub recipient_address: String,
}

#[derive(uniffi::Record, Debug)]
pub struct PaymentRecipient {
    pub address: String,
    pub amount_sats: u64,
}

/// An input being spent in a sending transaction.
/// BIP-352 requires:
///   * ALL eligible input private keys (P2PKH, P2WPKH, P2SH-P2WPKH, P2TR)
///   * The corresponding outpoints (txid + vout) for the input hash
///   * Whether each input is taproot — BIP-352 negates P2TR keys with odd parity
///     before summing, which prevents certain cross-input linking attacks
#[derive(uniffi::Record, Debug)]
pub struct SendingInput {
    /// Private key for this input (32 bytes as hex, 64 chars)
    pub secret_key_hex: String,

    /// True for P2TR (taproot) inputs, false for P2PKH / P2WPKH / P2SH-P2WPKH
    pub is_taproot: bool,

    /// Txid of the UTXO being spent, as displayed (big-endian hex, 64 chars).
    /// The library reverses it internally to little-endian for the hash.
    pub txid: String,

    /// Output index of the UTXO (the "n" in txid:n)
    pub vout: u32,
}

// SilentPaymentRecipient

#[derive(uniffi::Object)]
pub struct SilentPaymentRecipient {
    scan_secret: SecretKey,
    spend_secret: SecretKey,
    scan_public: PublicKey,
    spend_public: PublicKey,
    network: NetworkFFI,
}

#[uniffi::export]
impl SilentPaymentRecipient {
    #[uniffi::constructor]
    pub fn generate(network: NetworkFFI) -> Result<Arc<Self>, SilentPaymentError> {
        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let scan_secret = SecretKey::new(&mut rng);
        let spend_secret = SecretKey::new(&mut rng);
        let scan_public = PublicKey::from_secret_key(&secp, &scan_secret);
        let spend_public = PublicKey::from_secret_key(&secp, &spend_secret);
        Ok(Arc::new(Self {
            scan_secret,
            spend_secret,
            scan_public,
            spend_public,
            network,
        }))
    }

    #[uniffi::constructor]
    pub fn from_secret_keys(
        scan_secret_hex: String,
        spend_secret_hex: String,
        network: NetworkFFI,
    ) -> Result<Arc<Self>, SilentPaymentError> {
        let secp = Secp256k1::new();
        let scan_secret = SecretKey::from_slice(&hex_to_32_bytes(&scan_secret_hex)?)
            .map_err(|e: secp256k1::Error| SilentPaymentError::InvalidKey { msg: e.to_string() })?;
        let spend_secret = SecretKey::from_slice(&hex_to_32_bytes(&spend_secret_hex)?)
            .map_err(|e: secp256k1::Error| SilentPaymentError::InvalidKey { msg: e.to_string() })?;
        let scan_public = PublicKey::from_secret_key(&secp, &scan_secret);
        let spend_public = PublicKey::from_secret_key(&secp, &spend_secret);
        Ok(Arc::new(Self {
            scan_secret,
            spend_secret,
            scan_public,
            spend_public,
            network,
        }))
    }

    /// Returns the proper bech32m BIP-352 address.
    /// SpAddress::new() returns Self (not Result),
    /// then Into<String> via encode feature.
    ///
    /// Delegates entirely to SpAddress - no manual bech32m code in ffi.rs.
    pub fn get_address(&self) -> SilentPaymentAddress {
        // SpAddress::new() - no ? needed, returns Self directly
        let sp_addr = SpAddress::new(
            self.scan_public,
            self.spend_public,
            SpNetwork::from(self.network),
            SpVersion::ZERO,
        );

        // SpAddress implements Into<String> (bech32m via the library)
        let address: String = sp_addr.into();

        SilentPaymentAddress {
            address,
            scan_pubkey_hex: hex::encode(self.scan_public.serialize()),
            spend_pubkey_hex: hex::encode(self.spend_public.serialize()),
            network: self.network,
        }
    }

    /// Derive the labeled sub-address for label m.
    ///
    /// # BIP-352 derivation
    /// label_pubkey = H_BIP0352/Label(b_scan || m) × G
    /// B_m          = B_spend + label_pubkey          (EC point addition)
    /// address      = bech32m(hrp, version || B_scan || B_m)
    ///
    /// Share this address with a specific payer. All payments to it are
    /// detected in a single scan pass alongside unlabeled payments.
    ///
    /// Label 0 is reserved by BIP-352 convention. Use labels >= 1.
    pub fn get_labeled_address(
        &self,
        label: u32,
    ) -> Result<SilentPaymentAddress, SilentPaymentError> {
        // label_pubkey_m = H_BIP0352/Label(b_scan || m) × G
        let label_pubkey = compute_label_pubkey(&self.scan_secret, label)?;

        // B_m = B_spend + label_pubkey
        let b_m = PublicKey::combine_keys(&[&self.spend_public, &label_pubkey]).map_err(
            |e: secp256k1::Error| SilentPaymentError::CryptoError {
                msg: format!("Failed to derive labeled spend key for m={label}: {e}"),
            },
        )?;

        // Encode with the library's bech32m implementation
        let sp_addr = SpAddress::new(
            self.scan_public,
            b_m,
            SpNetwork::from(self.network),
            SpVersion::ZERO,
        );
        let address: String = sp_addr.into();

        Ok(SilentPaymentAddress {
            address,
            scan_pubkey_hex: hex::encode(self.scan_public.serialize()),
            spend_pubkey_hex: hex::encode(b_m.serialize()), // B_m, not B_spend
            network: self.network,
        })
    }

    pub fn export_scan_secret_hex(&self) -> HexStringResult {
        HexStringResult {
            value: hex::encode(self.scan_secret.secret_bytes()),
        }
    }
    pub fn export_spend_secret_hex(&self) -> HexStringResult {
        HexStringResult {
            value: hex::encode(self.spend_secret.secret_bytes()),
        }
    }
    pub fn export_spend_pubkey_hex(&self) -> HexStringResult {
        HexStringResult {
            value: hex::encode(self.spend_public.serialize()),
        }
    }
}

// SilentPaymentScanner

#[derive(uniffi::Object)]
pub struct SilentPaymentScanner {
    scan_secret: SecretKey,
    spend_public: PublicKey,
}

#[uniffi::export]
impl SilentPaymentScanner {
    /// Watch-only scanner: scan key + spend PUBKEY only.
    /// Cannot spend, its safe for background services and servers.
    #[uniffi::constructor]
    pub fn watch_only(
        scan_secret_hex: String,
        spend_pubkey_hex: String,
    ) -> Result<Arc<Self>, SilentPaymentError> {
        let scan_secret = SecretKey::from_slice(&hex_to_32_bytes(&scan_secret_hex)?)
            .map_err(|e: secp256k1::Error| SilentPaymentError::InvalidKey { msg: e.to_string() })?;
        let spend_public = PublicKey::from_slice(&hex_to_33_bytes(&spend_pubkey_hex)?)
            .map_err(|e: secp256k1::Error| SilentPaymentError::InvalidKey { msg: e.to_string() })?;
        Ok(Arc::new(Self {
            scan_secret,
            spend_public,
        }))
    }

    /// Scan a transaction for payments using pre-computed tweak data.
    ///
    /// # Arguments
    ///
    /// * `sender_input_pubkeys_hex` — In mobile/light-client mode, this is a
    ///   **single** 33-byte compressed pubkey: the pre-computed tweak data
    ///   `A_sum × H_BIP0352/Inputs(smallest_outpoint || A_sum)` returned by
    ///   the tweak index server. The server does the input hash computation;
    ///   we only do the ECDH + output derivation.
    ///
    ///   In full-verification mode (no server), pass the raw sender input
    ///   pubkeys and use [`scan_transaction_full`] which also takes outpoints.
    ///
    /// * `tx_output_pubkeys_hex` — 33-byte compressed pubkeys from tx outputs.
    ///
    /// * `output_amounts_sats` — Parallel with output pubkeys.
    ///
    /// # BIP-352 computation (correct)
    ///
    /// ```text
    /// shared_secret = b_scan × tweak_data
    /// t_k = H_BIP0352/SharedSecret(shared_secret.serialize() || k.to_be_bytes())
    /// P_k = B_spend + t_k × G
    /// match P_k against each output pubkey
    /// ```
    pub fn scan_transaction(
        &self,
        sender_input_pubkeys_hex: Vec<String>,
        tx_output_pubkeys_hex: Vec<String>,
    ) -> Result<ScanTransactionResult, SilentPaymentError> {
        // In mobile mode, sender_input_pubkeys_hex contains a single entry:
        // the pre-computed tweak from the index server.
        if sender_input_pubkeys_hex.is_empty() {
            return Err(SilentPaymentError::InvalidKey {
                msg: "sender_input_pubkeys_hex must not be empty, must contain at least one pubkey"
                    .into(),
            });
        }

        // Step 1: ECDH - Parse the tweak data
        // sender_input_pubkeys_hex[0] = tweak data from index server
        //   = A_sum × H_BIP0352/Inputs(smallest_outpoint || A_sum)
        // (server pre-computed the input hash; we only do ECDH + output scan)
        let tweak_bytes = hex_to_33_bytes(&sender_input_pubkeys_hex[0])?;
        let tweak_data = PublicKey::from_slice(&tweak_bytes).map_err(|e: secp256k1::Error| {
            SilentPaymentError::InvalidKey {
                msg: format!("Invalid tweak pubkey: {e}"),
            }
        })?;

        // Step 2: ECDH - b_scan × tweak_data
        // shared_secret_point: constant-time scalar multiplication
        // Returns 64 bytes (x,y coordinates of the EC point)
        let raw_ecdh = shared_secret_point(&tweak_data, &self.scan_secret);

        // Reconstruct the full uncompressed EC point (0x04 || x || y)
        // then parse so we can call .serialize() for the 33-byte compressed form
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&raw_ecdh);
        let ecdh_pubkey = PublicKey::from_slice(&uncompressed)
            .expect("shared_secret_point always returns a valid curve point");

        // Scan k = 0, 1, 2, …
        // t_k = H_BIP0352/SharedSecret(compressed_ecdh_point || k)
        // P_k = B_spend + t_k × G
        // Match P_k against each output pubkey; stop when no match found.
        let mut payments = Vec::new();
        let mut k: u32 = 0;

        loop {
            // t_k — uses the correct BIP0352/SharedSecret tagged hash
            let t_k = compute_t_n(&ecdh_pubkey, k)?;
            // P_k = B_spend + t_k × G
            let expected_pk = compute_p_n(&self.spend_public, &t_k)?;

            let expected_bytes = expected_pk.serialize();
            let expected_full = hex::encode(&expected_bytes);
            let expected_xonly = hex::encode(&expected_bytes[1..]);

            let matched_vout = tx_output_pubkeys_hex
                .iter()
                .enumerate()
                .find(|(_, pk_hex)| {
                    // 66-char compressed match OR 64-char x-only match (taproot uses x-only)
                    // *pk_hex == &expected_full || *pk_hex == &expected_xonly
                    pk_hex.as_str() == expected_full.as_str()
                        || pk_hex.as_str() == expected_xonly.as_str()
                })
                .map(|(vout, _)| vout as u32);

            match matched_vout {
                Some(vout) => {
                    payments.push(FoundPayment {
                        output_index: vout,
                        tweak_hex: hex::encode(t_k.secret_bytes()),
                        amount_sats: 0,
                        label: None,
                    });
                    k += 1;
                }
                None => break,
            }
        }

        Ok(ScanTransactionResult { payments })
    }

    /// Scan for both unlabeled payments AND labeled sub-address payments
    /// in a single pass.
    ///
    /// # Performance
    /// Label pubkeys are pre-computed once per scan call (not per output).
    /// Cost: O(outputs × labels) point comparisons per k step.
    /// For typical wallets (< 50 labels, < 100 outputs), this is negligible.
    ///
    /// # Arguments
    /// * `labels` — label integers to check (e.g. `[1, 2, 3]`).
    ///   Pass an empty vec to behave identically to `scan_transaction`.
    ///
    /// # Returns
    /// `FoundPayment.label` tells you WHICH sub-address received the payment.
    pub fn scan_transaction_with_labels(
        &self,
        sender_input_pubkeys_hex: Vec<String>,
        tx_output_pubkeys_hex: Vec<String>,
        labels: Vec<u32>,
    ) -> Result<ScanTransactionResult, SilentPaymentError> {
        if sender_input_pubkeys_hex.is_empty() {
            return Err(SilentPaymentError::InvalidKey {
                msg: "sender_input_pubkeys_hex must not be empty".into(),
            });
        }

        let tweak_bytes = hex_to_33_bytes(&sender_input_pubkeys_hex[0])?;
        let tweak_data = PublicKey::from_slice(&tweak_bytes).map_err(|e: secp256k1::Error| {
            SilentPaymentError::InvalidKey {
                msg: format!("Invalid tweak pubkey: {e}"),
            }
        })?;

        let raw_ecdh = shared_secret_point(&tweak_data, &self.scan_secret);
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&raw_ecdh);
        let ecdh_pubkey = PublicKey::from_slice(&uncompressed)
            .expect("shared_secret_point always returns a valid point");

        // Pre-compute label pubkeys (outside the k loop)
        // label_pubkeys[i] = (m, H_BIP0352/Label(b_scan || m) × G)
        // Computed once here, reused for every k step.
        let label_pubkeys: Vec<(u32, PublicKey)> = labels
            .iter()
            .map(|&m| compute_label_pubkey(&self.scan_secret, m).map(|pk| (m, pk)))
            .collect::<Result<_, _>>()?;

        // Scan k = 0, 1, 2, ...
        let mut payments = Vec::new();
        let mut k: u32 = 0;

        loop {
            // t_k = H_BIP0352/SharedSecret(compressed_ecdh || k)
            // P_k = B_spend + t_k × G   (unlabeled expected output)
            let t_k = compute_t_n(&ecdh_pubkey, k)?;
            let p_k = compute_p_n(&self.spend_public, &t_k)?;
            let p_k_bytes = p_k.serialize();
            let p_k_full = hex::encode(&p_k_bytes);
            let p_k_xonly = hex::encode(&p_k_bytes[1..]);

            let mut found_this_k = false;

            // ── Unlabeled check ───────────────────────────────────────────────
            let unlabeled_vout = tx_output_pubkeys_hex
                .iter()
                .enumerate()
                .find(|(_, pk_hex)| {
                    pk_hex.as_str() == p_k_full.as_str() || pk_hex.as_str() == p_k_xonly.as_str()
                })
                .map(|(vout, _)| vout as u32);

            if let Some(vout) = unlabeled_vout {
                payments.push(FoundPayment {
                    output_index: vout,
                    tweak_hex: hex::encode(t_k.secret_bytes()),
                    amount_sats: 0,
                    label: None,
                });
                found_this_k = true;
            }

            // Labeled checks
            // P_k_m = P_k + label_pubkey_m
            //       = (B_spend + t_k × G) + (label_hash_m × G)
            //       = B_m + t_k × G       where B_m = B_spend + label_hash_m × G
            for &(m, ref label_pk) in &label_pubkeys {
                let p_k_m =
                    PublicKey::combine_keys(&[&p_k, label_pk]).map_err(|e: secp256k1::Error| {
                        SilentPaymentError::CryptoError {
                            msg: format!("Point addition failed for label {m}: {e}"),
                        }
                    })?;
                let p_k_m_bytes = p_k_m.serialize();
                let p_k_m_full = hex::encode(&p_k_m_bytes);
                let p_k_m_xonly = hex::encode(&p_k_m_bytes[1..]);

                let labeled_vout = tx_output_pubkeys_hex
                    .iter()
                    .enumerate()
                    .find(|(_, pk_hex)| {
                        pk_hex.as_str() == p_k_m_full.as_str()
                            || pk_hex.as_str() == p_k_m_xonly.as_str()
                    })
                    .map(|(vout, _)| vout as u32);

                if let Some(vout) = labeled_vout {
                    payments.push(FoundPayment {
                        output_index: vout,
                        tweak_hex: hex::encode(t_k.secret_bytes()),
                        amount_sats: 0,
                        label: Some(m),
                    });
                    found_this_k = true;
                }
            }

            // BIP-352: stop scanning when the current k produces no match
            // (neither unlabeled nor any label). Further k values won't match.
            if !found_this_k {
                break;
            }
            k += 1;
        }

        Ok(ScanTransactionResult { payments })
    }
}

// Free functions
/// Create BIP-352 compliant silent payment output pubkeys for a set of recipients.
///
/// # BIP-352 sending protocol
/// 1. For each P2TR input: if parity is ODD, negate the private key
/// 2. a_sum = sum of all (possibly negated) input private keys
/// 3. A_sum = a_sum × G
/// 4. smallest_outpoint = lexicographically smallest (txid_le || vout_le) outpoint
/// 5. input_hash = H_BIP0352/Inputs(smallest_outpoint || A_sum)
/// 6. partial_secret = a_sum × input_hash         ← calculate_partial_secret()
/// 7. For each recipient:
///    shared_secret = partial_secret × B_scan     ← ECDH
///    t_k = H_BIP0352/SharedSecret(shared_secret || k)
///    P_k = B_spend + t_k × G                    ← output pubkey
///
/// Steps 1–6 are handled by sp_lib::utils::sending::calculate_partial_secret.
/// Steps 7+ use our own public-API implementation (same as scan_transaction).
///
/// # Multiple recipients with the same scan key
/// BIP-352 requires using k = 0, 1, 2, … when sending to the same scan key
/// multiple times in one transaction. This function handles that automatically.
#[uniffi::export]
pub fn create_silent_payment_outputs(
    inputs: Vec<SendingInput>,
    recipients: Vec<PaymentRecipient>,
) -> Result<Vec<OutputWithKey>, SilentPaymentError> {
    if inputs.is_empty() {
        return Err(SilentPaymentError::InvalidKey {
            msg: "inputs must not be empty — at least one input private key is required".into(),
        });
    }
    if recipients.is_empty() {
        return Err(SilentPaymentError::InvalidAddress {
            msg: "recipients must not be empty".into(),
        });
    }

    // Parse inputs
    let mut sp_keys: Vec<(SecretKey, bool)> = Vec::with_capacity(inputs.len());
    let mut sp_outpoints: Vec<SpOutPoint> = Vec::with_capacity(inputs.len());

    for input in &inputs {
        let key = SecretKey::from_slice(&hex_to_32_bytes(&input.secret_key_hex)?).map_err(
            |e: secp256k1::Error| SilentPaymentError::InvalidKey {
                msg: format!("Invalid input secret key: {e}"),
            },
        )?;

        sp_keys.push((key, input.is_taproot));

        // from_txid_and_vout accepts the txid as displayed (big-endian)
        // and handles the byte reversal to little-endian internally
        let outpoint =
            SpOutPoint::from_txid_and_vout(input.txid.clone(), input.vout).map_err(|e| {
                SilentPaymentError::EncodingError {
                    msg: format!(
                        "Invalid outpoint (txid={}, vout={}): {e}",
                        input.txid, input.vout
                    ),
                }
            })?;

        sp_outpoints.push(outpoint);
    }

    // compute partial_secret via sp_lib (the BIP-352 correct path)
    //
    // calculate_partial_secret does:
    //   • Taproot negation: P2TR keys with odd parity are negated
    //   • Key summation: a_sum = sum of (possibly negated) keys
    //   • Input hash:    H_BIP0352/Inputs(smallest_outpoint || A_sum)
    //   • Multiplication: partial_secret = a_sum × input_hash
    //
    // PartialSecret.secret_bytes() is public — we extract the scalar
    // and use it with shared_secret_point (constant-time ECDH).
    let partial_secret = calculate_partial_secret(&sp_keys, &sp_outpoints).map_err(|e| {
        SilentPaymentError::CryptoError {
            msg: format!("Failed to compute partial secret: {e}"),
        }
    })?;

    let partial_scalar =
        SecretKey::from_slice(&partial_secret.secret_bytes()).map_err(|e: secp256k1::Error| {
            SilentPaymentError::CryptoError {
                msg: format!("Partial secret is an invalid scalar: {e}"),
            }
        })?;

    // Derive output pubkeys for each recipient
    //
    // BIP-352: if the same scan key appears multiple times, use k = 0, 1, 2, ...
    // Track the next k value per scan pubkey (as a hex key in a small vec).
    let mut scan_key_counters: Vec<(String, u32)> = Vec::new();
    let mut outputs = Vec::with_capacity(recipients.len());

    for recipient in &recipients {
        let (scan_pk, spend_pk) = parse_sp_address(&recipient.address)?;
        let scan_pk_hex = hex::encode(scan_pk.serialize());

        // Get (and increment) the k counter for this scan key
        let k = match scan_key_counters
            .iter_mut()
            .find(|(h, _)| h == &scan_pk_hex)
        {
            Some(entry) => {
                let k = entry.1;
                entry.1 += 1;
                k
            }
            None => {
                scan_key_counters.push((scan_pk_hex, 1));
                0
            }
        };

        // shared_secret = partial_secret × B_scan
        // shared_secret_point is constant-time (important since we're using a private key)
        let raw_ecdh = shared_secret_point(&scan_pk, &partial_scalar);
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&raw_ecdh);
        let ecdh_pubkey = PublicKey::from_slice(&uncompressed)
            .expect("shared_secret_point always returns a valid EC point");

        // t_k = H_BIP0352/SharedSecret(compressed_ecdh || k)
        // P_k = B_spend + t_k × G
        let t_k = compute_t_n(&ecdh_pubkey, k)?;
        let p_k = compute_p_n(&spend_pk, &t_k)?;

        outputs.push(OutputWithKey {
            pubkey_hex: hex::encode(p_k.serialize()),
            recipient_address: recipient.address.clone(),
        });
    }

    Ok(outputs)
}

/// Build the tsp1q.../sp1q... address from the keys stored in the scanner.
/// Used to form the server-side subscription parameters (without needing the spend secret).
/// In Frigate for example, this is used to generate the `tsp1q...` address.
#[uniffi::export]
pub fn build_sp_address(
    scan_secret_hex: String,
    spend_pubkey_hex: String,
    network: NetworkFFI,
) -> Result<HexStringResult, SilentPaymentError> {
    let secp = Secp256k1::new();

    let scan_secret = SecretKey::from_slice(&hex_to_32_bytes(&scan_secret_hex)?)
        .map_err(|e: secp256k1::Error| SilentPaymentError::InvalidKey { msg: e.to_string() })?;
    let scan_public = PublicKey::from_secret_key(&secp, &scan_secret);

    let spend_public = PublicKey::from_slice(&hex_to_33_bytes(&spend_pubkey_hex)?)
        .map_err(|e: secp256k1::Error| SilentPaymentError::InvalidKey { msg: e.to_string() })?;

    let sp_addr = SpAddress::new(
        scan_public,
        spend_public,
        SpNetwork::from(network),
        SpVersion::ZERO,
    );
    let address: String = sp_addr.into();

    Ok(HexStringResult { value: address })
}

/// Returns the 33-byte compressed pubkey that the tweak index server would
/// serve to mobile scanners: A_sum × input_hash = partial_secret × G.
///
/// This bridges create_silent_payment_outputs (sender) with scan_transaction
/// (receiver) in offline demos. In production, the index server computes it.
///
/// Mathematical identity:
///   partial_secret × G = (a_sum × input_hash) × G
///                      = a_sum × (input_hash × G)
///                      = A_sum × input_hash          <- tweak data
#[uniffi::export]
pub fn compute_sender_tweak_data(
    inputs: Vec<SendingInput>,
) -> Result<HexStringResult, SilentPaymentError> {
    use sp_lib::utils::{sending::calculate_partial_secret, OutPoint as SpOutPoint};

    if inputs.is_empty() {
        return Err(SilentPaymentError::InvalidKey {
            msg: "inputs must not be empty".into(),
        });
    }

    let mut sp_keys: Vec<(SecretKey, bool)> = Vec::with_capacity(inputs.len());
    let mut sp_outpoints: Vec<SpOutPoint> = Vec::with_capacity(inputs.len());

    for input in &inputs {
        let key = SecretKey::from_slice(&hex_to_32_bytes(&input.secret_key_hex)?)
            .map_err(|e: secp256k1::Error| SilentPaymentError::InvalidKey { msg: e.to_string() })?;
        sp_keys.push((key, input.is_taproot));

        let outpoint = SpOutPoint::from_txid_and_vout(input.txid.clone(), input.vout)
            .map_err(|e| SilentPaymentError::EncodingError { msg: e.to_string() })?;
        sp_outpoints.push(outpoint);
    }

    // partial_secret = a_sum × input_hash  (scalar, via calculate_partial_secret)
    let partial_secret = calculate_partial_secret(&sp_keys, &sp_outpoints)
        .map_err(|e| SilentPaymentError::CryptoError { msg: e.to_string() })?;

    let partial_scalar = SecretKey::from_slice(&partial_secret.secret_bytes())
        .map_err(|e: secp256k1::Error| SilentPaymentError::CryptoError { msg: e.to_string() })?;

    // tweak_data = partial_secret × G
    // This is the public key the mobile scanner receives from the index server
    let secp = Secp256k1::new();
    let tweak_pubkey = PublicKey::from_secret_key(&secp, &partial_scalar);

    Ok(HexStringResult {
        value: hex::encode(tweak_pubkey.serialize()),
    })
}

// Helpers
fn hex_to_32_bytes(s: &str) -> Result<[u8; 32], SilentPaymentError> {
    hex::decode(s)
        .map_err(|e| SilentPaymentError::EncodingError { msg: e.to_string() })?
        .try_into()
        .map_err(|_| SilentPaymentError::EncodingError {
            msg: format!("Expected 32 bytes from: {s}"),
        })
}

fn hex_to_33_bytes(s: &str) -> Result<[u8; 33], SilentPaymentError> {
    hex::decode(s)
        .map_err(|e| SilentPaymentError::EncodingError { msg: e.to_string() })?
        .try_into()
        .map_err(|_| SilentPaymentError::EncodingError {
            msg: format!("Expected 33 bytes (compressed pubkey) from: {s}"),
        })
}

/// Parse a bech32m BIP-352 address using the silentpayment
/// library's TryFrom<&str> implementation which validates:
/// - bech32m checksum
/// - HRP (sp / tsp / sprt)
/// - payload length (107 base32 chars = version + 33 + 33 bytes)
/// - version byte (0)
fn parse_sp_address(addr: &str) -> Result<(PublicKey, PublicKey), SilentPaymentError> {
    let sp_addr = SpAddress::try_from(addr)
        .map_err(|e| SilentPaymentError::InvalidAddress { msg: e.to_string() })?;
    Ok((sp_addr.get_scan_key(), sp_addr.get_spend_key()))
}
