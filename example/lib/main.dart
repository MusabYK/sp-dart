import 'package:sp_dart/sp_dart.dart';

void main() {
  // Must be called before any other sp_dart function.
  ensureInitialized();
  // Always dispose them when not in use.
  SilentPaymentRecipient? recipient;
  SilentPaymentRecipient? senderKeypair;
  SilentPaymentScanner? scanner;
  try {
    // RECIPIENT KEY GENERATION
    recipient = SilentPaymentRecipient.generate(network: NetworkFfi.signet);
    final recipientAddress = recipient.getAddress();
    String recipientScanSecretHex = recipient.exportScanSecretHex().value;
    String recipientSpendPubkeyHex = recipient.exportSpendPubkeyHex().value;

    print(
      'Address(recipient): ${recipientAddress.address}\n'
      'Scan Secret: $recipientScanSecretHex\n'
      'Spend Pubkey: $recipientSpendPubkeyHex\n'
      'Network: ${recipientAddress.network.name}\n',
    );

    // End-to-end Demo (offline, no server)
    print('Running full BIP-352 Round-Trip Demo...');
    //  Recipient creates a watch-only scanner
    //  to scan transactions using scan secret + spend pubkey
    scanner = SilentPaymentScanner.watchOnly(
      scanSecretHex: recipientScanSecretHex,
      spendPubkeyHex: recipientSpendPubkeyHex,
    );

    // SENDER SETUP
    // We reuse SilentPaymentRecipient.generate() simply because it can generate
    // valid secp256k1 keypairs.
    // This works cryptographically for a demo but semantically it is incorrect.
    // A sender is not a SilentPaymentRecipient.
    // The sender merely owns spendable UTXOs.
    // A real sender wallet might not even support receiving silent payments.
    // In production these keys come from the UTXOs being spent by
    // the sender's wallet.
    senderKeypair = SilentPaymentRecipient.generate(network: NetworkFfi.signet);

    // In production this is actually the sender's private key (the private key
    // of the UTXO being spent), not his secret key.
    // exportScanSecretHex().value is just used as a hex string representation
    // of the private key for the purpose of computing the tweak data.
    final senderInputPrivKeyHex = senderKeypair.exportScanSecretHex().value;

    // Sender describes the input(s) he is spending
    // In production it is the real UTXO the sender is spending.
    // The input hash will be computed correctly using this outpoint.
    final senderInputs = [
      SendingInput(
        secretKeyHex: senderInputPrivKeyHex,
        isTaproot: false, // P2WPKH
        txid:
            'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'
            'e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
        vout: 0,
      ),
    ];

    // SENDER COMPUTE OUTPUTS
    final outputs = createSilentPaymentOutputs(
      inputs: senderInputs,
      recipients: [
        PaymentRecipient(address: recipientAddress.address, amountSats: 70000),
      ],
    );

    // Derive tweak_data for the scanner
    // tweak_data = partial_secret × G
    //            = (a_sum × input_hash) × G
    // In production this is pre-computed server-side (tweak index / Frigate)
    // so the device never has to touch the full block.
    final tweakData = computeSenderTweakData(inputs: senderInputs);

    // RECIPIENT SCANNS THE TRANSACTION
    // A_tweak already incorporates the input hash and all eligible sender inputs.
    // The scanner receives A_tweak from the tweak index server.
    // Recipient Scan for the transactions that beling to him
    // In a real scenario, the scanner receives the pre-computed tweak
    // from the tweak index server.
    final result = scanner.scanTransaction(
      senderInputPubkeysHex: [tweakData.value],
      txOutputPubkeysHex: outputs.map((o) => o.pubkeyHex).toList(),
      outputAmountsSats: [70000],
    );

    print(
      result.payments.isNotEmpty
          ? 'BIP-352 Round-Trip\n'
                'Sender computed output pubkey:\n'
                '   ${outputs.first.pubkeyHex.substring(0, 20)}...\n\n'
                'Recipient FOUND the payment:\n'
                '   Output index (k)     : ${result.payments.first.outputIndex}\n'
                '   Tweak t_k            : ${result.payments.first.tweakHex.substring(0, 20)}…\n'
                '   Amount : ${result.payments.first.amountSats} sats\n'
                '   Label  : ${result.payments.first.label ?? "unlabeled"}\n'
          : 'Round-trip failed — crypto mismatch',
    );
  } on SilentPaymentException catch (e) {
    print('${e.runtimeType}: $e');
  } catch (e) {
    print('$e');
  } finally {
    // Dispose in reverse order of creation, it decrements Arc<T> (refcount) in .so.
    scanner?.dispose();
    senderKeypair?.dispose();
    recipient?.dispose();
  }
}
