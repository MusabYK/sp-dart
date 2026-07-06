import 'package:sp_dart/sp_dart.dart';

void main() {
  ensureInitialized();
  SilentPaymentRecipient? recipient;
  SilentPaymentRecipient? senderKeypair;
  SilentPaymentScanner? scanner;
  try {
    // RECIPIENT KEY GENERATION
    print('✅ Generating BIP-352 keys in Rust...');
    recipient = SilentPaymentRecipient.generate(network: NetworkFfi.signet);

    final recipientScanSecretHex = recipient.exportScanSecretHex().value;
    final recipientSpendPubkeyHex = recipient.exportSpendPubkeyHex().value;
    final recipientAddress = recipient.getAddress();

    print(
      'Recipient\n'
      'Address       : ${recipientAddress.address}\n'
      'Scan Secret   : $recipientScanSecretHex\n'
      'Spend Pubkey  : $recipientSpendPubkeyHex\n'
      'Network       : ${recipientAddress.network.name}\n',
    );

    print('Derive labeled sub-addresses');
    final standardAddr = recipient.getAddress();
    final label1Addr = recipient.getLabeledAddress(label: 1); // e.g. donations
    final label2Addr = recipient.getLabeledAddress(label: 2); // e.g. shop
    print(
      'Standard addr : ${standardAddr.address.substring(standardAddr.address.length - 30)}\n'
      'Label 1 addr  : ${label1Addr.address.substring(label1Addr.address.length - 30)}\n'
      'Label 2 addr  : ${label2Addr.address.substring(label2Addr.address.length - 30)}\n',
    );

    print('Create Recipient Scanner (watch-only)...');
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
    senderKeypair = SilentPaymentRecipient.generate(network: NetworkFfi.signet);

    // In production this is actually the sender's input private key (the private key
    // of the UTXO being spent), not his secret key.
    // exportScanSecretHex().value is just used as a hex string representation
    // of the private key for the purpose of having a valid 32-byte secp256k1
    // private key to fill in the SendingInput.
    final senderInputPrivKeyHex = senderKeypair.exportScanSecretHex().value;

    print('Sender creating one transaction with 3 SP outputs...');

    const standardAmount = 50000;
    const label1Amount = 75000;
    const label2Amount = 30000;

    // Sender describes the input(s) he is spending
    // In production it is the real UTXO the sender is spending.
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
        PaymentRecipient(
          address: standardAddr.address,
          amountSats: standardAmount,
        ),
        PaymentRecipient(address: label1Addr.address, amountSats: label1Amount),
        PaymentRecipient(address: label2Addr.address, amountSats: label2Amount),
      ],
    );

    // Derive tweak_data for the scanner
    // In production this is pre-computed server-side (tweak index / Frigate)
    final tweakData = computeSenderTweakData(inputs: senderInputs);

    // RECIPIENT SCANNS THE TRANSACTION
    // A_tweak already incorporates the input hash and all eligible sender inputs.
    // The scanner receives A_tweak from the tweak index server.
    // Recipient Scan for the transactions that beling to him
    // In a real scenario, the scanner receives the pre-computed tweak
    // from the tweak index server.
    // Scanner does: b_scan × tweak_data = shared_secret (same as sender computed)
    final result = scanner.scanTransactionWithLabels(
      senderInputPubkeysHex: [tweakData.value],
      txOutputPubkeysHex: outputs.map((o) => o.pubkeyHex).toList(),
      labels: [1, 2, 3],
    );

    if (result.payments.isEmpty) {
      print('Label demo failed - crypto mismatch');
      return;
    }

    for (final payment in result.payments) {
      final amount = [
        standardAmount,
        label1Amount,
        label2Amount,
      ][payment.outputIndex];
      print(
        'Payment detected on label: ${payment.label ?? "unlabeled"}\n'
        '   Amount : $amount sats\n',
      );
    }
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
