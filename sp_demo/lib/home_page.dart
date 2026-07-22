import 'package:flutter/material.dart';
import 'package:sp_dart/sp_dart.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  String _output = 'Press a button to call Rust.';
  String _address = 'tsp1q...';
  bool _loading = false;

  void _setLoading(String msg) => setState(() {
    _loading = true;
    _output = msg;
  });

  void _setOutput(String txt) => setState(() {
    _loading = false;
    _output = txt;
  });

  // Key generation
  void _generateSpKeys() {
    _setLoading('Generating BIP-352 keys in Rust...');

    SilentPaymentRecipient? recipient;
    try {
      recipient = SilentPaymentRecipient.generate(network: Network.signet);

      final address = recipient.getAddress();
      _address = address.address;
      String scanSecreteHex = recipient.exportScanSecretHex().value;
      String spendPunKeyHex = recipient.exportSpendPubkeyHex().value;

      _setOutput(
        'BIP-352 keys generated\n\n'
        'SP-Address: $_address\n\n'
        'Scan Secret: $scanSecreteHex\n\n'
        'Spend Pubkey: $spendPunKeyHex\n\n'
        'Network: ${address.network.name}',
      );
    } on SilentPaymentException catch (e) {
      _setOutput('$e');
    } finally {
      recipient?.dispose();
      setState(() => _loading = false);
    }
  }

  // End-to-end demo (offline, no server)
  void _runOfflineDemo() {
    _setLoading('Running full BIP-352 demo (with input hash)...');
    SilentPaymentRecipient? recipient;
    SilentPaymentRecipient? senderKeypair;
    SilentPaymentScanner? scanner;

    try {
      recipient = SilentPaymentRecipient.generate(network: Network.testnet);
      senderKeypair = SilentPaymentRecipient.generate(network: Network.testnet);

      final recipientAddr = recipient.getAddress();
      final senderPrivKey = senderKeypair.exportScanSecretHex().value;

      // In production: the real UTXO the sender is spending.
      // For demo: a valid-format fake txid (64 hex chars = 32 bytes).
      // The input hash will be computed correctly using this outpoint.
      final senderInputs = [
        SendingInput(
          secretKeyHex: senderPrivKey,
          isTaproot: false, // P2WPKH
          txid:
              'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
          vout: 0,
        ),
      ];

      // Full BIP-352: compute output with proper input hash
      final outputs = createSilentPaymentOutputs(
        inputs: senderInputs,
        recipients: [
          PaymentRecipient(address: recipientAddr.address, amountSats: 70000),
        ],
      );

      // compute tweak data = A_sum × input_hash = partial_secret × G
      // This is what the tweak index server computes and serves to mobile wallets.
      // We must NOT pass the raw sender pubkey — the input hash changes it.
      final tweakData = computeSenderTweakData(inputs: senderInputs);

      // Recipient scans — scanner only needs scan secret + spend pubkey
      scanner = SilentPaymentScanner.watchOnly(
        scanSecretHex: recipient.exportScanSecretHex().value,
        spendPubkeyHex: recipient.exportSpendPubkeyHex().value,
      );

      // The scanner uses the sender's PUBLIC input key (the A_sum from the server).
      // In production: the tweak index server computes A_sum × input_hash.
      // For this demo: we pass the sender's pubkey directly, which means
      // the scanner's ECDH and the sender's ECDH must produce matching shared secrets.
      //
      // Note: in a real transaction, the scanner receives the pre-computed tweak
      // from the tweak index server. Here we're verifying the full round-trip.
      final result = scanner.scanTransaction(
        senderInputPubkeysHex: [tweakData.value],
        txOutputPubkeysHex: outputs.map((o) => o.pubkeyHex).toList(),
      );

      _setOutput(
        result.payments.isNotEmpty
            ? 'BIP-352 Round-Trip\n\n'
                  'Sender computed output:\n'
                  '   ${outputs.first.pubkeyHex.substring(0, 20)}...\n\n'
                  'Recipient FOUND the payment:\n'
                  '   Amount : ${result.payments.first.amountSats} sats\n'
                  '   Label  : ${result.payments.first.label ?? "unlabeled"}\n\n'
            : 'Round-trip failed — crypto mismatch',
      );
    } on SilentPaymentException catch (e) {
      _setOutput('${e.runtimeType}: $e');
    } catch (e) {
      _setOutput('$e');
    } finally {
      recipient?.dispose();
      senderKeypair?.dispose();
      scanner?.dispose();
      setState(() => _loading = false);
    }
  }

  void _demonstrateLabels() {
    SilentPaymentRecipient? recipient;
    SilentPaymentRecipient? senderKeypair;
    SilentPaymentScanner? scanner;

    try {
      recipient = SilentPaymentRecipient.generate(network: Network.signet);
      senderKeypair = SilentPaymentRecipient.generate(network: Network.signet);

      final senderPrivKey = senderKeypair.exportScanSecretHex().value;
      // final senderPubKey = senderKeypair.getAddress().scanPubkeyHex;

      final standardAddr = recipient.getAddress();
      final label1Addr = recipient.getLabeledAddress(label: 1);
      final label2Addr = recipient.getLabeledAddress(label: 2);

      final senderInputs = [
        SendingInput(
          secretKeyHex: senderPrivKey,
          isTaproot: false, // P2WPKH — most common wallet input type
          txid:
              'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
          vout: 0,
        ),
      ];
      // Sender pays to label 1
      final outputs = createSilentPaymentOutputs(
        inputs: senderInputs,
        recipients: [
          PaymentRecipient(address: label1Addr.address, amountSats: 75000),
        ],
      );

      final tweakData = computeSenderTweakData(inputs: senderInputs);

      scanner = SilentPaymentScanner.watchOnly(
        scanSecretHex: recipient.exportScanSecretHex().value,
        spendPubkeyHex: recipient.exportSpendPubkeyHex().value,
      );

      final result = scanner.scanTransactionWithLabels(
        senderInputPubkeysHex: [tweakData.value],
        txOutputPubkeysHex: outputs.map((o) => o.pubkeyHex).toList(),
        labels: [1, 2, 3],
      );

      if (result.payments.isEmpty) {
        _setOutput('Label demo failed — crypto mismatch');
        return;
      }

      final std = standardAddr.address;
      final lbl1 = label1Addr.address;
      final lbl2 = label2Addr.address;
      final payment = result.payments.first;
      _setOutput(
        'Label Demo\n\n'
        'Standard addr : ${'${std.substring(0, 8)}...${std.substring(std.length - 20)}'}\n'
        'Label 1 addr  : ${'${lbl1.substring(0, 8)}...${lbl1.substring(lbl1.length - 20)}'}\n'
        'Label 2 addr  : ${'${lbl2.substring(0, 8)}...${lbl2.substring(lbl2.length - 20)}'}\n\n'
        'Payment detected on label: ${payment.label ?? "unlabeled"}\n'
        '   Amount : ${payment.amountSats} sats',
      );
    } on SilentPaymentException catch (e) {
      _setOutput(e.toString());
    } catch (e) {
      _setOutput(e.toString());
    } finally {
      recipient?.dispose();
      senderKeypair?.dispose();
      scanner?.dispose();
      setState(() => _loading = false);
    }
  }

  /// UI
  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 2,
      child: Scaffold(
        appBar: AppBar(
          title: const Text('BIP-352 Silent Payments'),
          backgroundColor: Theme.of(context).colorScheme.inversePrimary,
          bottom: const TabBar(
            tabs: [
              Tab(icon: Icon(Icons.home), text: 'Wallet'),
              Tab(icon: Icon(Icons.history), text: 'Payments'),
            ],
          ),
        ),
        body: TabBarView(children: [_walletTab(), _paymentsTab()]),
      ),
    );
  }

  Widget _walletTab() => SingleChildScrollView(
    padding: const EdgeInsets.all(16),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Status card
        Card(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.grey.shade50,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: SelectableText(
                    'SP-Adress: $_address',
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      height: 1.6,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  'Scan Status',
                  style: Theme.of(context).textTheme.titleSmall,
                ),
                const SizedBox(height: 8),
                _statusRow('Last height', '0'),
                _statusRow('Total blocks', '0'),
                _statusRow('Payments', '0 found'),
              ],
            ),
          ),
        ),

        const SizedBox(height: 12),

        // Buttons
        FilledButton.icon(
          onPressed: _loading ? null : _generateSpKeys,
          icon: const Icon(Icons.vpn_key),
          label: const Text('Generate Keys'),
        ),
        const SizedBox(height: 8),

        FilledButton.icon(
          onPressed: () {},
          icon: const Icon(Icons.sync),
          label: const Text('Sync Now (Coming soon)'),
        ),
        const SizedBox(height: 8),

        OutlinedButton.icon(
          onPressed: _loading ? null : _runOfflineDemo,
          icon: const Icon(Icons.science_outlined),
          label: const Text('End-to-End Demo (Offline)'),
        ),

        const SizedBox(height: 8),

        OutlinedButton.icon(
          onPressed: _loading ? null : _demonstrateLabels,
          icon: const Icon(Icons.label_outline),
          label: const Text('Label Demo'),
        ),
        const SizedBox(height: 8),

        // Progress
        if (_loading) ...[
          const LinearProgressIndicator(),
          const SizedBox(height: 8),
        ],

        // Output
        Container(
          constraints: const BoxConstraints(minHeight: 200),
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Colors.grey.shade50,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: Colors.grey.shade300),
          ),
          child: SelectableText(
            _output,
            style: const TextStyle(
              fontFamily: 'monospace',
              fontSize: 12,
              height: 1.6,
            ),
          ),
        ),

        const SizedBox(height: 8),
        Text(
          'Output Log',
          textAlign: TextAlign.center,
          style: const TextStyle(fontSize: 11, color: Colors.grey),
        ),
      ],
    ),
  );

  Widget _paymentsTab() {
    return const Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.inbox_outlined, size: 64, color: Colors.grey),
          SizedBox(height: 12),
          Text('No payments yet.', style: TextStyle(color: Colors.grey)),
          SizedBox(height: 4),
          Text(
            'Sync to check for incoming payments.',
            style: TextStyle(fontSize: 12, color: Colors.grey),
          ),
        ],
      ),
    );
  }

  Widget _statusRow(String label, String value) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 2),
    child: Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label, style: const TextStyle(fontSize: 12)),
        Text(
          value,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
        ),
      ],
    ),
  );
}
