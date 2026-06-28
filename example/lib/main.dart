import 'package:sp_dart/sp_dart.dart';

void main() {
  ensureInitialized();

  final recipient = SilentPaymentRecipient.generate(network: NetworkFfi.signet);
  final address = recipient.getAddress();
  String scanSecreteHex = recipient.exportScanSecretHex().value;
  String spendPunKeyHex = recipient.exportSpendPubkeyHex().value;

  print(
    'BIP-352 keys generated\n'
    'SP-Address: ${address.address}\n'
    'Scan Secret: $scanSecreteHex\n'
    'Spend Pubkey: $spendPunKeyHex\n'
    'Network: ${address.network.name}',
  );
  recipient.dispose();
}
