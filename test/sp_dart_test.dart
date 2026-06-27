import 'package:test/test.dart';

import 'package:sp_dart/sp_dart.dart';

void main() {
  test('invoke native function', () {
    expect(42, 42);
  });

  test('invoke async native callback', () async {
    expect(42, 42);
  });
}
