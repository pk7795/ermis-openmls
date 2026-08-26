import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:openmls_flutter/openmls_flutter.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('loads the packaged native asset and calls Rust', (tester) async {
    await OpenMlsFlutter.init();

    final first = await hashChannelId(
      projectId: 'openmls-flutter-smoke',
      userIds: ['alice', 'bob'],
    );
    final second = await hashChannelId(
      projectId: 'openmls-flutter-smoke',
      userIds: ['bob', 'alice'],
    );

    expect(first, isNotEmpty);
    expect(second, first);
  });
}
