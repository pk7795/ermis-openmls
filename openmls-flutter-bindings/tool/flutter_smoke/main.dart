import 'package:flutter/material.dart';
import 'package:openmls_flutter/openmls_flutter.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await OpenMlsFlutter.init();
  final channelId = await hashChannelId(
    projectId: 'openmls-flutter-smoke',
    userIds: ['alice', 'bob'],
  );

  runApp(
    MaterialApp(
      home: Scaffold(
        body: Center(child: Text('OpenMLS Flutter ready: $channelId')),
      ),
    ),
  );
}
