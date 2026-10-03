import 'dart:io';

void setup(HttpClient client, SharedPreferences prefs, String t) {
  client.badCertificateCallback = (cert, host, port) => true; // BAD:flutter-tls-verification-disabled
  client.badCertificateCallback = (X509Certificate cert, String host, int port) { return true; }; // BAD:flutter-tls-verification-disabled
  client.badCertificateCallback = (cert, host, port) => host == 'localhost';
  prefs.setString('auth_token', t); // BAD:flutter-secret-in-shared-preferences
  prefs.setString('userPassword', t); // BAD:flutter-secret-in-shared-preferences
  prefs.setString('theme', 'dark');
  final db = 'postgres://app:s3cr3tpass@db:5432/app'; // BAD:hardcoded-database-url-credentials
}
