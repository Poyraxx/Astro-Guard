#if !defined(ARDUINO_ARCH_ESP32)
#error "Bu sketch ESP32 icindir. Arduino IDE'de Tools > Board menusunden bir ESP32 karti secmelisin."
#endif

#include <Preferences.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiUdp.h>
#include <mbedtls/sha256.h>
#include <sys/time.h>
#include <time.h>

#include "bkzs_esp32_profile.h"
#include "bkzs_wifi_secrets.h"

Preferences g_store;
WiFiUDP g_udp;
WiFiClient g_tcpClient;

uint32_t g_sequence = BKZS_SEQ_START;
String g_previousCleanHash;
unsigned long g_lastSendAt = 0;
String g_signalPrefix;
String g_signalSuffix;

String jsonEscape(const String& value) {
  String escaped;
  escaped.reserve(value.length() + 8);
  for (size_t i = 0; i < value.length(); ++i) {
    const char ch = value[i];
    if (ch == '\\' || ch == '"') {
      escaped += '\\';
      escaped += ch;
    } else if (ch == '\n') {
      escaped += "\\n";
    } else if (ch == '\r') {
      escaped += "\\r";
    } else if (ch == '\t') {
      escaped += "\\t";
    } else {
      escaped += ch;
    }
  }
  return escaped;
}

String quoted(const String& value) {
  return "\"" + jsonEscape(value) + "\"";
}

String trimNumeric(String value) {
  if (value.indexOf('.') < 0) {
    return value;
  }
  while (value.endsWith("0")) {
    value.remove(value.length() - 1);
  }
  if (value.endsWith(".")) {
    value.remove(value.length() - 1);
  }
  if (value == "-0") {
    return "0";
  }
  return value;
}

String formatNumber(double value, uint8_t decimals) {
  return trimNumeric(String(static_cast<float>(value), static_cast<unsigned int>(decimals)));
}

String sha256Hex(const String& input) {
  unsigned char digest[32];
  mbedtls_sha256_context context;
  mbedtls_sha256_init(&context);
  mbedtls_sha256_starts(&context, 0);
  mbedtls_sha256_update(&context, reinterpret_cast<const unsigned char*>(input.c_str()), input.length());
  mbedtls_sha256_finish(&context, digest);
  mbedtls_sha256_free(&context);

  static const char* HEX_DIGITS = "0123456789abcdef";
  String output;
  output.reserve(64);
  for (uint8_t byte : digest) {
    output += HEX_DIGITS[(byte >> 4) & 0x0F];
    output += HEX_DIGITS[byte & 0x0F];
  }
  return output;
}

String digest24(const String& input) {
  return sha256Hex(input).substring(0, 24);
}

String digest16(const String& input) {
  return sha256Hex(input).substring(0, 16);
}

String randomPacketId() {
  const char* hex = "0123456789abcdef";
  String packetId;
  packetId.reserve(12);
  while (packetId.length() < 12) {
    uint32_t value = esp_random();
    for (int i = 0; i < 8 && packetId.length() < 12; ++i) {
      packetId += hex[(value >> (28 - (i * 4))) & 0x0F];
    }
  }
  return packetId;
}

String buildAttackMetaJson() {
  return "{\"secret_compromised\":false,\"stage_hint\":null}";
}

String buildPayloadJson() {
  return String("{\"attack_meta\":") + buildAttackMetaJson()
       + ",\"channel\":" + quoted(String(BKZS_CHANNEL))
       + ",\"confidence\":0.995"
       + ",\"mission_phase\":" + quoted(String(BKZS_MISSION_PHASE))
       + "}";
}

String buildMetricsJson() {
  return String("{\"altitude\":") + formatNumber(BKZS_BASE_ALTITUDE, 1)
       + ",\"clock_bias\":12.5"
       + ",\"clock_drift\":0.8"
       + ",\"cn0\":43.2"
       + ",\"doppler\":1210.4"
       + ",\"latitude\":" + formatNumber(BKZS_BASE_LATITUDE, 6)
       + ",\"longitude\":" + formatNumber(BKZS_BASE_LONGITUDE, 6)
       + ",\"power\":-109.6"
       + ",\"sat_count\":9"
       + ",\"speed\":" + formatNumber(BKZS_BASE_SPEED_MPS, 1)
       + "}";
}

String initialCleanHashForSource(const String& source) {
  return digest24(
      String("{\"lane\":\"genesis\",\"session_nonce\":") + quoted(String(BKZS_SESSION_NONCE))
      + ",\"source\":" + quoted(source)
      + "}"
  );
}

String buildChallengeProof(const String& source, const String& epochId, const String& previousCleanHash) {
  return digest24(
      String("{\"epoch_id\":") + quoted(epochId)
      + ",\"lane\":\"primary\""
      + ",\"previous_clean_hash\":" + quoted(previousCleanHash)
      + ",\"seed\":" + quoted(String(BKZS_SIGNAL_SECRET))
      + ",\"session_nonce\":" + quoted(String(BKZS_SESSION_NONCE))
      + ",\"source\":" + quoted(source)
      + "}"
  );
}

String buildPacketWithoutChecksumAndFlowTag(
    const String& packetId,
    const String& source,
    const String& timestampIso,
    const String& epochId,
    const String& challengeProof
) {
  return String("{\"challenge_proof\":") + quoted(challengeProof)
       + ",\"epoch_id\":" + quoted(epochId)
       + ",\"holdover_state\":{}"
       + ",\"metrics\":" + buildMetricsJson()
       + ",\"op_code\":" + quoted(String(BKZS_OP_CODE))
       + ",\"packet_id\":" + quoted(packetId)
       + ",\"payload\":" + buildPayloadJson()
       + ",\"peer_observations\":{}"
       + ",\"seq\":" + String(g_sequence)
       + ",\"session_nonce\":" + quoted(String(BKZS_SESSION_NONCE))
       + ",\"source\":" + quoted(source)
       + ",\"trust_lane\":\"primary\""
       + ",\"ts\":" + quoted(timestampIso)
       + "}";
}

String buildFlowTag(const String& packetWithoutChecksumAndFlowTag) {
  return digest24(
      String("{\"payload\":") + packetWithoutChecksumAndFlowTag
      + ",\"session_nonce\":" + quoted(String(BKZS_SESSION_NONCE))
      + ",\"signal_secret\":" + quoted(String(BKZS_SIGNAL_SECRET))
      + "}"
  );
}

String buildFullPacket(
    const String& packetId,
    const String& source,
    const String& timestampIso,
    const String& epochId,
    const String& challengeProof,
    const String& flowTag,
    const String& checksum
) {
  return String("{\"challenge_proof\":") + quoted(challengeProof)
       + ",\"checksum\":" + quoted(checksum)
       + ",\"epoch_id\":" + quoted(epochId)
       + ",\"flow_tag\":" + quoted(flowTag)
       + ",\"holdover_state\":{}"
       + ",\"metrics\":" + buildMetricsJson()
       + ",\"op_code\":" + quoted(String(BKZS_OP_CODE))
       + ",\"packet_id\":" + quoted(packetId)
       + ",\"payload\":" + buildPayloadJson()
       + ",\"peer_observations\":{}"
       + ",\"seq\":" + String(g_sequence)
       + ",\"session_nonce\":" + quoted(String(BKZS_SESSION_NONCE))
       + ",\"source\":" + quoted(source)
       + ",\"trust_lane\":\"primary\""
       + ",\"ts\":" + quoted(timestampIso)
       + "}";
}

void splitSignalSecret() {
  String secret = String(BKZS_SIGNAL_SECRET);
  int midpoint = secret.length() / 2;
  if (midpoint <= 0) {
    g_signalPrefix = secret;
    g_signalSuffix = "";
    return;
  }
  g_signalPrefix = secret.substring(0, midpoint);
  g_signalSuffix = secret.substring(midpoint);
}

String frameSignalPayload(const String& packetJson) {
  return g_signalPrefix + packetJson + g_signalSuffix;
}

bool ensureUtcTime() {
  time_t now = time(nullptr);
  if (now > 1700000000) {
    return true;
  }
  configTime(0, 0, BKZS_NTP_SERVER);
  for (int i = 0; i < 40; ++i) {
    delay(250);
    now = time(nullptr);
    if (now > 1700000000) {
      return true;
    }
  }
  return false;
}

bool buildTimestampIso(String& isoOut, String& epochIdOut) {
  struct timeval currentTime;
  if (gettimeofday(&currentTime, nullptr) != 0) {
    return false;
  }
  if (currentTime.tv_sec < 1700000000) {
    return false;
  }
  struct tm utcTime;
  gmtime_r(&currentTime.tv_sec, &utcTime);
  char buffer[40];
  snprintf(
      buffer,
      sizeof(buffer),
      "%04d-%02d-%02dT%02d:%02d:%02d.%03ld+00:00",
      utcTime.tm_year + 1900,
      utcTime.tm_mon + 1,
      utcTime.tm_mday,
      utcTime.tm_hour,
      utcTime.tm_min,
      utcTime.tm_sec,
      currentTime.tv_usec / 1000
  );
  isoOut = String(buffer);
  epochIdOut = String(static_cast<unsigned long>(currentTime.tv_sec));
  return true;
}

void connectWifi() {
  if (WiFi.status() == WL_CONNECTED) {
    return;
  }
  WiFi.mode(WIFI_STA);
  WiFi.begin(BKZS_WIFI_SSID, BKZS_WIFI_PASSWORD);
  Serial.print("Wi-Fi baglaniyor");
  uint8_t tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 40) {
    delay(250);
    Serial.print(".");
    tries++;
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("Wi-Fi baglandi. ESP32 IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("Wi-Fi baglantisi kurulamadi.");
  }
}

void clearChainState() {
  g_store.remove("seq");
  g_store.remove("prev_hash");
  g_sequence = BKZS_SEQ_START;
  g_previousCleanHash = initialCleanHashForSource(String(BKZS_SOURCE));
}

void loadChainState() {
  g_store.begin("bkzs-esp32", false);
  if (BKZS_FORCE_GENESIS_ON_BOOT) {
    clearChainState();
    return;
  }
  pinMode(0, INPUT_PULLUP);
  if (digitalRead(0) == LOW) {
    clearChainState();
    Serial.println("BOOT tusu basiliydi, zincir state temizlendi.");
    return;
  }
  g_sequence = g_store.getUInt("seq", BKZS_SEQ_START);
  g_previousCleanHash = g_store.getString("prev_hash", initialCleanHashForSource(String(BKZS_SOURCE)));
}

void saveChainState() {
  g_store.putUInt("seq", g_sequence);
  g_store.putString("prev_hash", g_previousCleanHash);
}

bool sendFramedPacket(const String& framedPacket) {
#if BKZS_USE_UDP
  if (!g_udp.beginPacket(BKZS_TARGET_HOST, BKZS_TARGET_PORT)) {
    return false;
  }
  g_udp.print(framedPacket);
  return g_udp.endPacket() > 0;
#else
  if (!g_tcpClient.connect(BKZS_TARGET_HOST, BKZS_TARGET_PORT)) {
    return false;
  }
  size_t written = g_tcpClient.print(framedPacket);
  g_tcpClient.stop();
  return written == framedPacket.length();
#endif
}

void sendNormalPacket() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWifi();
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Paket atlandi: Wi-Fi bagli degil.");
    return;
  }
  if (!ensureUtcTime()) {
    Serial.println("Paket atlandi: UTC saat senkronize degil.");
    return;
  }

  String timestampIso;
  String epochId;
  if (!buildTimestampIso(timestampIso, epochId)) {
    Serial.println("Paket atlandi: zaman damgasi olusturulamadi.");
    return;
  }

  const String source = String(BKZS_SOURCE);
  const String packetId = randomPacketId();
  const String challengeProof = buildChallengeProof(source, epochId, g_previousCleanHash);
  const String packetWithoutChecksumAndFlowTag = buildPacketWithoutChecksumAndFlowTag(
      packetId,
      source,
      timestampIso,
      epochId,
      challengeProof
  );
  const String flowTag = buildFlowTag(packetWithoutChecksumAndFlowTag);
  const String checksum = digest16(packetWithoutChecksumAndFlowTag);
  const String packetJson = buildFullPacket(
      packetId,
      source,
      timestampIso,
      epochId,
      challengeProof,
      flowTag,
      checksum
  );
  const String framedPacket = frameSignalPayload(packetJson);

  const bool sent = sendFramedPacket(framedPacket);
  if (!sent) {
    Serial.print("Gonderim basarisiz | seq ");
    Serial.println(g_sequence);
    return;
  }

  g_previousCleanHash = digest24(packetWithoutChecksumAndFlowTag);
  g_sequence += 1;
  saveChainState();

  Serial.print("Gonderildi | seq ");
  Serial.print(g_sequence - 1);
  Serial.print(" | packet_id ");
  Serial.print(packetId);
  Serial.print(" | target ");
  Serial.print(BKZS_TARGET_HOST);
  Serial.print(":");
  Serial.println(BKZS_TARGET_PORT);
}

void setup() {
  Serial.begin(115200);
  delay(500);
  splitSignalSecret();
  connectWifi();
  ensureUtcTime();
#if BKZS_USE_UDP
  g_udp.begin(0);
#endif
  loadChainState();
  Serial.println("BKZS ESP32 temiz veri gonderici hazir.");
}

void loop() {
  if (millis() - g_lastSendAt >= BKZS_SEND_INTERVAL_MS) {
    g_lastSendAt = millis();
    sendNormalPacket();
  }
  delay(10);
}
