// ESP32 base firmware: status page, password-protected settings, manual upload,
// and signed OTA updates pulled from GitHub. Credentials live in NVS, not in this file.
#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <Update.h>
#include <Preferences.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include "pubkey.h"

#ifdef USE_SEED
#include "seed_config.h"   // defines SEED_SSID, SEED_PASS, SEED_WEBPASS (private)
#endif

#ifndef FW_BUILD
#define FW_BUILD 1
#endif
#ifndef FW_VERSION
#define FW_VERSION dev
#endif
#define STR_(x) #x
#define STR(x) STR_(x)

static const char* OTA_BASE = "https://raw.githubusercontent.com/t112840006-coder/esp32-room-firmware/ota/ota/";
const int LED_PIN = 2;
const unsigned long CHECK_INTERVAL_MS = 30UL * 60UL * 1000UL;

extern const uint8_t rootca_bundle[] asm("_binary_x509_crt_bundle_start");

Preferences prefs;
WebServer server(80);
String cfgSsid, cfgPass, cfgWebPass;
bool apMode = false;
bool autoInstall = false;

// --- OTA state ---
struct OtaInfo { int build = 0; String version; uint32_t size = 0; String sha256; String file; } avail;
String otaState = "idle";
String otaError = "";
String tlsMode = "-";
bool installing = false, pendingInstall = false, pendingCheck = false;
uint32_t otaDone = 0, otaTotal = 0;
unsigned long nextCheck = 0, lastWifiTry = 0, lastLed = 0;
bool ledState = false;
String updateError = "";

// ---------------------------------------------------------------- helpers
bool auth() {
  if (apMode) return true;                       // setup AP is WPA2-protected
  if (!server.authenticate("admin", cfgWebPass.c_str())) { server.requestAuthentication(); return false; }
  return true;
}

static String htmlEscape(const String& s) {
  String o;
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '<') o += "&lt;"; else if (c == '>') o += "&gt;"; else if (c == '&') o += "&amp;";
    else if (c == '"') o += "&quot;"; else o += c;
  }
  return o;
}

const char STYLE[] PROGMEM =
  "<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
  "<style>body{font-family:-apple-system,system-ui,sans-serif;background:#111;color:#eee;text-align:center;padding:20px}"
  "h1{font-size:20px}pre{color:#aaa;font-size:14px;line-height:1.6;text-align:left;display:inline-block}a{color:#6ea0ff}"
  "input,button{font-size:17px;margin:8px 0;width:92%;padding:14px;border-radius:12px;border:0;background:#333;color:#fff}"
  "button.p{background:#2d6cdf}.ok{color:#7be495}.warn{color:#e4d97b}.bad{color:#ff7b7b}</style>";

// ---------------------------------------------------------------- settings
void loadConfig() {
  prefs.begin("cfg", false);
  cfgSsid = prefs.getString("ssid", "");
  cfgPass = prefs.getString("pass", "");
  cfgWebPass = prefs.getString("web", "");
  autoInstall = prefs.getBool("auto", false);
#ifdef USE_SEED
  if (cfgSsid.isEmpty()) {
    cfgSsid = SEED_SSID; cfgPass = SEED_PASS; cfgWebPass = SEED_WEBPASS;
    prefs.putString("ssid", cfgSsid); prefs.putString("pass", cfgPass); prefs.putString("web", cfgWebPass);
  }
#endif
}

// ---------------------------------------------------------------- signed OTA
static bool verifyManifest(const uint8_t* data, size_t len, const uint8_t* sig, size_t sigLen) {
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int r = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)OTA_PUBKEY_PEM, sizeof(OTA_PUBKEY_PEM));
  if (r != 0) { mbedtls_pk_free(&pk); return false; }
  uint8_t hash[32];
  mbedtls_sha256_ret(data, len, hash, 0);
  r = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sigLen);
  mbedtls_pk_free(&pk);
  return r == 0;
}

// Open a GET stream. First try a verified TLS connection; if the TLS handshake itself fails,
// retry without certificate validation (integrity is still guaranteed by the ECDSA signature).
static int openGet(HTTPClient& http, WiFiClientSecure& client, const String& url) {
  for (int attempt = 0; attempt < 2; attempt++) {
    if (attempt == 0) client.setCACertBundle(rootca_bundle); else client.setInsecure();
    http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
    http.setTimeout(15000);
    if (!http.begin(client, url)) continue;
    int code = http.GET();
    if (code > 0) { tlsMode = attempt == 0 ? "verified" : "insecure (signature-protected)"; return code; }
    http.end();
    client.stop();
  }
  return -1;
}

static bool fetchSmall(const String& url, uint8_t* buf, size_t maxLen, size_t& got) {
  WiFiClientSecure client; HTTPClient http;
  int code = openGet(http, client, url);
  if (code != 200) { otaError = "HTTP " + String(code) + " for " + url.substring(url.lastIndexOf('/') + 1); http.end(); return false; }
  WiFiClient* s = http.getStreamPtr();
  int total = http.getSize();
  got = 0;
  unsigned long t0 = millis();
  while ((http.connected() || s->available()) && (total < 0 || (int)got < total) && millis() - t0 < 15000) {
    int n = s->available();
    if (n > 0) {
      if (got + n > maxLen) { otaError = "response too large"; http.end(); return false; }
      got += s->readBytes(buf + got, n);
    } else delay(5);
  }
  http.end();
  return got > 0;
}

bool checkForUpdate() {
  otaState = "checking"; otaError = "";
  if (WiFi.status() != WL_CONNECTED) { otaState = "error"; otaError = "no Wi-Fi"; return false; }
  static uint8_t mbuf[1024]; static uint8_t sbuf[160];
  size_t mlen = 0, slen = 0;
  if (!fetchSmall(String(OTA_BASE) + "manifest.json", mbuf, sizeof(mbuf), mlen)) { otaState = "error"; return false; }
  if (!fetchSmall(String(OTA_BASE) + "manifest.sig", sbuf, sizeof(sbuf), slen)) { otaState = "error"; return false; }
  if (!verifyManifest(mbuf, mlen, sbuf, slen)) { otaState = "error"; otaError = "bad signature - ignored"; return false; }
  JsonDocument doc;
  if (deserializeJson(doc, mbuf, mlen)) { otaState = "error"; otaError = "bad manifest"; return false; }
  avail.build = doc["build"] | 0;
  avail.version = doc["version"] | "";
  avail.size = doc["size"] | 0;
  avail.sha256 = doc["sha256"] | "";
  avail.file = doc["file"] | "firmware.bin";
  if (avail.size < 100000 || avail.sha256.length() != 64) { otaState = "error"; otaError = "invalid manifest values"; return false; }
  otaState = avail.build > FW_BUILD ? "available" : "up-to-date";
  return true;
}

bool installUpdate() {
  if (installing) return false;
  installing = true; otaError = ""; otaDone = 0;
  // Always re-verify a fresh manifest right before installing.
  if (!checkForUpdate() || avail.build <= FW_BUILD) { installing = false; return false; }
  otaState = "installing"; otaTotal = avail.size;

  WiFiClientSecure client; HTTPClient http;
  int code = openGet(http, client, String(OTA_BASE) + avail.file);
  if (code != 200) { otaState = "error"; otaError = "HTTP " + String(code) + " downloading firmware"; http.end(); installing = false; return false; }
  if ((uint32_t)http.getSize() != avail.size) { otaState = "error"; otaError = "size mismatch"; http.end(); installing = false; return false; }
  if (!Update.begin(avail.size)) { otaState = "error"; otaError = String("Update.begin: ") + Update.errorString(); http.end(); installing = false; return false; }

  mbedtls_sha256_context sha; mbedtls_sha256_init(&sha); mbedtls_sha256_starts_ret(&sha, 0);
  WiFiClient* s = http.getStreamPtr();
  static uint8_t buf[1460];
  unsigned long lastData = millis(), lastServe = millis();
  while (otaDone < avail.size && millis() - lastData < 20000) {
    int n = s->available();
    if (n > 0) {
      if (n > (int)sizeof(buf)) n = sizeof(buf);
      if ((uint32_t)n > avail.size - otaDone) n = avail.size - otaDone;
      int r = s->readBytes(buf, n);
      if (r <= 0) continue;
      if (Update.write(buf, r) != (size_t)r) { otaError = String("write: ") + Update.errorString(); break; }
      mbedtls_sha256_update_ret(&sha, buf, r);
      otaDone += r; lastData = millis();
    } else delay(2);
    if (millis() - lastServe > 400) { lastServe = millis(); server.handleClient(); }   // keep status page alive
  }
  http.end();
  uint8_t digest[32]; mbedtls_sha256_finish_ret(&sha, digest); mbedtls_sha256_free(&sha);
  char hex[65]; for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", digest[i]);

  bool ok = otaError.isEmpty() && otaDone == avail.size && avail.sha256.equalsIgnoreCase(String(hex));
  if (!ok) {
    Update.abort();
    otaState = "error";
    if (otaError.isEmpty()) otaError = otaDone != avail.size ? "download incomplete" : "hash mismatch - rejected";
    installing = false; return false;
  }
  if (!Update.end(true)) { otaState = "error"; otaError = String("Update.end: ") + Update.errorString(); installing = false; return false; }
  otaState = "installed, rebooting";
  server.handleClient();
  delay(800);
  ESP.restart();
  return true;
}

// ---------------------------------------------------------------- web
String apiJson() {
  String j = "{";
  j += "\"version\":\"" + String(STR(FW_VERSION)) + "\",\"build\":" + String(FW_BUILD);
  j += ",\"uptime\":" + String(millis() / 1000);
  j += ",\"wifi\":" + String(WiFi.status() == WL_CONNECTED ? "true" : "false");
  j += ",\"ssid\":\"" + WiFi.SSID() + "\",\"ip\":\"" + WiFi.localIP().toString() + "\",\"rssi\":" + String(WiFi.RSSI());
  j += ",\"heap\":" + String(ESP.getFreeHeap());
  j += ",\"ota\":\"" + otaState + "\",\"ota_err\":\"" + otaError + "\"";
  j += ",\"avail_build\":" + String(avail.build) + ",\"avail_version\":\"" + avail.version + "\"";
  j += ",\"done\":" + String(otaDone) + ",\"total\":" + String(otaTotal);
  j += ",\"auto\":" + String(autoInstall ? "true" : "false") + ",\"tls\":\"" + tlsMode + "\"}";
  return j;
}

const char HOME[] PROGMEM = R"HTML(<!doctype html><html><head><title>ESP32 Base</title></head><body>
<h1>ESP32 Base</h1><pre id="s">loading...</pre>
<div id="u"></div>
<button class="p" onclick="go('/ota/check')">Check for update</button>
<button id="ins" class="p" style="display:none" onclick="if(confirm('Install update now?'))go('/ota/install')">Install update</button>
<button onclick="go('/ota/auto?on='+(window.auto?0:1))" id="au"></button>
<p><a href="/settings">Settings</a> &nbsp; <a href="/update">Manual upload</a></p>
<script>
async function go(p){try{await fetch(p)}catch(e){} load()}
async function load(){try{const d=await (await fetch('/api')).json();window.auto=d.auto;
s.textContent='version  '+d.version+' (build '+d.build+')\nuptime   '+d.uptime+' s\nwifi     '+d.ssid+'  '+d.ip+'  '+d.rssi+' dBm\nheap     '+d.heap+'\ntls      '+d.tls;
let t='update: '+d.ota;if(d.ota==='available')t+=' → '+d.avail_version+' (build '+d.avail_build+')';
if(d.ota==='installing')t+=' '+Math.round(d.done*100/Math.max(d.total,1))+'%';
if(d.ota_err)t+='<br><span class="bad">'+d.ota_err+'</span>';
u.innerHTML=t;ins.style.display=d.ota==='available'?'':'none';
au.textContent='Auto-install: '+(d.auto?'ON':'OFF');}catch(e){}}
setInterval(load,1500);load();
</script></body></html>)HTML";

void setupRoutes() {
  server.on("/", []() {
    if (!auth()) return;
    if (apMode) {
      String h = "<!doctype html><html><head>" + String(FPSTR(STYLE)) + "<title>Setup</title></head><body><h1>Wi-Fi setup</h1>"
                 "<form method='POST' action='/settings'><input name='ssid' placeholder='Wi-Fi name'>"
                 "<input name='pass' type='password' placeholder='Wi-Fi password'>"
                 "<input name='web' type='password' placeholder='New admin password (min 8)'><button class='p'>Save</button></form></body></html>";
      server.send(200, "text/html", h); return;
    }
    server.send(200, "text/html", String("<!doctype html><html><head>") + FPSTR(STYLE) + FPSTR(HOME));
  });
  server.on("/api", []() { if (!auth()) return; server.send(200, "application/json", apiJson()); });
  server.on("/ota/check", []() { if (!auth()) return; pendingCheck = true; server.send(200, "text/plain", "checking\n"); });
  server.on("/ota/install", []() { if (!auth()) return; pendingInstall = true; server.send(200, "text/plain", "installing\n"); });
  server.on("/ota/auto", []() {
    if (!auth()) return;
    autoInstall = server.arg("on") == "1"; prefs.putBool("auto", autoInstall);
    server.send(200, "text/plain", autoInstall ? "auto on\n" : "auto off\n");
  });
  server.on("/settings", HTTP_GET, []() {
    if (!auth()) return;
    String h = "<!doctype html><html><head>" + String(FPSTR(STYLE)) + "<title>Settings</title></head><body><h1>Settings</h1>"
               "<form method='POST'><input name='ssid' value='" + htmlEscape(cfgSsid) + "' placeholder='Wi-Fi name'>"
               "<input name='pass' type='password' placeholder='Wi-Fi password (blank = keep)'>"
               "<input name='web' type='password' placeholder='New admin password (blank = keep, min 8)'>"
               "<button class='p'>Save and reboot</button></form><p><a href='/'>Back</a></p></body></html>";
    server.send(200, "text/html", h);
  });
  server.on("/settings", HTTP_POST, []() {
    if (!auth()) return;
    String ssid = server.arg("ssid"), pass = server.arg("pass"), web = server.arg("web");
    if (ssid.length() > 0 && ssid.length() <= 32) { prefs.putString("ssid", ssid); }
    if (pass.length() > 0 && pass.length() >= 8) prefs.putString("pass", pass);
    if (web.length() >= 8) prefs.putString("web", web);
    server.send(200, "text/plain", "saved, rebooting");
    delay(500); ESP.restart();
  });
  server.on("/update", HTTP_GET, []() {
    if (!auth()) return;
    server.send(200, "text/html", String("<!doctype html><html><head>") + FPSTR(STYLE) + "<title>Update</title></head><body><h1>Manual upload</h1>"
      "<form method='POST' enctype='multipart/form-data'><input type='file' name='fw'><button class='p'>Upload</button></form>"
      "<p><a href='/'>Back</a></p></body></html>");
  });
  server.on("/update", HTTP_POST,
    []() {
      if (!auth()) return;
      if (Update.hasError() || updateError.length()) {
        server.send(200, "text/plain", "FAIL: " + (updateError.length() ? updateError : String(Update.errorString())));
        updateError = ""; return;
      }
      server.send(200, "text/plain", "OK, rebooting"); delay(300); ESP.restart();
    },
    []() {
      if (!auth()) return;
      HTTPUpload& u = server.upload();
      if (u.status == UPLOAD_FILE_START) { updateError = ""; if (!Update.begin(UPDATE_SIZE_UNKNOWN)) updateError = Update.errorString(); }
      else if (u.status == UPLOAD_FILE_WRITE) { if (!updateError.length() && Update.write(u.buf, u.currentSize) != u.currentSize) updateError = Update.errorString(); }
      else if (u.status == UPLOAD_FILE_END) { if (!updateError.length() && !Update.end(true)) updateError = Update.errorString(); }
      else if (u.status == UPLOAD_FILE_ABORTED) { Update.abort(); updateError = "upload aborted"; }
    });
}

// ---------------------------------------------------------------- arduino
void setup() {
  pinMode(LED_PIN, OUTPUT);
  loadConfig();

  uint8_t mac[6]; WiFi.macAddress(mac);
  char suffix[5]; sprintf(suffix, "%02X%02X", mac[4], mac[5]);
  if (cfgSsid.isEmpty() || cfgWebPass.length() < 8) {
    apMode = true;
    WiFi.mode(WIFI_AP);
    WiFi.softAP((String("ESP32-Setup-") + suffix).c_str(), "esp32setup");
  } else {
    WiFi.mode(WIFI_STA);
    WiFi.setHostname("esp32-base");
    WiFi.setAutoReconnect(true);
    WiFi.begin(cfgSsid.c_str(), cfgPass.c_str());
  }
  setupRoutes();
  server.begin();
  nextCheck = millis() + 60000;
}

void loop() {
  server.handleClient();

  if (!apMode) {
    if (WiFi.status() != WL_CONNECTED && millis() - lastWifiTry > 15000) {
      lastWifiTry = millis(); WiFi.disconnect(); WiFi.begin(cfgSsid.c_str(), cfgPass.c_str());
    }
    if (pendingCheck) { pendingCheck = false; checkForUpdate(); }
    if (pendingInstall) { pendingInstall = false; installUpdate(); }
    if (WiFi.status() == WL_CONNECTED && millis() > nextCheck) {
      nextCheck = millis() + CHECK_INTERVAL_MS;
      if (checkForUpdate() && autoInstall && avail.build > FW_BUILD) pendingInstall = true;
    }
  }

  unsigned long period = apMode ? 100 : (WiFi.status() == WL_CONNECTED ? 1000 : 250);
  if (millis() - lastLed >= period) { lastLed = millis(); ledState = !ledState; digitalWrite(LED_PIN, ledState); }
}
