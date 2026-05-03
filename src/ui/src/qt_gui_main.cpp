#include "netsentinel/diagnostics/diagnostic_tools.h"
#include "netsentinel/engine/adapter_inventory.h"
#include "netsentinel/engine/oui_vendor.h"
#include "netsentinel/engine/scan_contract.h"
#include "netsentinel/engine/scan_scope.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QMetaObject>
#include <QPixmap>
#include <QProgressBar>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QSplitter>
#include <QStackedWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QThread>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace {

struct NetworkContext {
    QString adapter = "Unknown adapter";
    QString local_ip;
    QString cidr = "192.168.50.0/24";
    QString gateway = "192.168.50.1";
    QString dns;
};

struct AppSettings {
    QString cidr = "192.168.50.0/24";
    int timeout_seconds = 4;
    bool arp = true;
    bool icmp = true;
    bool tcp = true;
    QString port_preset = "Common";
    QString report_dir = "reports";
    bool dark = true;
};

struct PortRow {
    QString target;
    int port = 0;
    QString protocol = "TCP";
    QString state = "open";
    QString service;
    QString note;
};

struct Device {
    QString ip;
    QString mac = "-";
    QString hostname = "-";
    QString vendor = "Unknown vendor";
    QString type = "Unknown";
    QString state = "Online";
    QString first_seen;
    QString last_seen;
    QString methods;
    QStringList ports;
    QStringList services;
    QStringList findings;
    QStringList events;
    QString details;
};

struct ScanData {
    bool ok = false;
    QString message;
    NetworkContext context;
    QString cidr;
    QString started_at;
    QString finished_at;
    std::vector<Device> devices;
    std::vector<PortRow> ports;
    QStringList events;
};

QString now_text() {
    return QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
}

bool is_ipv4(const QString& value) {
    const auto parts = value.split('.');
    if (parts.size() != 4) {
        return false;
    }
    for (const auto& part : parts) {
        bool ok = false;
        const int octet = part.toInt(&ok);
        if (!ok || octet < 0 || octet > 255) {
            return false;
        }
    }
    return true;
}

bool authorized_cidr(const QString& cidr) {
    const QString trimmed = cidr.trimmed();
    return trimmed == "192.168.50.0/24" || trimmed == "192.168.1.0/24";
}

bool authorized_ip(const QString& ip) {
    return is_ipv4(ip) && (ip.startsWith("192.168.50.") || ip.startsWith("192.168.1."));
}

std::uint32_t ip_key(const QString& ip) {
    std::uint32_t out = 0;
    for (const auto& part : ip.split('.')) {
        bool ok = false;
        const int value = part.toInt(&ok);
        out = (out << 8) | static_cast<std::uint32_t>(ok ? std::clamp(value, 0, 255) : 0);
    }
    return out;
}

void add_unique(QStringList& list, const QString& value) {
    if (!value.isEmpty() && !list.contains(value)) {
        list.push_back(value);
    }
}

QString extract_field(const QString& text, const QString& key) {
    const QString marker = key + "=";
    const int start = text.indexOf(marker);
    if (start < 0) {
        return {};
    }
    const int value_start = start + marker.size();
    int end = text.indexOf(';', value_start);
    if (end < 0) {
        end = text.size();
    }
    return text.mid(value_start, end - value_start).trimmed();
}

void set_item(QTableWidget* table, int row, int col, const QString& value) {
    auto* item = new QTableWidgetItem(value);
    item->setFlags(item->flags() ^ Qt::ItemIsEditable);
    table->setItem(row, col, item);
}

QString service_name(int port) {
    switch (port) {
    case 21: return "FTP";
    case 22: return "SSH";
    case 23: return "Telnet";
    case 53: return "DNS";
    case 80: return "HTTP";
    case 135: return "Windows RPC";
    case 139: return "NetBIOS";
    case 443: return "HTTPS";
    case 445: return "SMB";
    case 554: return "RTSP media/camera";
    case 1900: return "SSDP/UPnP";
    case 3389: return "Remote Desktop";
    case 5000: return "NAS/web app";
    case 8080: return "HTTP alternate";
    case 8443: return "HTTPS/admin alternate";
    case 8554: return "RTSP alternate";
    case 37777: return "Camera/NVR vendor port";
    default: return QString("TCP %1").arg(port);
    }
}

std::vector<int> preset_ports(const QString& preset, const QString& custom = {}) {
    if (preset == "Router") {
        return {22, 53, 80, 443, 1900, 5000, 8080, 8443};
    }
    if (preset == "Windows / SMB") {
        return {135, 139, 445, 3389, 5985, 5986};
    }
    if (preset == "IoT / Camera") {
        return {80, 443, 554, 8554, 5000, 8080, 8443, 37777};
    }
    if (preset == "Custom") {
        std::vector<int> ports;
        for (const auto& part : custom.split(',', Qt::SkipEmptyParts)) {
            bool ok = false;
            const int port = part.trimmed().toInt(&ok);
            if (ok && port > 0 && port <= 65535) {
                ports.push_back(port);
            }
        }
        if (!ports.empty()) {
            return ports;
        }
    }
    return {22, 53, 80, 135, 139, 443, 445, 554, 3389, 5000, 8080, 8443};
}

NetworkContext detect_context() {
    NetworkContext context;
    const auto adapters = netsentinel::engine::list_network_adapters(false);
    if (!adapters) {
        return context;
    }
    const auto& list = adapters.value();
    auto selected = list.end();
    for (auto it = list.begin(); it != list.end(); ++it) {
        if (!it->up || it->ipv4_addresses.empty()) {
            continue;
        }
        const QString ip = QString::fromStdString(it->ipv4_addresses.front());
        const QString gw = QString::fromStdString(it->gateway.value_or(""));
        if (ip.startsWith("192.168.50.") || gw.startsWith("192.168.50.")) {
            selected = it;
            break;
        }
        if (selected == list.end()) {
            selected = it;
        }
    }
    if (selected == list.end()) {
        return context;
    }
    context.adapter = QString::fromStdString(selected->friendly_name.value_or(selected->interface_name));
    context.local_ip = selected->ipv4_addresses.empty() ? QString{} : QString::fromStdString(selected->ipv4_addresses.front());
    context.gateway = QString::fromStdString(selected->gateway.value_or(""));
    QStringList dns;
    for (const auto& server : selected->dns_servers) {
        dns.push_back(QString::fromStdString(server));
    }
    context.dns = dns.join(", ");
    const auto proposal = netsentinel::engine::propose_scan_scope_from_adapter(*selected, 1024);
    if (proposal && authorized_cidr(QString::fromStdString(proposal.value().network_cidr))) {
        context.cidr = QString::fromStdString(proposal.value().network_cidr);
    } else if (context.local_ip.startsWith("192.168.1.")) {
        context.cidr = "192.168.1.0/24";
    }
    if (context.gateway.isEmpty()) {
        context.gateway = context.cidr.startsWith("192.168.1.") ? "192.168.1.1" : "192.168.50.1";
    }
    return context;
}

QString guess_type(const Device& device, const QString& gateway) {
    const QString text = QString("%1 %2 %3").arg(device.hostname, device.vendor, device.services.join(" ")).toLower();
    if (device.ip == gateway) return "Router";
    if (text.contains("nas") || text.contains("smb")) return "NAS / file server";
    if (text.contains("iphone") || text.contains("ipad") || text.contains("phone")) return "Mobile device";
    if (text.contains("camera") || text.contains("rtsp") || text.contains("vmc")) return "Camera / IoT";
    if (text.contains("dns") || text.contains("pihole")) return "DNS / network service";
    if (text.contains("laptop") || text.contains("desktop") || text.contains("pc")) return "Computer";
    return "Unknown";
}

QStringList findings_for(const Device& device, const QString& gateway) {
    QStringList findings;
    if (device.vendor == "Unknown vendor" && device.hostname == "-") {
        findings << "Unknown device identity. Confirm this device belongs on the network.";
    }
    if (device.ports.contains("23")) {
        findings << "High: Telnet is open. Disable or restrict Telnet.";
    }
    if (device.ports.contains("3389")) {
        findings << "High: Remote Desktop is open. Restrict to trusted devices.";
    }
    if (device.ports.contains("445") && device.ip != gateway) {
        findings << "Review: SMB is open. Expected for NAS/Windows shares, risky if unexpected.";
    }
    if (device.ports.contains("554") || device.ports.contains("8554") || device.ports.contains("37777")) {
        findings << "Review: camera/media service port detected. Confirm the device purpose.";
    }
    if (device.ip == gateway && (device.ports.contains("80") || device.ports.contains("443") || device.ports.contains("8443"))) {
        findings << "Info: router web/admin service detected. Keep firmware updated and admin access restricted.";
    }
    return findings;
}

QString severity(const Device& device) {
    for (const auto& finding : device.findings) {
        if (finding.startsWith("High:")) return "High";
        if (finding.startsWith("Review:")) return "Review";
    }
    return device.findings.empty() ? "OK" : "Info";
}

ScanData run_scan(const AppSettings& settings, const NetworkContext& fallback, const std::function<void(QString, int)>& progress) {
    ScanData data;
    data.context = detect_context();
    if (data.context.local_ip.isEmpty()) {
        data.context = fallback;
    }
    data.cidr = settings.cidr.trimmed();
    data.started_at = now_text();
    data.events << QString("%1  Scan started for %2").arg(data.started_at, data.cidr);
    if (!authorized_cidr(data.cidr)) {
        data.message = "Blocked: only 192.168.50.0/24 and 192.168.1.0/24 are authorized in this GUI.";
        return data;
    }
    if (!settings.arp) {
        data.message = "ARP discovery must be enabled for the current backend scan session.";
        return data;
    }
    if (progress) progress("Preparing authorized local scan", 5);

    netsentinel::engine::ScanProfile profile{};
    profile.profile_id = "gui-reset";
    profile.name = "GUI Network Scan";
    profile.scope.scope_id = "authorized-local";
    profile.scope.cidr_or_range = data.cidr.toStdString();
    profile.scope.local_only = true;
    profile.scope.authorized = true;
    profile.timeout_seconds = settings.timeout_seconds;
    profile.retries = 1;

    netsentinel::engine::ScanSessionRunOptions options{};
    options.mock_mode = false;
    options.max_concurrency = 8;
    options.max_qps = 32;
    options.enabled_probes = {"arp"};
    if (settings.icmp) options.enabled_probes.push_back("icmp");
    if (settings.tcp) options.enabled_probes.push_back("tcp");
    options.enabled_probes.push_back("netbios");
    options.enabled_probes.push_back("mdns");
    options.enabled_probes.push_back("ssdp");
    options.tcp_port_hints = preset_ports(settings.port_preset);
    options.on_progress = [&](const netsentinel::engine::ScanProgressEvent& event) {
        const int total = static_cast<int>(std::max<std::size_t>(event.stage_total, 1));
        const int index = static_cast<int>(std::min(event.stage_index, event.stage_total));
        int percent = std::clamp((index * 100) / total, 5, 98);
        if (event.kind == netsentinel::engine::ScanProgressKind::completed) percent = 100;
        const QString line = QString("%1 %2 %3")
            .arg(QString::fromStdString(event.stage), QString::fromStdString(event.target), QString::fromStdString(event.message)).trimmed();
        if (!line.isEmpty()) data.events << QString("%1  %2").arg(now_text(), line);
        if (progress) progress(line, percent);
    };

    netsentinel::engine::ScanDependencies deps{};
    netsentinel::engine::ScanCancellation cancel{};
    const auto session = netsentinel::engine::run_scan_session(profile, deps, cancel, options);
    if (!session) {
        data.message = QString("Scan failed: %1").arg(QString::fromStdString(session.error().user_message));
        return data;
    }

    std::map<QString, Device> devices;
    std::map<QString, QStringList> methods;
    std::map<QString, QStringList> details;
    const auto oui_result = netsentinel::engine::load_oui_catalog();
    const auto oui = oui_result ? oui_result.value() : std::vector<netsentinel::engine::OUIRecord>{};
    for (const auto& probe : session.value().probe_results) {
        const QString target = QString::fromStdString(probe.target);
        if (!is_ipv4(target)) continue;
        auto& dev = devices[target];
        dev.ip = target;
        dev.first_seen = data.started_at;
        dev.last_seen = now_text();
        if (target == data.context.gateway) dev.hostname = "Router / Gateway";
        const QString name = QString::fromStdString(probe.probe_name);
        const QString message = QString::fromStdString(probe.message);
        if (name == "arp") {
            add_unique(methods[target], "ARP");
            const QString mac = extract_field(message, "mac");
            if (!mac.isEmpty()) {
                dev.mac = mac;
                dev.vendor = QString::fromStdString(netsentinel::engine::lookup_vendor_by_mac(mac.toStdString(), oui));
            }
        } else if (name == "icmp" || name == "icmp-sweep") {
            if (probe.success) add_unique(methods[target], "ICMP");
        } else if (name.startsWith("tcp/")) {
            add_unique(methods[target], "TCP");
            bool ok = false;
            const int port = name.mid(4).toInt(&ok);
            if (ok && probe.success) {
                add_unique(dev.ports, QString::number(port));
                add_unique(dev.services, service_name(port));
                data.ports.push_back(PortRow{target, port, "TCP", "open", service_name(port), QString::number(probe.response_time_ms) + " ms"});
            }
        } else if (name == "netbios") {
            add_unique(methods[target], "NetBIOS");
            const QString nb = extract_field(message, "name");
            if (!nb.isEmpty()) dev.hostname = nb;
        }
        if (!message.isEmpty()) add_unique(details[target], QString("%1: %2").arg(name, message));
    }

    for (auto& pair : devices) {
        auto& dev = pair.second;
        dev.methods = methods[pair.first].join(", ");
        dev.details = details[pair.first].join("\n");
        dev.type = guess_type(dev, data.context.gateway);
        dev.findings = findings_for(dev, data.context.gateway);
        dev.events << QString("%1  First seen in current scan").arg(dev.first_seen);
        if (!dev.ports.empty()) dev.events << QString("%1  %2 open TCP port(s) observed").arg(dev.last_seen).arg(dev.ports.size());
        data.devices.push_back(dev);
    }
    std::sort(data.devices.begin(), data.devices.end(), [](const Device& a, const Device& b) { return ip_key(a.ip) < ip_key(b.ip); });
    data.ok = session.value().completed;
    data.finished_at = now_text();
    data.events << QString("%1  Scan finished: %2 devices, %3 open ports").arg(data.finished_at).arg(data.devices.size()).arg(data.ports.size());
    data.message = QString("Scan complete: %1 devices found, %2 open TCP ports.").arg(data.devices.size()).arg(data.ports.size());
    return data;
}

std::vector<PortRow> run_port_scan(QStringList targets, const QString& preset, const QString& custom_ports, QString* message) {
    QStringList clean;
    for (const auto& target : targets) {
        const QString ip = target.trimmed();
        if (authorized_ip(ip)) clean << ip;
    }
    if (clean.empty()) {
        if (message) *message = "No authorized local target selected.";
        return {};
    }
    netsentinel::diagnostics::PortScanConfig config{};
    config.mock_mode = false;
    config.concurrency = 8;
    config.banner = false;
    for (const auto& target : clean) config.targets.push_back(target.toStdString());
    const auto result = netsentinel::diagnostics::run_service_identification(config, preset.toLower().toStdString(), preset_ports(preset, custom_ports));
    if (message) *message = QString::fromStdString(result.message);
    std::vector<PortRow> rows;
    for (const auto& obs : result.observations) {
        rows.push_back(PortRow{
            QString::fromStdString(obs.target),
            obs.port,
            QString::fromStdString(obs.protocol.empty() ? "TCP" : obs.protocol),
            "open",
            QString::fromStdString(obs.service),
            QString("confidence %1%").arg(obs.confidence_percent)
        });
    }
    return rows;
}

QString write_report(const AppSettings& settings, const ScanData& scan, const std::optional<Device>& only_device = std::nullopt) {
    if (scan.devices.empty()) return {};
    QDir dir(settings.report_dir.isEmpty() ? "reports" : settings.report_dir);
    if (!dir.exists()) dir.mkpath(".");
    const QString stamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    const QString file_name = only_device ? QString("NetSentinel11-device-%1-%2.html").arg(only_device->ip, stamp) : QString("NetSentinel11-network-report-%1.html").arg(stamp);
    QFile file(dir.filePath(file_name));
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) return {};
    QTextStream out(&file);
    out << "<!doctype html><html><head><meta charset='utf-8'><title>NetSentinel11 Report</title>";
    out << "<style>body{font-family:Segoe UI,Arial;background:#0f172a;color:#e5edf8;padding:28px}table{border-collapse:collapse;width:100%;background:#111c2f}td,th{border:1px solid #263852;padding:8px;text-align:left}th{background:#1d3354}</style></head><body>";
    out << "<h1>NetSentinel11 " << (only_device ? "Device" : "Network") << " Report</h1>";
    out << "<p>Generated: " << now_text().toHtmlEscaped() << "</p>";
    out << "<p>Scope: " << scan.cidr.toHtmlEscaped() << " | Gateway: " << scan.context.gateway.toHtmlEscaped() << " | Adapter: " << scan.context.adapter.toHtmlEscaped() << "</p>";
    out << "<p>Real authorized-LAN scan data only. No exploit payloads, credential attacks, spoofing, MITM, deauth, stealth, or public-IP scanning.</p>";
    out << "<table><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>Type</th><th>Methods</th><th>Open ports</th><th>Findings</th></tr>";
    auto write_device_row = [&](const Device& d) {
        out << "<tr><td>" << d.ip.toHtmlEscaped() << "</td><td>" << d.mac.toHtmlEscaped() << "</td><td>" << d.hostname.toHtmlEscaped()
            << "</td><td>" << d.vendor.toHtmlEscaped() << "</td><td>" << d.type.toHtmlEscaped() << "</td><td>" << d.methods.toHtmlEscaped()
            << "</td><td>" << d.ports.join(", ").toHtmlEscaped() << "</td><td>" << d.findings.join("; ").toHtmlEscaped() << "</td></tr>";
    };
    if (only_device) write_device_row(*only_device); else for (const auto& d : scan.devices) write_device_row(d);
    out << "</table><h2>Port results</h2><table><tr><th>Target</th><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Note</th></tr>";
    for (const auto& p : scan.ports) {
        if (only_device && p.target != only_device->ip) continue;
        out << "<tr><td>" << p.target.toHtmlEscaped() << "</td><td>" << p.port << "</td><td>" << p.protocol.toHtmlEscaped() << "</td><td>" << p.state.toHtmlEscaped() << "</td><td>" << p.service.toHtmlEscaped() << "</td><td>" << p.note.toHtmlEscaped() << "</td></tr>";
    }
    out << "</table><h2>Events</h2><ul>";
    for (const auto& e : scan.events) out << "<li>" << e.toHtmlEscaped() << "</li>";
    out << "</ul></body></html>";
    return QDir::toNativeSeparators(QFileInfo(file).absoluteFilePath());
}

QString style_sheet(bool dark) {
    if (!dark) {
        return "QMainWindow,QWidget{background:#eef3f8;color:#142033;font-family:'Segoe UI Variable','Segoe UI';font-size:13px}"
               "#Sidebar{background:#0f1f33;border-radius:24px}#TopBar,#Card{background:#fff;border:1px solid #d7e2ee;border-radius:20px}"
               "#AppTitle{color:#fff;font-size:24px;font-weight:850}#Subtle{color:#8ea8c4}#PageTitle{font-size:28px;font-weight:850;color:#0f2745}"
               "#Metric{font-size:28px;font-weight:850;color:#1264cf}#CardTitle{color:#5f7187;font-weight:750}"
               "QPushButton{border:0;border-radius:13px;padding:10px 14px;background:#d9e7f5;color:#102033;font-weight:700}"
               "QPushButton:hover{background:#c7ddf3}QPushButton:pressed{background:#a8c9ee}QPushButton:disabled{background:#edf2f7;color:#8b9aad}"
               "QPushButton[role='primary']{background:#1264cf;color:white}QPushButton[nav='true']{background:transparent;color:#d7e7f8;text-align:left}"
               "QPushButton[active='true']{background:#2f80ed;color:white}"
               "QLineEdit,QComboBox,QSpinBox,QTextEdit,QListWidget,QTableWidget{background:white;color:#142033;border:1px solid #d7e2ee;border-radius:12px;padding:6px}"
               "QHeaderView::section{background:#e6eff8;color:#27384a;border:0;padding:8px;font-weight:800}QTableWidget::item:selected{background:#cde4ff;color:#07111f}"
               "QProgressBar{border:1px solid #d7e2ee;border-radius:8px;text-align:center;background:#edf4fb}QProgressBar::chunk{background:#1264cf;border-radius:8px}";
    }
    return "QMainWindow,QWidget{background:#07111f;color:#e5edf8;font-family:'Segoe UI Variable','Segoe UI';font-size:13px}"
           "#Sidebar{background:#0b1627;border:1px solid #15243a;border-radius:24px}#TopBar,#Card{background:#101c2f;border:1px solid #263852;border-radius:20px}"
           "#AppTitle{color:#fff;font-size:24px;font-weight:850}#Subtle{color:#8ea8c4}#PageTitle{font-size:28px;font-weight:850;color:#f8fbff}"
           "#Metric{font-size:28px;font-weight:850;color:#78b7ff}#CardTitle{color:#9fb2c8;font-weight:750}"
           "QPushButton{border:0;border-radius:13px;padding:10px 14px;background:#182a40;color:#eaf2fb;font-weight:700}"
           "QPushButton:hover{background:#223957}QPushButton:pressed{background:#315071}QPushButton:disabled{background:#111827;color:#64748b}"
           "QPushButton[role='primary']{background:#2f80ed;color:white}QPushButton[role='primary']:hover{background:#1f6fd1}"
           "QPushButton[nav='true']{background:transparent;color:#d7e7f8;text-align:left}QPushButton[active='true']{background:#1d4ed8;color:white}"
           "QLineEdit,QComboBox,QSpinBox,QTextEdit,QListWidget,QTableWidget{background:#0f1a29;color:#eaf2fb;border:1px solid #263852;border-radius:12px;padding:6px}"
           "QHeaderView::section{background:#17263a;color:#eaf2fb;border:0;padding:8px;font-weight:800}QTableWidget::item:selected{background:#1d4ed8;color:white}"
           "QProgressBar{border:1px solid #263852;border-radius:8px;text-align:center;background:#0f1a29;color:#e5edf8}QProgressBar::chunk{background:#2f80ed;border-radius:8px}";
}

QFrame* make_card(const QString& title, QLabel** metric = nullptr, const QString& detail = {}) {
    auto* frame = new QFrame();
    frame->setObjectName("Card");
    auto* box = new QVBoxLayout(frame);
    box->setContentsMargins(18, 16, 18, 16);
    auto* t = new QLabel(title);
    t->setObjectName("CardTitle");
    auto* m = new QLabel("-");
    m->setObjectName("Metric");
    auto* d = new QLabel(detail);
    d->setObjectName("Subtle");
    d->setWordWrap(true);
    box->addWidget(t);
    box->addWidget(m);
    box->addWidget(d);
    if (metric) *metric = m;
    return frame;
}

} // namespace

class ScannerWindow final : public QMainWindow {
public:
    explicit ScannerWindow(QWidget* parent = nullptr) : QMainWindow(parent) {
        setWindowTitle("NetSentinel11");
        resize(1480, 940);
        context_ = detect_context();
        load_settings();
        build();
        refresh_all();
        set_status("Ready. Click Scan Network.", 0);
    }

    void open_page_name(QString name) {
        name = name.toLower().remove(' ').remove('-');
        for (int i = 0; i < pages_.size(); ++i) {
            QString item = pages_[i].toLower().remove(' ').remove('-').remove('/');
            if (item.contains(name)) {
                set_page(i);
                return;
            }
        }
    }

    void trigger_scan() { start_scan(); }
    void trigger_port_scan() { start_selected_port_scan(); }
    void trigger_report() { generate_network_report(); }

private:
    AppSettings settings_;
    NetworkContext context_;
    ScanData scan_;
    QString selected_ip_;
    QString last_report_;

    QStackedWidget* stack_ = nullptr;
    QLabel* page_title_ = nullptr;
    QLabel* status_ = nullptr;
    QLabel* network_ = nullptr;
    QProgressBar* progress_ = nullptr;
    QStringList pages_;
    std::vector<QPushButton*> nav_;

    QLabel* adapter_ = nullptr;
    QLabel* local_ip_ = nullptr;
    QLabel* cidr_ = nullptr;
    QLabel* gateway_ = nullptr;
    QLabel* dns_ = nullptr;
    QLabel* devices_ = nullptr;
    QLabel* ports_ = nullptr;
    QLabel* findings_ = nullptr;
    QLabel* bandwidth_ = nullptr;
    QLabel* last_scan_ = nullptr;
    QListWidget* recent_ = nullptr;

    QLineEdit* dev_search_ = nullptr;
    QComboBox* dev_filter_ = nullptr;
    QTableWidget* dev_table_ = nullptr;
    QTextEdit* dev_detail_ = nullptr;
    QComboBox* port_target_ = nullptr;
    QLineEdit* custom_target_ = nullptr;
    QComboBox* port_preset_ = nullptr;
    QLineEdit* custom_ports_ = nullptr;
    QTableWidget* port_table_ = nullptr;
    QTableWidget* sec_table_ = nullptr;
    QLabel* sec_state_ = nullptr;
    QListWidget* events_ = nullptr;
    QComboBox* event_filter_ = nullptr;
    QTextEdit* bandwidth_text_ = nullptr;
    QTextEdit* router_text_ = nullptr;
    QTableWidget* wifi_table_ = nullptr;
    QTextEdit* reports_text_ = nullptr;
    QLineEdit* set_cidr_ = nullptr;
    QSpinBox* set_timeout_ = nullptr;
    QCheckBox* set_arp_ = nullptr;
    QCheckBox* set_icmp_ = nullptr;
    QCheckBox* set_tcp_ = nullptr;
    QComboBox* set_preset_ = nullptr;
    QLineEdit* set_report_ = nullptr;
    QCheckBox* set_dark_ = nullptr;

    QPushButton* button(const QString& text, const QString& role = {}) {
        auto* b = new QPushButton(text);
        if (!role.isEmpty()) b->setProperty("role", role);
        b->setCursor(Qt::PointingHandCursor);
        return b;
    }

    QLabel* text_label(const QString& text, const QString& object = {}) {
        auto* l = new QLabel(text);
        if (!object.isEmpty()) l->setObjectName(object);
        l->setWordWrap(true);
        return l;
    }

    void load_settings() {
        QSettings s("NetSentinel11", "NetSentinel11");
        settings_.cidr = s.value("scanner/cidr", context_.cidr).toString();
        if (!authorized_cidr(settings_.cidr)) settings_.cidr = context_.cidr;
        settings_.timeout_seconds = s.value("scanner/timeout", 4).toInt();
        settings_.arp = s.value("scanner/arp", true).toBool();
        settings_.icmp = s.value("scanner/icmp", true).toBool();
        settings_.tcp = s.value("scanner/tcp", true).toBool();
        settings_.port_preset = s.value("scanner/preset", "Common").toString();
        settings_.report_dir = s.value("reports/dir", "reports").toString();
        settings_.dark = s.value("ui/dark", true).toBool();
    }

    void save_settings() {
        if (set_cidr_) {
            settings_.cidr = set_cidr_->text().trimmed();
            settings_.timeout_seconds = set_timeout_->value();
            settings_.arp = set_arp_->isChecked();
            settings_.icmp = set_icmp_->isChecked();
            settings_.tcp = set_tcp_->isChecked();
            settings_.port_preset = set_preset_->currentText();
            settings_.report_dir = set_report_->text().trimmed();
            settings_.dark = set_dark_->isChecked();
        }
        QSettings s("NetSentinel11", "NetSentinel11");
        s.setValue("scanner/cidr", settings_.cidr);
        s.setValue("scanner/timeout", settings_.timeout_seconds);
        s.setValue("scanner/arp", settings_.arp);
        s.setValue("scanner/icmp", settings_.icmp);
        s.setValue("scanner/tcp", settings_.tcp);
        s.setValue("scanner/preset", settings_.port_preset);
        s.setValue("reports/dir", settings_.report_dir);
        s.setValue("ui/dark", settings_.dark);
        qApp->setStyleSheet(style_sheet(settings_.dark));
        set_status("Settings saved. They will load after restart.", 100);
        refresh_dashboard();
    }

    void build() {
        qApp->setStyleSheet(style_sheet(settings_.dark));
        auto* root = new QWidget(this);
        auto* main = new QHBoxLayout(root);
        main->setContentsMargins(18, 18, 18, 18);
        main->setSpacing(18);
        auto* side = new QFrame(root);
        side->setObjectName("Sidebar");
        side->setFixedWidth(250);
        auto* side_layout = new QVBoxLayout(side);
        side_layout->setContentsMargins(18, 20, 18, 20);
        side_layout->addWidget(text_label("NetSentinel11", "AppTitle"));
        side_layout->addWidget(text_label("Local network scanner", "Subtle"));
        side_layout->addSpacing(14);
        pages_ = {"Dashboard", "Devices", "Port Scanner", "Security", "Timeline / Events", "Bandwidth / Top Talkers", "Router / DNS / DHCP", "Wi-Fi", "Reports", "Settings"};
        for (int i = 0; i < pages_.size(); ++i) {
            auto* b = button(pages_[i]);
            b->setProperty("nav", true);
            connect(b, &QPushButton::clicked, this, [this, i]() { set_page(i); });
            side_layout->addWidget(b);
            nav_.push_back(b);
        }
        side_layout->addStretch();

        auto* content = new QWidget(root);
        auto* content_layout = new QVBoxLayout(content);
        content_layout->setContentsMargins(0, 0, 0, 0);
        auto* top = new QFrame(content);
        top->setObjectName("TopBar");
        auto* top_layout = new QHBoxLayout(top);
        page_title_ = text_label("Dashboard", "PageTitle");
        network_ = text_label("", "Subtle");
        status_ = text_label("Ready", "Subtle");
        progress_ = new QProgressBar();
        progress_->setRange(0, 100);
        progress_->setValue(0);
        progress_->setFixedWidth(220);
        auto* scan = button("Scan Network", "primary");
        connect(scan, &QPushButton::clicked, this, [this]() { start_scan(); });
        top_layout->addWidget(page_title_, 1);
        top_layout->addWidget(network_, 2);
        top_layout->addWidget(status_, 2);
        top_layout->addWidget(progress_);
        top_layout->addWidget(scan);

        stack_ = new QStackedWidget(content);
        stack_->addWidget(build_dashboard());
        stack_->addWidget(build_devices());
        stack_->addWidget(build_ports());
        stack_->addWidget(build_security());
        stack_->addWidget(build_events());
        stack_->addWidget(build_bandwidth());
        stack_->addWidget(build_router());
        stack_->addWidget(build_wifi());
        stack_->addWidget(build_reports());
        stack_->addWidget(build_settings());
        content_layout->addWidget(top);
        content_layout->addWidget(stack_, 1);
        main->addWidget(side);
        main->addWidget(content, 1);
        setCentralWidget(root);
        set_page(0);
    }

    QWidget* build_dashboard() {
        auto* page = new QWidget();
        auto* layout = new QVBoxLayout(page);
        layout->addWidget(text_label("Real scan first. No fake devices in normal mode.", "PageTitle"));
        auto* grid = new QGridLayout();
        grid->setSpacing(14);
        grid->addWidget(make_card("Adapter", &adapter_, "Active Windows network adapter."), 0, 0);
        grid->addWidget(make_card("Local IP", &local_ip_, "IPv4 used for local scope."), 0, 1);
        grid->addWidget(make_card("Authorized CIDR", &cidr_, "Editable in Settings."), 0, 2);
        grid->addWidget(make_card("Gateway", &gateway_, "Router target."), 0, 3);
        grid->addWidget(make_card("DNS", &dns_, "Windows adapter DNS servers."), 1, 0);
        grid->addWidget(make_card("Devices", &devices_, "Real scan result count."), 1, 1);
        grid->addWidget(make_card("Open ports", &ports_, "Safe TCP connect results."), 1, 2);
        grid->addWidget(make_card("Findings", &findings_, "Derived from current scan."), 1, 3);
        grid->addWidget(make_card("Bandwidth", &bandwidth_, "No fake traffic shown."), 2, 0);
        grid->addWidget(make_card("Last scan", &last_scan_, "Scan completion time."), 2, 1);
        layout->addLayout(grid);
        auto* row = new QHBoxLayout();
        auto* scan = button("Scan Network", "primary");
        auto* scan_ports = button("Scan Selected Device Ports");
        auto* report = button("Generate Network Report");
        connect(scan, &QPushButton::clicked, this, [this]() { start_scan(); });
        connect(scan_ports, &QPushButton::clicked, this, [this]() { start_selected_port_scan(); });
        connect(report, &QPushButton::clicked, this, [this]() { generate_network_report(); });
        row->addWidget(scan);
        row->addWidget(scan_ports);
        row->addWidget(report);
        row->addStretch();
        layout->addLayout(row);
        recent_ = new QListWidget();
        layout->addWidget(recent_, 1);
        return page;
    }

    QWidget* build_devices() {
        auto* page = new QWidget();
        auto* layout = new QVBoxLayout(page);
        auto* controls = new QHBoxLayout();
        dev_search_ = new QLineEdit();
        dev_search_->setPlaceholderText("Search devices...");
        dev_filter_ = new QComboBox();
        dev_filter_->addItems({"All", "With findings", "Open ports", "Unknown", "Router"});
        controls->addWidget(dev_search_, 2);
        controls->addWidget(dev_filter_);
        layout->addLayout(controls);
        auto* split = new QSplitter();
        dev_table_ = new QTableWidget(0, 11);
        dev_table_->setHorizontalHeaderLabels({"IP", "MAC", "Hostname", "Vendor", "Type", "State", "First seen", "Last seen", "Methods", "Open ports", "Risk"});
        dev_table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        dev_table_->verticalHeader()->setVisible(false);
        dev_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        dev_table_->setSelectionMode(QAbstractItemView::SingleSelection);
        split->addWidget(dev_table_);
        auto* detail_card = new QFrame();
        detail_card->setObjectName("Card");
        auto* dlay = new QVBoxLayout(detail_card);
        dlay->addWidget(text_label("Device detail", "CardTitle"));
        dev_detail_ = new QTextEdit();
        dev_detail_->setReadOnly(true);
        dlay->addWidget(dev_detail_, 1);
        auto* buttons = new QGridLayout();
        auto* scan_ports = button("Scan Ports", "primary");
        auto* report = button("Generate Device Report");
        auto* copy_ip = button("Copy IP");
        auto* copy_mac = button("Copy MAC");
        auto* open = button("Open Details");
        buttons->addWidget(scan_ports, 0, 0);
        buttons->addWidget(report, 0, 1);
        buttons->addWidget(copy_ip, 1, 0);
        buttons->addWidget(copy_mac, 1, 1);
        buttons->addWidget(open, 2, 0, 1, 2);
        dlay->addLayout(buttons);
        split->addWidget(detail_card);
        split->setStretchFactor(0, 3);
        split->setStretchFactor(1, 2);
        layout->addWidget(split, 1);
        connect(dev_search_, &QLineEdit::textChanged, this, [this]() { refresh_devices(); });
        connect(dev_filter_, &QComboBox::currentTextChanged, this, [this]() { refresh_devices(); });
        connect(dev_table_, &QTableWidget::itemSelectionChanged, this, [this]() { select_from_table(); });
        connect(scan_ports, &QPushButton::clicked, this, [this]() { start_selected_port_scan(); });
        connect(report, &QPushButton::clicked, this, [this]() { generate_device_report(); });
        connect(copy_ip, &QPushButton::clicked, this, [this]() { QApplication::clipboard()->setText(selected_ip_); set_status("Copied IP.", 100); });
        connect(copy_mac, &QPushButton::clicked, this, [this]() { if (auto d = selected_device()) QApplication::clipboard()->setText(d->mac); set_status("Copied MAC.", 100); });
        connect(open, &QPushButton::clicked, this, [this]() { set_page(1); refresh_detail(); });
        return page;
    }

    QWidget* build_ports() {
        auto* page = new QWidget();
        auto* layout = new QVBoxLayout(page);
        auto* controls = new QGridLayout();
        port_target_ = new QComboBox();
        port_target_->addItems({"Selected device", "Router / gateway", "All discovered devices", "Custom authorized local IP"});
        custom_target_ = new QLineEdit();
        custom_target_->setPlaceholderText("192.168.50.x or 192.168.1.x");
        port_preset_ = new QComboBox();
        port_preset_->addItems({"Common", "Router", "Windows / SMB", "IoT / Camera", "Custom"});
        custom_ports_ = new QLineEdit("22,53,80,443,445,554,3389,8080,8443");
        auto* timeout = new QSpinBox();
        timeout->setRange(1, 30);
        timeout->setValue(settings_.timeout_seconds);
        auto* start = button("Start Scan", "primary");
        auto* stop = button("Stop / Cancel");
        stop->setEnabled(false);
        stop->setToolTip("Current scans are bounded. Cancellable workers are a remaining improvement.");
        auto* export_button = button("Export Results");
        controls->addWidget(text_label("Target", "Subtle"), 0, 0);
        controls->addWidget(port_target_, 0, 1);
        controls->addWidget(custom_target_, 0, 2);
        controls->addWidget(text_label("Preset", "Subtle"), 1, 0);
        controls->addWidget(port_preset_, 1, 1);
        controls->addWidget(custom_ports_, 1, 2);
        controls->addWidget(text_label("Timeout", "Subtle"), 2, 0);
        controls->addWidget(timeout, 2, 1);
        controls->addWidget(start, 2, 2);
        controls->addWidget(stop, 2, 3);
        controls->addWidget(export_button, 2, 4);
        layout->addLayout(controls);
        port_table_ = new QTableWidget(0, 6);
        port_table_->setHorizontalHeaderLabels({"Target IP", "Port", "Protocol", "State", "Service guess", "Latency/source"});
        port_table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        port_table_->verticalHeader()->setVisible(false);
        layout->addWidget(port_table_, 1);
        connect(start, &QPushButton::clicked, this, [this]() { start_port_page_scan(); });
        connect(export_button, &QPushButton::clicked, this, [this]() { generate_network_report(); });
        return page;
    }

    QWidget* build_security() {
        auto* page = new QWidget();
        auto* layout = new QVBoxLayout(page);
        sec_state_ = text_label("No scan run yet. Click Scan Network.", "Subtle");
        sec_table_ = new QTableWidget(0, 5);
        sec_table_->setHorizontalHeaderLabels({"Severity", "Device", "IP", "Finding", "Recommendation"});
        sec_table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        sec_table_->verticalHeader()->setVisible(false);
        layout->addWidget(sec_state_);
        layout->addWidget(sec_table_, 1);
        return page;
    }

    QWidget* build_events() {
        auto* page = new QWidget();
        auto* layout = new QVBoxLayout(page);
        event_filter_ = new QComboBox();
        event_filter_->addItems({"All events", "Devices", "Security", "Scans", "Reports"});
        layout->addWidget(event_filter_, 0, Qt::AlignLeft);
        events_ = new QListWidget();
        layout->addWidget(events_, 1);
        connect(event_filter_, &QComboBox::currentTextChanged, this, [this]() { refresh_events(); });
        return page;
    }

    QWidget* build_bandwidth() {
        auto* page = new QWidget();
        auto* layout = new QVBoxLayout(page);
        bandwidth_text_ = new QTextEdit();
        bandwidth_text_->setReadOnly(true);
        layout->addWidget(bandwidth_text_, 1);
        return page;
    }

    QWidget* build_router() {
        auto* page = new QWidget();
        auto* layout = new QVBoxLayout(page);
        auto* row = new QHBoxLayout();
        auto* scan_router = button("Scan Router", "primary");
        auto* dns = button("Run DNS Benchmark");
        auto* dhcp = button("Run DHCP Discovery");
        row->addWidget(scan_router);
        row->addWidget(dns);
        row->addWidget(dhcp);
        row->addStretch();
        router_text_ = new QTextEdit();
        router_text_->setReadOnly(true);
        layout->addLayout(row);
        layout->addWidget(router_text_, 1);
        connect(scan_router, &QPushButton::clicked, this, [this]() { set_page(2); port_target_->setCurrentText("Router / gateway"); start_port_page_scan(); });
        connect(dhcp, &QPushButton::clicked, this, [this]() { run_dhcp(); });
        connect(dns, &QPushButton::clicked, this, [this]() { run_dns(); });
        return page;
    }

    QWidget* build_wifi() {
        auto* page = new QWidget();
        auto* layout = new QVBoxLayout(page);
        auto* scan = button("Scan Nearby Wi-Fi", "primary");
        wifi_table_ = new QTableWidget(0, 7);
        wifi_table_->setHorizontalHeaderLabels({"SSID", "BSSID", "Channel", "Band", "Signal", "Security", "Connected"});
        wifi_table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        wifi_table_->verticalHeader()->setVisible(false);
        layout->addWidget(scan, 0, Qt::AlignLeft);
        layout->addWidget(wifi_table_, 1);
        connect(scan, &QPushButton::clicked, this, [this]() { run_wifi(); });
        return page;
    }

    QWidget* build_reports() {
        auto* page = new QWidget();
        auto* layout = new QVBoxLayout(page);
        auto* row = new QHBoxLayout();
        auto* network = button("Generate Network Report", "primary");
        auto* device = button("Generate Device Report");
        auto* folder = button("Choose Report Folder");
        auto* open = button("Open Last Report");
        row->addWidget(network);
        row->addWidget(device);
        row->addWidget(folder);
        row->addWidget(open);
        row->addStretch();
        reports_text_ = new QTextEdit();
        reports_text_->setReadOnly(true);
        layout->addLayout(row);
        layout->addWidget(reports_text_, 1);
        connect(network, &QPushButton::clicked, this, [this]() { generate_network_report(); });
        connect(device, &QPushButton::clicked, this, [this]() { generate_device_report(); });
        connect(folder, &QPushButton::clicked, this, [this]() {
            const QString dir = QFileDialog::getExistingDirectory(this, "Choose report folder", settings_.report_dir);
            if (!dir.isEmpty()) {
                settings_.report_dir = dir;
                if (set_report_) set_report_->setText(dir);
                save_settings();
            }
        });
        connect(open, &QPushButton::clicked, this, [this]() { if (!last_report_.isEmpty()) QDesktopServices::openUrl(QUrl::fromLocalFile(last_report_)); });
        return page;
    }

    QWidget* build_settings() {
        auto* page = new QWidget();
        auto* layout = new QGridLayout(page);
        set_cidr_ = new QLineEdit(settings_.cidr);
        set_timeout_ = new QSpinBox();
        set_timeout_->setRange(1, 30);
        set_timeout_->setValue(settings_.timeout_seconds);
        set_arp_ = new QCheckBox("Enable ARP discovery");
        set_arp_->setChecked(settings_.arp);
        set_icmp_ = new QCheckBox("Enable ICMP discovery");
        set_icmp_->setChecked(settings_.icmp);
        set_tcp_ = new QCheckBox("Enable TCP liveness discovery");
        set_tcp_->setChecked(settings_.tcp);
        set_preset_ = new QComboBox();
        set_preset_->addItems({"Common", "Router", "Windows / SMB", "IoT / Camera", "Custom"});
        set_preset_->setCurrentText(settings_.port_preset);
        set_report_ = new QLineEdit(settings_.report_dir);
        set_dark_ = new QCheckBox("Dark mode");
        set_dark_->setChecked(settings_.dark);
        auto* save = button("Save Settings", "primary");
        layout->addWidget(text_label("Authorized CIDR", "Subtle"), 0, 0);
        layout->addWidget(set_cidr_, 0, 1);
        layout->addWidget(text_label("Timeout seconds", "Subtle"), 1, 0);
        layout->addWidget(set_timeout_, 1, 1);
        layout->addWidget(set_arp_, 2, 1);
        layout->addWidget(set_icmp_, 3, 1);
        layout->addWidget(set_tcp_, 4, 1);
        layout->addWidget(text_label("Default port preset", "Subtle"), 5, 0);
        layout->addWidget(set_preset_, 5, 1);
        layout->addWidget(text_label("Report output folder", "Subtle"), 6, 0);
        layout->addWidget(set_report_, 6, 1);
        layout->addWidget(set_dark_, 7, 1);
        layout->addWidget(save, 8, 1);
        layout->addWidget(text_label("Safe limits: normal GUI mode only permits 192.168.50.0/24 and 192.168.1.0/24. Public scanning, exploits, brute force, MITM, spoofing, deauth, and stealth behavior are not implemented.", "Subtle"), 9, 0, 1, 2);
        layout->setRowStretch(10, 1);
        connect(save, &QPushButton::clicked, this, [this]() { save_settings(); });
        return page;
    }

    void set_page(int index) {
        stack_->setCurrentIndex(index);
        page_title_->setText(pages_[index]);
        setWindowTitle("NetSentinel11 - " + pages_[index]);
        for (int i = 0; i < static_cast<int>(nav_.size()); ++i) {
            nav_[i]->setProperty("active", i == index);
            nav_[i]->style()->unpolish(nav_[i]);
            nav_[i]->style()->polish(nav_[i]);
        }
    }

    void set_status(const QString& text, int percent) {
        status_->setText(text);
        progress_->setValue(std::clamp(percent, 0, 100));
    }

    void refresh_all() {
        refresh_dashboard();
        refresh_devices();
        refresh_ports();
        refresh_security();
        refresh_events();
        refresh_bandwidth();
        refresh_router();
        refresh_reports();
    }

    void refresh_dashboard() {
        network_->setText(QString("%1 | %2 | gateway %3").arg(context_.adapter, settings_.cidr, context_.gateway));
        adapter_->setText(context_.adapter);
        local_ip_->setText(context_.local_ip.isEmpty() ? "Unknown" : context_.local_ip);
        cidr_->setText(settings_.cidr);
        gateway_->setText(context_.gateway);
        dns_->setText(context_.dns.isEmpty() ? "Unknown" : context_.dns);
        devices_->setText(QString::number(scan_.devices.size()));
        ports_->setText(QString::number(scan_.ports.size()));
        int finding_count = 0;
        for (const auto& d : scan_.devices) finding_count += d.findings.size();
        findings_->setText(QString::number(finding_count));
        bandwidth_->setText("Not configured");
        last_scan_->setText(scan_.finished_at.isEmpty() ? "Never" : scan_.finished_at);
        recent_->clear();
        const qsizetype start = std::max<qsizetype>(0, scan_.events.size() - 8);
        for (qsizetype i = start; i < scan_.events.size(); ++i) recent_->addItem(scan_.events[i]);
        if (recent_->count() == 0) recent_->addItem("No scan run yet. Click Scan Network.");
    }

    std::optional<Device> selected_device() const {
        for (const auto& d : scan_.devices) {
            if (d.ip == selected_ip_) return d;
        }
        return std::nullopt;
    }

    void refresh_devices() {
        if (!dev_table_) return;
        const QString search = dev_search_ ? dev_search_->text().toLower().trimmed() : QString{};
        const QString filter = dev_filter_ ? dev_filter_->currentText() : "All";
        dev_table_->setRowCount(0);
        int row = 0;
        for (const auto& d : scan_.devices) {
            const QString hay = QString("%1 %2 %3 %4 %5 %6").arg(d.ip, d.mac, d.hostname, d.vendor, d.type, d.services.join(" ")).toLower();
            if (!search.isEmpty() && !hay.contains(search)) continue;
            if (filter == "With findings" && d.findings.empty()) continue;
            if (filter == "Open ports" && d.ports.empty()) continue;
            if (filter == "Unknown" && d.type != "Unknown" && d.vendor != "Unknown vendor") continue;
            if (filter == "Router" && d.type != "Router") continue;
            dev_table_->insertRow(row);
            set_item(dev_table_, row, 0, d.ip);
            set_item(dev_table_, row, 1, d.mac);
            set_item(dev_table_, row, 2, d.hostname);
            set_item(dev_table_, row, 3, d.vendor);
            set_item(dev_table_, row, 4, d.type);
            set_item(dev_table_, row, 5, d.state);
            set_item(dev_table_, row, 6, d.first_seen);
            set_item(dev_table_, row, 7, d.last_seen);
            set_item(dev_table_, row, 8, d.methods);
            set_item(dev_table_, row, 9, QString::number(d.ports.size()));
            set_item(dev_table_, row, 10, severity(d));
            ++row;
        }
        if (row > 0 && selected_ip_.isEmpty()) dev_table_->selectRow(0);
        refresh_detail();
    }

    void select_from_table() {
        const int row = dev_table_->currentRow();
        if (row >= 0 && dev_table_->item(row, 0)) selected_ip_ = dev_table_->item(row, 0)->text();
        refresh_detail();
    }

    void refresh_detail() {
        if (!dev_detail_) return;
        const auto d = selected_device();
        if (!d) {
            dev_detail_->setPlainText("No device selected. Run Scan Network and select a device.");
            return;
        }
        dev_detail_->setPlainText(QString(
            "IP: %1\nMAC: %2\nHostname: %3\nVendor: %4\nType: %5\nState: %6\nFirst seen: %7\nLast seen: %8\nMethods: %9\nOpen ports: %10\nServices: %11\n\nSecurity findings:\n%12\n\nEvents:\n%13\n\nObservations:\n%14")
            .arg(d->ip, d->mac, d->hostname, d->vendor, d->type, d->state, d->first_seen, d->last_seen, d->methods, d->ports.join(", "), d->services.join(", "),
                 d->findings.empty() ? "No findings from current scan." : d->findings.join("\n"),
                 d->events.join("\n"), d->details));
    }

    void refresh_ports() {
        if (!port_table_) return;
        port_table_->setRowCount(static_cast<int>(scan_.ports.size()));
        for (int row = 0; row < static_cast<int>(scan_.ports.size()); ++row) {
            const auto& p = scan_.ports[static_cast<std::size_t>(row)];
            set_item(port_table_, row, 0, p.target);
            set_item(port_table_, row, 1, QString::number(p.port));
            set_item(port_table_, row, 2, p.protocol);
            set_item(port_table_, row, 3, p.state);
            set_item(port_table_, row, 4, p.service);
            set_item(port_table_, row, 5, p.note);
        }
    }

    void refresh_security() {
        if (!sec_table_) return;
        sec_table_->setRowCount(0);
        int row = 0;
        for (const auto& d : scan_.devices) {
            for (const auto& finding : d.findings) {
                sec_table_->insertRow(row);
                set_item(sec_table_, row, 0, severity(d));
                set_item(sec_table_, row, 1, d.hostname);
                set_item(sec_table_, row, 2, d.ip);
                set_item(sec_table_, row, 3, finding);
                set_item(sec_table_, row, 4, "Confirm expected services. Restrict, disable, or patch unexpected exposure.");
                ++row;
            }
        }
        sec_state_->setText(row == 0 ? (scan_.devices.empty() ? "No scan run yet. Click Scan Network." : "No findings from current scan.") : QString("%1 finding(s) from current scan.").arg(row));
    }

    void refresh_events() {
        if (!events_) return;
        events_->clear();
        const QString filter = event_filter_ ? event_filter_->currentText() : "All events";
        QStringList all = scan_.events;
        for (const auto& d : scan_.devices) {
            for (const auto& e : d.events) all << QString("%1  Device %2  %3").arg(now_text(), d.ip, e);
            for (const auto& f : d.findings) all << QString("%1  Security %2  %3").arg(now_text(), d.ip, f);
        }
        for (const auto& e : all) {
            if (filter == "Devices" && !e.contains("Device", Qt::CaseInsensitive)) continue;
            if (filter == "Security" && !e.contains("Security", Qt::CaseInsensitive)) continue;
            if (filter == "Scans" && !e.contains("Scan", Qt::CaseInsensitive)) continue;
            if (filter == "Reports" && !e.contains("Report", Qt::CaseInsensitive)) continue;
            events_->addItem(e);
        }
        if (events_->count() == 0) events_->addItem("No events yet.");
    }

    void refresh_bandwidth() {
        if (!bandwidth_text_) return;
        bandwidth_text_->setPlainText("Bandwidth data source not configured.\n\nNo fake traffic is shown. Configure a safe source such as router SNMP/UPnP counters, NetFlow/sFlow/IPFIX, Npcap-visible traffic, or an explicit agent before top-talkers can be displayed.");
    }

    void refresh_router() {
        if (!router_text_) return;
        router_text_->setPlainText(QString("Gateway/router IP: %1\nAdapter: %2\nLocal IP: %3\nAuthorized CIDR: %4\nDNS servers: %5\n\nButtons:\n- Scan Router: safe TCP service identification against gateway.\n- Run DHCP Discovery: Windows adapter-table DHCP discovery.\n- Run DNS Benchmark: bounded local resolver benchmark.")
            .arg(context_.gateway, context_.adapter, context_.local_ip, settings_.cidr, context_.dns.isEmpty() ? "Unknown" : context_.dns));
    }

    void refresh_reports() {
        if (!reports_text_) return;
        reports_text_->setPlainText(QString("Report folder: %1\nLast report: %2\n\nReports use current real scan data. Run Scan Network first.").arg(settings_.report_dir, last_report_.isEmpty() ? "None" : last_report_));
    }

    QStringList port_targets() const {
        const QString mode = port_target_->currentText();
        if (mode == "Router / gateway") return {context_.gateway};
        if (mode == "All discovered devices") {
            QStringList out;
            for (const auto& d : scan_.devices) out << d.ip;
            return out;
        }
        if (mode == "Custom authorized local IP") return {custom_target_->text().trimmed()};
        if (!selected_ip_.isEmpty()) return {selected_ip_};
        return scan_.devices.empty() ? QStringList{} : QStringList{scan_.devices.front().ip};
    }

    void start_scan() {
        save_settings();
        set_status("Starting real authorized LAN scan...", 2);
        auto settings = settings_;
        auto context = context_;
        auto* thread = QThread::create([this, settings, context]() {
            auto data = run_scan(settings, context, [this](const QString& line, int percent) {
                QMetaObject::invokeMethod(this, [this, line, percent]() { set_status(line, percent); }, Qt::QueuedConnection);
            });
            QMetaObject::invokeMethod(this, [this, data]() {
                scan_ = data;
                context_ = data.context;
                selected_ip_.clear();
                refresh_all();
                set_status(data.message, data.ok ? 100 : 0);
                if (!data.devices.empty()) {
                    set_page(1);
                    dev_table_->selectRow(0);
                }
            }, Qt::QueuedConnection);
        });
        connect(thread, &QThread::finished, thread, &QObject::deleteLater);
        thread->start();
    }

    void start_port_page_scan() {
        const QStringList targets = port_targets();
        const QString preset = port_preset_->currentText();
        const QString custom = custom_ports_->text();
        set_status("Starting safe TCP port scan...", 10);
        auto* thread = QThread::create([this, targets, preset, custom]() {
            QString message;
            auto rows = run_port_scan(targets, preset, custom, &message);
            QMetaObject::invokeMethod(this, [this, rows, message]() {
                for (const auto& row : rows) {
                    scan_.ports.push_back(row);
                    for (auto& d : scan_.devices) {
                        if (d.ip == row.target) {
                            add_unique(d.ports, QString::number(row.port));
                            add_unique(d.services, row.service);
                            d.type = guess_type(d, context_.gateway);
                            d.findings = findings_for(d, context_.gateway);
                            d.events << QString("%1  Port scan observed TCP/%2 %3").arg(now_text()).arg(row.port).arg(row.service);
                        }
                    }
                }
                scan_.events << QString("%1  Port scan finished: %2 open service observation(s)").arg(now_text()).arg(rows.size());
                refresh_all();
                set_status(rows.empty() ? message : QString("Port scan complete: %1 open service observation(s).").arg(rows.size()), 100);
            }, Qt::QueuedConnection);
        });
        connect(thread, &QThread::finished, thread, &QObject::deleteLater);
        thread->start();
    }

    void start_selected_port_scan() {
        if (selected_ip_.isEmpty() && !scan_.devices.empty()) selected_ip_ = scan_.devices.front().ip;
        if (selected_ip_.isEmpty()) {
            set_status("No device selected. Run Scan Network first.", 0);
            return;
        }
        set_page(2);
        port_target_->setCurrentText("Selected device");
        start_port_page_scan();
    }

    void generate_network_report() {
        last_report_ = write_report(settings_, scan_);
        if (last_report_.isEmpty()) {
            set_status("No real scan data to report yet, or report folder is not writable.", 0);
            return;
        }
        scan_.events << QString("%1  Report generated: %2").arg(now_text(), last_report_);
        refresh_reports();
        refresh_events();
        set_status("Network report generated: " + last_report_, 100);
    }

    void generate_device_report() {
        auto d = selected_device();
        if (!d) {
            set_status("No device selected for device report.", 0);
            return;
        }
        last_report_ = write_report(settings_, scan_, d);
        if (last_report_.isEmpty()) {
            set_status("Device report failed.", 0);
            return;
        }
        scan_.events << QString("%1  Device report generated for %2").arg(now_text(), d->ip);
        refresh_reports();
        refresh_events();
        set_status("Device report generated: " + last_report_, 100);
    }

    void run_dhcp() {
        netsentinel::diagnostics::DhcpDiscoveryConfig cfg{};
        cfg.mock_mode = false;
        cfg.allow_multiple_reply_check = true;
        const auto result = netsentinel::diagnostics::run_dhcp_discovery(cfg);
        QStringList lines;
        lines << "DHCP discovery:" << QString::fromStdString(result.message) << QString::fromStdString(result.limitations);
        for (const auto& adapter : result.adapters) {
            lines << QString("%1 | DHCP %2 | server %3 | %4").arg(QString::fromStdString(adapter.interface_name)).arg(adapter.dhcp_enabled ? "enabled" : "disabled").arg(QString::fromStdString(adapter.selected_server), QString::fromStdString(adapter.message));
        }
        router_text_->setPlainText(lines.join("\n"));
        scan_.events << QString("%1  DHCP discovery completed").arg(now_text());
        refresh_events();
    }

    void run_dns() {
        netsentinel::diagnostics::DnsBenchmarkConfig cfg{};
        cfg.mock_mode = false;
        for (const auto& server : context_.dns.split(',', Qt::SkipEmptyParts)) cfg.resolvers.push_back(server.trimmed().toStdString());
        if (cfg.resolvers.empty()) cfg.resolvers.push_back(context_.gateway.toStdString());
        cfg.queries = {"localhost"};
        cfg.samples = 2;
        cfg.timeout_ms = 800;
        const auto result = netsentinel::diagnostics::run_dns_benchmark(cfg);
        QStringList lines;
        lines << "DNS benchmark:" << QString::fromStdString(result.message);
        for (const auto& row : result.results) {
            lines << QString("%1 | avg %2 ms | failure %3 | %4").arg(QString::fromStdString(row.resolver)).arg(row.avg_latency_ms).arg(row.failure_rate).arg(QString::fromStdString(row.recommendation));
        }
        router_text_->setPlainText(lines.join("\n"));
        scan_.events << QString("%1  DNS benchmark completed").arg(now_text());
        refresh_events();
    }

    void run_wifi() {
        set_status("Scanning nearby Wi-Fi networks...", 10);
        auto* thread = QThread::create([this]() {
            netsentinel::diagnostics::WifiScanConfig cfg{};
            cfg.mock_mode = false;
            cfg.include_hidden = true;
            const auto result = netsentinel::diagnostics::run_wifi_scan(cfg);
            QMetaObject::invokeMethod(this, [this, result]() {
                wifi_table_->setRowCount(static_cast<int>(result.networks.size()));
                for (int row = 0; row < static_cast<int>(result.networks.size()); ++row) {
                    const auto& n = result.networks[static_cast<std::size_t>(row)];
                    set_item(wifi_table_, row, 0, QString::fromStdString(n.ssid));
                    set_item(wifi_table_, row, 1, QString::fromStdString(n.bssid));
                    set_item(wifi_table_, row, 2, QString::number(n.channel));
                    set_item(wifi_table_, row, 3, QString::fromStdString(n.band));
                    set_item(wifi_table_, row, 4, QString::number(n.signal_quality) + "%");
                    set_item(wifi_table_, row, 5, QString::fromStdString(n.auth + "/" + n.cipher));
                    set_item(wifi_table_, row, 6, n.connected ? "yes" : "no");
                }
                set_status(QString::fromStdString(result.message), result.success ? 100 : 0);
            }, Qt::QueuedConnection);
        });
        connect(thread, &QThread::finished, thread, &QObject::deleteLater);
        thread->start();
    }
};

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    app.setOrganizationName("NetSentinel11");
    app.setApplicationName("NetSentinel11");
    QCommandLineParser parser;
    parser.setApplicationDescription("NetSentinel11 professional Windows network scanner GUI");
    parser.addHelpOption();
    QCommandLineOption screenshot_option("screenshot", "Render GUI screenshot and exit.", "path");
    QCommandLineOption view_option("view", "Open page by name.", "name");
    QCommandLineOption autoscan_option("auto-scan", "Run Scan Network after launch for validation.");
    QCommandLineOption autoport_option("auto-port-scan", "Run selected-device port scan after auto-scan for validation.");
    QCommandLineOption autoreport_option("auto-report", "Generate a network report after auto-scan for validation.");
    parser.addOption(screenshot_option);
    parser.addOption(view_option);
    parser.addOption(autoscan_option);
    parser.addOption(autoport_option);
    parser.addOption(autoreport_option);
    parser.process(app);

    ScannerWindow window;
    if (!parser.value(view_option).isEmpty()) {
        window.open_page_name(parser.value(view_option));
    }
    const QString screenshot = parser.value(screenshot_option);
    if (!screenshot.isEmpty()) {
        window.resize(1480, 940);
        window.show();
        if (parser.isSet(autoscan_option)) {
            QTimer::singleShot(250, &window, [&window]() { window.trigger_scan(); });
            if (parser.isSet(autoport_option)) {
                QTimer::singleShot(39000, &window, [&window]() { window.trigger_port_scan(); });
            }
            if (parser.isSet(autoreport_option)) {
                QTimer::singleShot(parser.isSet(autoport_option) ? 50000 : 38000, &window, [&window]() { window.trigger_report(); });
            }
            QTimer::singleShot(parser.isSet(autoport_option) ? 62000 : 46000, &app, [&app, &window, screenshot]() {
                const QPixmap pixmap = window.grab();
                app.exit(!pixmap.isNull() && pixmap.save(screenshot, "PNG") ? 0 : 1);
            });
        } else {
            QTimer::singleShot(300, &app, [&app, &window, screenshot]() {
                const QPixmap pixmap = window.grab();
                app.exit(!pixmap.isNull() && pixmap.save(screenshot, "PNG") ? 0 : 1);
            });
        }
        return app.exec();
    }
    window.show();
    if (parser.isSet(autoscan_option)) {
        QTimer::singleShot(300, &window, [&window]() { window.trigger_scan(); });
        if (parser.isSet(autoport_option)) {
            QTimer::singleShot(39000, &window, [&window]() { window.trigger_port_scan(); });
        }
        if (parser.isSet(autoreport_option)) {
            QTimer::singleShot(parser.isSet(autoport_option) ? 50000 : 38000, &window, [&window]() { window.trigger_report(); });
        }
    }
    return app.exec();
}
