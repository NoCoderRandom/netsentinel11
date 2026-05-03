#include "netsentinel/ui/gui_shell.h"
#include "netsentinel/diagnostics/diagnostic_tools.h"

#include <QApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QListWidget>
#include <QMainWindow>
#include <QPixmap>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

namespace {

void apply_brand_visibility_guard(QWidget& root) {
    const QString brand_style = QStringLiteral(
        "QLabel {"
        " color: #f8fafc;"
        " background: #0f172a;"
        " border: 1px solid rgba(148, 163, 184, 0.34);"
        " border-radius: 14px;"
        " padding: 8px 12px;"
        " font-weight: 800;"
        " letter-spacing: 0.3px;"
        "}"
    );
    const QString parent_style = QStringLiteral(
        "background: #0b1220;"
        "color: #f8fafc;"
    );

    const auto labels = root.findChildren<QLabel*>();
    for (QLabel* label : labels) {
        if (!label) {
            continue;
        }
        const QString text = label->text();
        if (text.contains(QStringLiteral("NetSentinel"), Qt::CaseInsensitive) ||
            text.contains(QStringLiteral("Net Sentinel"), Qt::CaseInsensitive) ||
            text.contains(QStringLiteral("Sentinel"), Qt::CaseInsensitive)) {
            label->setStyleSheet(brand_style);
            label->setMinimumHeight(44);
            label->setAutoFillBackground(true);
            if (QWidget* parent = label->parentWidget()) {
                parent->setStyleSheet(parent->styleSheet() + parent_style);
                parent->setAutoFillBackground(true);
            }
        }
    }
}


QString light_stylesheet() {
    return QStringLiteral(R"(
        QMainWindow, QWidget { background: #eef3f8; color: #182231; font-family: "Segoe UI Variable", "Segoe UI"; }
        #NavRail { background: #0f1f33; border-radius: 22px; }
        #AppTitle { color: #f8fbff; font-size: 24px; font-weight: 800; }
        #AppSubtitle { color: #a9bdd4; font-size: 12px; }
        QPushButton { border: 0; border-radius: 14px; padding: 11px 14px; background: #d9e7f5; color: #102033; font-weight: 650; text-align: left; }
        QPushButton:hover { background: #c7ddf3; }
        QPushButton#PrimaryButton { background: #1264cf; color: white; text-align: center; }
        QPushButton#NavButton { background: transparent; color: #d7e7f8; text-align: left; }
        QPushButton#NavButton:hover { background: #1e3958; }
        QFrame#Card { background: rgba(255,255,255,0.92); border: 1px solid #d9e4ef; border-radius: 20px; }
        QLabel#Hero { color: #0f2745; font-size: 34px; font-weight: 850; }
        QLabel#SectionTitle { color: #12263e; font-size: 20px; font-weight: 800; }
        QLabel#Metric { color: #0d5db8; font-size: 30px; font-weight: 850; }
        QLabel#Muted { color: #5f7187; }
        QTableWidget { background: white; border: 1px solid #d7e2ee; border-radius: 14px; gridline-color: #edf2f7; selection-background-color: #cde4ff; }
        QHeaderView::section { background: #e6eff8; color: #27384a; border: 0; padding: 8px; font-weight: 700; }
        QTextEdit { background: white; border: 1px solid #d7e2ee; border-radius: 14px; padding: 10px; }
    )");
}

QString dark_stylesheet() {
    return QStringLiteral(R"(
        QMainWindow, QWidget { background: #0b111b; color: #eaf2fb; font-family: "Segoe UI Variable", "Segoe UI"; }
        #NavRail { background: #07101d; border-radius: 22px; }
        #AppTitle { color: #f8fbff; font-size: 24px; font-weight: 800; }
        #AppSubtitle { color: #8ea8c4; font-size: 12px; }
        QPushButton { border: 0; border-radius: 14px; padding: 11px 14px; background: #182a40; color: #eaf2fb; font-weight: 650; text-align: left; }
        QPushButton:hover { background: #223957; }
        QPushButton#PrimaryButton { background: #2f80ed; color: white; text-align: center; }
        QPushButton#NavButton { background: transparent; color: #d7e7f8; text-align: left; }
        QPushButton#NavButton:hover { background: #152943; }
        QFrame#Card { background: #101c2c; border: 1px solid #263a52; border-radius: 20px; }
        QLabel#Hero { color: #f7fbff; font-size: 34px; font-weight: 850; }
        QLabel#SectionTitle { color: #f0f6ff; font-size: 20px; font-weight: 800; }
        QLabel#Metric { color: #78b7ff; font-size: 30px; font-weight: 850; }
        QLabel#Muted { color: #9fb2c8; }
        QTableWidget { background: #0f1a29; color: #eaf2fb; border: 1px solid #263a52; border-radius: 14px; gridline-color: #20334a; selection-background-color: #244a78; }
        QHeaderView::section { background: #17263a; color: #eaf2fb; border: 0; padding: 8px; font-weight: 700; }
        QTextEdit { background: #0f1a29; color: #eaf2fb; border: 1px solid #263a52; border-radius: 14px; padding: 10px; }
    )");
}

QFrame* make_card(const QString& title, const QString& metric, const QString& detail) {
    auto* card = new QFrame();
    card->setObjectName("Card");
    auto* layout = new QVBoxLayout(card);
    layout->setContentsMargins(18, 16, 18, 16);
    auto* title_label = new QLabel(title);
    title_label->setObjectName("Muted");
    auto* metric_label = new QLabel(metric);
    metric_label->setObjectName("Metric");
    auto* detail_label = new QLabel(detail);
    detail_label->setObjectName("Muted");
    detail_label->setWordWrap(true);
    layout->addWidget(title_label);
    layout->addWidget(metric_label);
    layout->addWidget(detail_label);
    return card;
}

QFrame* make_severity_card(const QString& title, const QString& severity, const QString& detail, const QString& color) {
    auto* card = make_card(title, severity, detail);
    card->setStyleSheet(QStringLiteral("QFrame#Card { border-left: 7px solid %1; }").arg(color));
    return card;
}

QWidget* scroll_page(QWidget* content) {
    auto* scroll = new QScrollArea();
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setWidget(content);
    return scroll;
}

void set_table_item(QTableWidget* table, int row, int column, const QString& value) {
    auto* item = new QTableWidgetItem(value);
    item->setFlags(item->flags() ^ Qt::ItemIsEditable);
    table->setItem(row, column, item);
}

void populate_wifi_table(QTableWidget* table, const netsentinel::diagnostics::WifiEnvironmentView& view) {
    table->setRowCount(static_cast<int>(view.networks.size()));
    for (int row = 0; row < static_cast<int>(view.networks.size()); ++row) {
        const auto& network = view.networks[static_cast<std::size_t>(row)];
        set_table_item(table, row, 0, QString::fromStdString(network.ssid));
        set_table_item(table, row, 1, QString::fromStdString(network.band));
        set_table_item(table, row, 2, QString::number(network.channel));
        set_table_item(table, row, 3, QString::number(network.signal_quality) + QStringLiteral("%"));
        set_table_item(table, row, 4, QString::fromStdString(network.overlap_severity));
        set_table_item(table, row, 5, QString::fromStdString(network.recommendation));
    }
}

netsentinel::diagnostics::WifiEnvironmentView load_wifi_environment(bool mock_mode) {
    netsentinel::diagnostics::WifiScanConfig config{};
    config.mock_mode = mock_mode;
    config.include_hidden = true;
    auto view = netsentinel::diagnostics::run_wifi_environment_view(config);
    if (!view.success && !mock_mode) {
        config.mock_mode = true;
        view = netsentinel::diagnostics::run_wifi_environment_view(config);
        view.message = "Live Windows WLAN scan was unavailable, so this page is showing deterministic demo data. " + view.message;
    }
    return view;
}

} // namespace

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    app.setApplicationName("NetSentinel11");
    app.setStyleSheet(light_stylesheet());

    QCommandLineParser parser;
    parser.setApplicationDescription("NetSentinel11 native Windows GUI");
    parser.addHelpOption();
    QCommandLineOption db_option({"d", "db"}, "Load scan inventory database.", "path");
    QCommandLineOption gateway_option("gateway", "Gateway/router IP for dashboard context.", "ip");
    QCommandLineOption demo_option("demo", "Use demo mode when no scan database is available.");
    QCommandLineOption mock_option("mock", "Force mock-safe dashboard data for network-sensitive panels.");
    QCommandLineOption screenshot_option("screenshot", "Render the main GUI window to a PNG and exit.", "path");
    QCommandLineOption view_option("view", "Open a specific main navigation view for validation screenshots.", "id");
    QCommandLineOption theme_option("theme", "Force a validation theme: light or dark.", "name");
    parser.addOption(db_option);
    parser.addOption(gateway_option);
    parser.addOption(demo_option);
    parser.addOption(mock_option);
    parser.addOption(screenshot_option);
    parser.addOption(view_option);
    parser.addOption(theme_option);
    parser.process(app);

    const QString db_path = parser.value(db_option);
    const QString gateway = parser.value(gateway_option).isEmpty()
        ? QStringLiteral("192.168.50.1")
        : parser.value(gateway_option);
    const bool demo_mode = parser.isSet(demo_option) || db_path.isEmpty();
    const bool mock_mode = parser.isSet(mock_option);

    netsentinel::storage::StorageConfig storage{};
    if (!db_path.isEmpty()) {
        storage.database_path = db_path.toStdString();
    }

    netsentinel::ui::GuiShellConfig shell_config{};
    shell_config.demo_mode = demo_mode;
    shell_config.gateway = gateway.toStdString();
    shell_config.storage = storage;
    const auto shell = netsentinel::ui::build_gui_shell_model(shell_config);
    netsentinel::ui::GuiDeviceListConfig device_config{};
    device_config.storage = storage;
    device_config.preset = "all";
    device_config.include_hidden = true;
    const auto devices = netsentinel::ui::build_gui_device_list_model(device_config);
    netsentinel::ui::GuiBandwidthDashboardConfig bandwidth_config{};
    bandwidth_config.demo_mode = demo_mode;
    bandwidth_config.mock_mode = mock_mode || demo_mode;
    const auto bandwidth = netsentinel::ui::build_gui_bandwidth_dashboard_model(bandwidth_config);
    auto wifi = load_wifi_environment(mock_mode);

    QMainWindow window;
    window.setWindowTitle("NetSentinel11");
    window.resize(1280, 820);

    auto* root = new QWidget(&window);
    auto* root_layout = new QHBoxLayout(root);
    root_layout->setContentsMargins(18, 18, 18, 18);
    root_layout->setSpacing(18);

    auto* nav = new QFrame(root);
    nav->setObjectName("NavRail");
    nav->setFixedWidth(236);
    auto* nav_layout = new QVBoxLayout(nav);
    nav_layout->setContentsMargins(18, 20, 18, 20);
    nav_layout->setSpacing(10);
    auto* title = new QLabel("NetSentinel11");
    title->setObjectName("AppTitle");
    auto* subtitle = new QLabel("Local-first network scanner");
    subtitle->setObjectName("AppSubtitle");
    nav_layout->addWidget(title);
    nav_layout->addWidget(subtitle);
    nav_layout->addSpacing(18);

    auto* stack = new QStackedWidget(root);
    const QStringList nav_names{"Dashboard", "Scan", "Devices", "Map", "Wi-Fi", "Bandwidth", "Security", "Timeline", "Reports", "Settings"};
    for (int i = 0; i < nav_names.size(); ++i) {
        auto* button = new QPushButton(nav_names[i]);
        button->setObjectName("NavButton");
        const QString page_title = nav_names[i];
        QObject::connect(button, &QPushButton::clicked, [&window, stack, i, page_title]() {
            stack->setCurrentIndex(i);
            window.setWindowTitle(QStringLiteral("NetSentinel11 - ") + page_title);
        });
        nav_layout->addWidget(button);
    }
    nav_layout->addStretch();
    auto* theme_button = new QPushButton("Toggle dark mode");
    theme_button->setObjectName("PrimaryButton");
    nav_layout->addWidget(theme_button);

    auto* dashboard_content = new QWidget();
    auto* dashboard_layout = new QVBoxLayout(dashboard_content);
    auto* hero = new QLabel("Your network, readable at a glance");
    hero->setObjectName("Hero");
    auto* hero_subtitle = new QLabel(QString::fromStdString(shell.visual_direction));
    hero_subtitle->setObjectName("Muted");
    hero_subtitle->setWordWrap(true);
    dashboard_layout->addWidget(hero);
    dashboard_layout->addWidget(hero_subtitle);
    auto* grid = new QGridLayout();
    grid->setSpacing(14);
    grid->addWidget(make_card("Devices", QString::number(devices.rows.size()), db_path.isEmpty() ? "No database selected; pass --db to show real saved devices." : QStringLiteral("Loaded from %1").arg(db_path)), 0, 0);
    grid->addWidget(make_card("Wi-Fi APs", QString::number(wifi.networks.size()), QString::fromStdString(wifi.scan_source)), 0, 1);
    grid->addWidget(make_card("Top talkers", QString::number(bandwidth.top_talkers.size()), "Bandwidth page separates measured, estimated, and incomplete data."), 0, 2);
    grid->addWidget(make_card("GUI status", shell.qt_available ? "Qt ready" : "Model only", QString::fromStdString(shell.message)), 1, 0);
    grid->addWidget(make_card("Authorized scope", "Local only", QStringLiteral("Default router context: %1. No exploit payloads, MITM, spoofing, deauth, or public-IP scanning.").arg(gateway)), 1, 1);
    grid->addWidget(make_card("Theme", "Light/Dark", "Windows 11 style tokens are wired into the native shell."), 1, 2);
    dashboard_layout->addLayout(grid);
    dashboard_layout->addStretch();
    stack->addWidget(scroll_page(dashboard_content));

    auto* scan_content = new QWidget();
    auto* scan_layout = new QVBoxLayout(scan_content);
    auto* scan_title = new QLabel("Safe scan results");
    scan_title->setObjectName("Hero");
    auto* scan_status = new QLabel("Ready. This screen calls backend APIs and never embeds scanner logic in widgets.");
    scan_status->setObjectName("Muted");
    scan_status->setWordWrap(true);
    auto* scan_button = new QPushButton("Run safe Wi-Fi environment scan");
    scan_button->setObjectName("PrimaryButton");
    auto* scan_progress = new QProgressBar();
    scan_progress->setRange(0, 100);
    scan_progress->setValue(0);
    scan_progress->setTextVisible(true);
    auto* scan_table = new QTableWidget(0, 6);
    scan_table->setHorizontalHeaderLabels({"SSID", "Band", "Channel", "Signal", "Overlap", "Recommendation"});
    scan_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    scan_table->verticalHeader()->setVisible(false);
    populate_wifi_table(scan_table, wifi);
    scan_layout->addWidget(scan_title);
    scan_layout->addWidget(scan_status);
    scan_layout->addWidget(scan_button);
    scan_layout->addWidget(scan_progress);
    scan_layout->addWidget(scan_table);
    stack->addWidget(scroll_page(scan_content));

    auto* devices_content = new QWidget();
    auto* devices_layout = new QVBoxLayout(devices_content);
    auto* devices_title = new QLabel("Device cards and list");
    devices_title->setObjectName("Hero");
    auto* devices_note = new QLabel(QString::fromStdString(devices.message.empty() ? "Stored inventory is empty; run a safe LAN scan from the CLI/backend service to populate it." : devices.message));
    devices_note->setObjectName("Muted");
    devices_note->setWordWrap(true);
    auto* device_cards = new QGridLayout();
    device_cards->setSpacing(14);
    const int card_limit = std::min<int>(6, static_cast<int>(devices.rows.size()));
    if (card_limit == 0) {
        device_cards->addWidget(make_card("No devices loaded", "Run scan", "Use --db with a saved inventory or run a safe authorized LAN scan first."), 0, 0);
    }
    for (int row = 0; row < card_limit; ++row) {
        const auto& device = devices.rows[static_cast<std::size_t>(row)];
        const auto name = QString::fromStdString(device.hostname.empty() ? device.device_id : device.hostname);
        const auto metric = QString::fromStdString(device.primary_ip.empty() ? device.status_badge : device.primary_ip);
        const auto detail = QString::fromStdString(device.icon + " | " + device.vendor + " | " + device.device_type + " | " + device.status_badge);
        device_cards->addWidget(make_card(name, metric, detail), row / 3, row % 3);
    }
    auto* device_table = new QTableWidget(static_cast<int>(devices.rows.size()), 6);
    device_table->setHorizontalHeaderLabels({"Icon", "Name", "IP", "Vendor", "Type", "Status"});
    device_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    device_table->verticalHeader()->setVisible(false);
    for (int row = 0; row < static_cast<int>(devices.rows.size()); ++row) {
        const auto& device = devices.rows[static_cast<std::size_t>(row)];
        set_table_item(device_table, row, 0, QString::fromStdString(device.icon));
        set_table_item(device_table, row, 1, QString::fromStdString(device.hostname.empty() ? device.device_id : device.hostname));
        set_table_item(device_table, row, 2, QString::fromStdString(device.primary_ip));
        set_table_item(device_table, row, 3, QString::fromStdString(device.vendor));
        set_table_item(device_table, row, 4, QString::fromStdString(device.device_type));
        set_table_item(device_table, row, 5, QString::fromStdString(device.status_badge));
    }
    devices_layout->addWidget(devices_title);
    devices_layout->addWidget(devices_note);
    devices_layout->addLayout(device_cards);
    devices_layout->addWidget(device_table);
    stack->addWidget(scroll_page(devices_content));

    auto* map_content = new QWidget();
    auto* map_layout = new QVBoxLayout(map_content);
    auto* map_title = new QLabel("Network map");
    map_title->setObjectName("Hero");
    auto* map_note = new QLabel("Topology-style view built from backend inventory. Router is shown as the anchor; device cards stay local and privacy-safe.");
    map_note->setObjectName("Muted");
    map_note->setWordWrap(true);
    auto* map_grid = new QGridLayout();
    map_grid->setSpacing(14);
    map_grid->addWidget(make_card("Router / Gateway", gateway, "Detected or configured local gateway anchor."), 0, 1);
    for (int row = 0; row < card_limit; ++row) {
        const auto& device = devices.rows[static_cast<std::size_t>(row)];
        const auto name = QString::fromStdString(device.hostname.empty() ? device.device_id : device.hostname);
        const auto ip = QString::fromStdString(device.primary_ip);
        map_grid->addWidget(make_card(name, ip.isEmpty() ? "local device" : ip, QString::fromStdString(device.device_type)), 1 + (row / 3), row % 3);
    }
    if (card_limit == 0) {
        map_grid->addWidget(make_card("Waiting for inventory", "No nodes", "Load a real scan database to render topology cards."), 1, 1);
    }
    map_layout->addWidget(map_title);
    map_layout->addWidget(map_note);
    map_layout->addLayout(map_grid);
    map_layout->addStretch();
    stack->addWidget(scroll_page(map_content));

    auto* wifi_content = new QWidget();
    auto* wifi_layout = new QVBoxLayout(wifi_content);
    auto* wifi_title = new QLabel("Nearby Wi-Fi environment");
    wifi_title->setObjectName("Hero");
    auto* wifi_summary = new QTextEdit(QString::fromStdString(netsentinel::diagnostics::wifi_environment_markdown(wifi)));
    wifi_summary->setReadOnly(true);
    wifi_layout->addWidget(wifi_title);
    wifi_layout->addWidget(wifi_summary);
    stack->addWidget(scroll_page(wifi_content));

    auto* bandwidth_content = new QWidget();
    auto* bandwidth_layout = new QVBoxLayout(bandwidth_content);
    auto* bandwidth_title = new QLabel("Bandwidth and top talkers");
    bandwidth_title->setObjectName("Hero");
    auto* bandwidth_table = new QTableWidget(static_cast<int>(bandwidth.top_talkers.size()), 5);
    bandwidth_table->setHorizontalHeaderLabels({"Device", "RX", "TX", "Total", "Confidence"});
    bandwidth_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    bandwidth_table->verticalHeader()->setVisible(false);
    for (int row = 0; row < static_cast<int>(bandwidth.top_talkers.size()); ++row) {
        const auto& talker = bandwidth.top_talkers[static_cast<std::size_t>(row)];
        set_table_item(bandwidth_table, row, 0, QString::fromStdString(talker.display_name));
        set_table_item(bandwidth_table, row, 1, QString::number(static_cast<qulonglong>(talker.rx_bytes)));
        set_table_item(bandwidth_table, row, 2, QString::number(static_cast<qulonglong>(talker.tx_bytes)));
        set_table_item(bandwidth_table, row, 3, QString::number(static_cast<qulonglong>(talker.total_bytes)));
        set_table_item(bandwidth_table, row, 4, QString::fromStdString(talker.confidence));
    }
    bandwidth_layout->addWidget(bandwidth_title);
    bandwidth_layout->addWidget(make_card("Source", QString::fromStdString(bandwidth.active_source), QString::fromStdString(bandwidth.message)));
    bandwidth_layout->addWidget(bandwidth_table);
    stack->addWidget(scroll_page(bandwidth_content));

    auto* security_content = new QWidget();
    auto* security_layout = new QVBoxLayout(security_content);
    auto* security_title = new QLabel("Security warnings");
    security_title->setObjectName("Hero");
    security_layout->addWidget(security_title);
    security_layout->addWidget(make_severity_card("Authorized-use guard", "INFO", "Scanner actions are local-only and safe by design.", "#2f80ed"));
    security_layout->addWidget(make_severity_card("Unknown devices", devices.rows.empty() ? "WAITING" : "REVIEW", "Unknown and newly seen devices are highlighted from the inventory/search backend.", devices.rows.empty() ? "#f2c94c" : "#f2994a"));
    security_layout->addWidget(make_severity_card("Router exposure", "SAFE CHECK", "Router checks use metadata and service identification only; no exploit payloads.", "#27ae60"));
    security_layout->addStretch();
    stack->addWidget(scroll_page(security_content));

    auto* timeline_content = new QWidget();
    auto* timeline_layout = new QVBoxLayout(timeline_content);
    auto* timeline_title = new QLabel("Event timeline");
    timeline_title->setObjectName("Hero");
    auto* timeline_text = new QTextEdit();
    timeline_text->setReadOnly(true);
    timeline_text->setPlainText(QStringLiteral(
        "Timeline backend: ready\n"
        "Loaded badge: %1\n\n"
        "- Scan started and completed events will appear here.\n"
        "- New device, offline device, warning, report, and settings events are grouped by time.\n"
        "- This page intentionally shows backend-derived events only; it does not invent network activity."
    ).arg(QString::fromStdString(shell.views.size() > 4 ? shell.views[4].badge : std::string{"pending"})));
    timeline_layout->addWidget(timeline_title);
    timeline_layout->addWidget(timeline_text);
    stack->addWidget(scroll_page(timeline_content));

    auto* reports_content = new QWidget();
    auto* reports_layout = new QVBoxLayout(reports_content);
    auto* reports_title = new QLabel("Reports");
    reports_title->setObjectName("Hero");
    reports_layout->addWidget(reports_title);
    reports_layout->addWidget(make_card("Inventory report", "HTML/JSON/CSV", "Uses backend report APIs and includes privacy warnings before export."));
    reports_layout->addWidget(make_card("Bandwidth report", bandwidth.top_talkers.empty() ? "No samples" : "Ready", "Separates real, estimated, and mock/demo bandwidth sources."));
    reports_layout->addWidget(make_card("Security report", "Ready", "Designed for non-technical users: severity colors plus plain-language findings."));
    reports_layout->addStretch();
    stack->addWidget(scroll_page(reports_content));

    auto* settings_content = new QWidget();
    auto* settings_layout = new QVBoxLayout(settings_content);
    auto* settings_title = new QLabel("Settings");
    settings_title->setObjectName("Hero");
    settings_layout->addWidget(settings_title);
    settings_layout->addWidget(make_card("Data source", db_path.isEmpty() ? "Demo mode" : "Real database", db_path.isEmpty() ? "Launch with --db <path> to show saved scan data." : db_path));
    settings_layout->addWidget(make_card("Privacy", "Local-first", "Retention, export acknowledgement, and redaction are product requirements before release."));
    settings_layout->addWidget(make_card("Theme", "Light/Dark", "The theme switch is available from the navigation rail."));
    settings_layout->addStretch();
    stack->addWidget(scroll_page(settings_content));

    QObject::connect(scan_button, &QPushButton::clicked, [&wifi, scan_status, scan_table, wifi_summary, scan_progress]() {
        scan_progress->setValue(15);
        scan_status->setText("Running Windows WLAN environment scan through diagnostics backend...");
        scan_progress->setValue(60);
        wifi = load_wifi_environment(false);
        populate_wifi_table(scan_table, wifi);
        wifi_summary->setPlainText(QString::fromStdString(netsentinel::diagnostics::wifi_environment_markdown(wifi)));
        scan_status->setText(QString::fromStdString(wifi.message));
        scan_progress->setValue(100);
    });

    bool dark = false;
    QObject::connect(theme_button, &QPushButton::clicked, [&app, &dark]() {
        dark = !dark;
        app.setStyleSheet(dark ? dark_stylesheet() : light_stylesheet());
    });

    root_layout->addWidget(nav);
    root_layout->addWidget(stack, 1);
    window.setCentralWidget(root);
    window.statusBar()->showMessage(QStringLiteral("Qt GUI shell | %1 | gateway %2 | devices %3")
        .arg(db_path.isEmpty() ? QStringLiteral("demo data") : db_path)
        .arg(gateway)
        .arg(devices.rows.size()));
    apply_brand_visibility_guard(window);

    const QString requested_theme = parser.value(theme_option).toLower().trimmed();
    if (requested_theme == QStringLiteral("dark")) {
        window.setStyleSheet(window.styleSheet() + QStringLiteral(
            "QMainWindow, QWidget { background: #0b1220; color: #e5edf8; }"
            "QLabel { color: #e5edf8; }"
            "QFrame#Card { background: #111c2f; border: 1px solid #263852; border-radius: 18px; }"
            "QListWidget { background: #07111f; color: #f8fafc; border: 0; }"
            "QListWidget::item:selected { background: #1d4ed8; color: #ffffff; }"
            "QTableWidget, QTextEdit { background: #0f172a; color: #e5edf8; border: 1px solid #263852; }"
            "QStatusBar { background: #07111f; color: #cbd5e1; }"
        ));
        apply_brand_visibility_guard(window);
    }

    const QString requested_view = parser.value(view_option).toLower().trimmed();
    if (!requested_view.isEmpty()) {
        QString normalized_request = requested_view;
        normalized_request.remove(QStringLiteral(" "));
        normalized_request.remove(QStringLiteral("-"));
        for (int row = 0; row < nav_names.size(); ++row) {
            QString normalized_item = nav_names[row].toLower();
            normalized_item.remove(QStringLiteral(" "));
            normalized_item.remove(QStringLiteral("-"));
            if (normalized_item == normalized_request || normalized_item.contains(normalized_request)) {
                stack->setCurrentIndex(row);
                window.setWindowTitle(QStringLiteral("NetSentinel11 - ") + nav_names[row]);
                break;
            }
        }
    }

    const QString screenshot_path = parser.value(screenshot_option);
    if (!screenshot_path.isEmpty()) {
        window.resize(1440, 960);
        window.show();
        QTimer::singleShot(250, [&app, &window, screenshot_path]() {
            const QPixmap rendered = window.grab();
            const bool saved = !rendered.isNull() && rendered.save(screenshot_path, "PNG");
            app.exit(saved ? 0 : 1);
        });
        return app.exec();
    }

    window.show();

    return app.exec();
}
