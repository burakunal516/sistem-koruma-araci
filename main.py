import sys
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QLabel, QStackedWidget, QFileDialog, QTableWidget,
    QTableWidgetItem, QHeaderView, QProgressBar
)
from core import SystemCore

class FullScanWorker(QThread):
    progress_signal = Signal(int, int, bool, bool)  # (completed, total, timeout, quota)
    file_scanned_signal = Signal(dict)
    finished_signal = Signal(int, bool, bool)      # (total, timeout, quota)

    def __init__(self, dir_path):
        super().__init__()
        self.dir_path = dir_path

    def run(self):
        total_count = 0
        timeout_flag = False
        quota_flag = False

        def on_progress(completed, total, timeout_reached=False, quota_reached=False):
            nonlocal total_count, timeout_flag, quota_flag
            total_count = completed
            timeout_flag = timeout_reached
            quota_flag = quota_reached
            self.progress_signal.emit(completed, total, timeout_reached, quota_reached)

        def on_file_scanned(item):
            self.file_scanned_signal.emit(item)

        SystemCore.scan_directory(
            self.dir_path, 
            progress_callback=on_progress, 
            file_callback=on_file_scanned
        )
        self.finished_signal.emit(total_count, timeout_flag, quota_flag)


class SpeedTestWorker(QThread):
    finished_signal = Signal(dict)

    def run(self):
        result = SystemCore.run_speedtest()
        self.finished_signal.emit(result)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Güvenlik ve Sistem Analiz Aracı")
        self.resize(1050, 680)
        
        # Tamamen Koyu (Dark Mode) Tasarım QSS
        self.setStyleSheet("""
            QMainWindow { background-color: #121212; }
            QWidget#sidebar { background-color: #1e1e1e; border-right: 1px solid #2d2d2d; }
            QPushButton#sidebar_btn {
                background-color: transparent;
                color: #a0a0a0;
                border: none;
                text-align: left;
                padding: 14px 18px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 8px;
            }
            QPushButton#sidebar_btn:hover { background-color: #2a2a2a; color: #ffffff; }
            QPushButton#sidebar_btn:checked { background-color: #0ea5e9; color: #ffffff; }
            QLabel { color: #e0e0e0; font-size: 14px; }
            QPushButton#action_btn {
                background-color: #0ea5e9; color: white; border: none;
                padding: 12px 24px; font-weight: bold; border-radius: 8px; font-size: 14px;
            }
            QPushButton#action_btn:hover { background-color: #0284c7; }
            QPushButton#action_btn:disabled { background-color: #333333; color: #666666; }
            QProgressBar {
                border: 1px solid #333333;
                border-radius: 6px;
                text-align: center;
                background-color: #1e1e1e;
                color: #ffffff;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #0ea5e9;
                border-radius: 5px;
            }
            QTableWidget {
                background-color: #181818;
                color: #e0e0e0;
                gridline-color: #2d2d2d;
                border: 1px solid #2d2d2d;
                border-radius: 8px;
                selection-background-color: #0ea5e9;
            }
            QHeaderView::section {
                background-color: #222222;
                color: #ffffff;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
        """)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QHBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        self.create_sidebar()

        self.stacked_widget = QStackedWidget()
        self.main_layout.addWidget(self.stacked_widget)

        self.init_virus_scan_page()
        self.init_network_page()
        self.init_storage_page()

    def create_sidebar(self):
        self.sidebar = QWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar_layout = QVBoxLayout(self.sidebar)
        self.sidebar_layout.setContentsMargins(15, 25, 15, 25)
        self.sidebar_layout.setSpacing(12)

        lbl_logo = QLabel("SİSTEM KORUMA")
        lbl_logo.setStyleSheet("color: #ffffff; font-size: 16px; font-weight: bold; margin-bottom: 25px;")
        self.sidebar_layout.addWidget(lbl_logo)

        self.btn_virus = QPushButton("🛡 Toplu Virüs Taraması")
        self.btn_network = QPushButton("🌐 İnternet Hız Testi")
        self.btn_storage = QPushButton("💾 Depolama Analizi")

        for btn in [self.btn_virus, self.btn_network, self.btn_storage]:
            btn.setObjectName("sidebar_btn")
            btn.setCheckable(True)
            self.sidebar_layout.addWidget(btn)

        self.sidebar_layout.addStretch()
        self.main_layout.addWidget(self.sidebar)

        self.btn_virus.clicked.connect(lambda: self.switch_page(0, self.btn_virus))
        self.btn_network.clicked.connect(lambda: self.switch_page(1, self.btn_network))
        self.btn_storage.clicked.connect(lambda: self.switch_page(2, self.btn_storage))

        self.btn_virus.setChecked(True)

    def switch_page(self, index, active_btn):
        self.stacked_widget.setCurrentIndex(index)
        for btn in [self.btn_virus, self.btn_network, self.btn_storage]:
            btn.setChecked(False)
        active_btn.setChecked(True)

        if index == 2:
            self.load_storage_data()

    # --- Sayfa 1: Toplu Virüs Taraması ---
    def init_virus_scan_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(35, 35, 35, 35)

        title = QLabel("Dizin / Gerçek Tehdit Taraması (VirusTotal API)")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #ffffff;")
        
        self.btn_select_dir = QPushButton("Klasör Seç ve Taramayı Başlat")
        self.btn_select_dir.setObjectName("action_btn")
        self.btn_select_dir.clicked.connect(self.start_directory_scan)

        self.scan_progress_bar = QProgressBar()
        self.scan_progress_bar.setRange(0, 100)
        self.scan_progress_bar.setValue(0)
        self.scan_progress_bar.setFixedHeight(24)
        self.scan_progress_bar.setVisible(False)

        self.lbl_scan_status = QLabel("Taranacak Dizin Seçilmedi (7 Dk Zaman Aşımı & Kota Koruması Aktif)")
        self.lbl_scan_status.setStyleSheet("font-size: 14px; color: #b0b0b0; margin-top: 5px;")

        self.table_scan = QTableWidget()
        self.table_scan.setColumnCount(3)
        self.table_scan.setHorizontalHeaderLabels(["Tehdit İçeren Dosya Yolu", "SHA-256 Hash", "Durum / Bilgi"])
        self.table_scan.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)

        layout.addWidget(title)
        layout.addWidget(self.btn_select_dir)
        layout.addWidget(self.scan_progress_bar)
        layout.addWidget(self.lbl_scan_status)
        layout.addWidget(self.table_scan)

        self.stacked_widget.addWidget(page)

    def start_directory_scan(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Taranacak Klasörü Seç")
        if dir_path:
            self.btn_select_dir.setEnabled(False)
            self.scan_progress_bar.setVisible(True)
            self.scan_progress_bar.setValue(0)
            self.lbl_scan_status.setText(f"🔍 Dosyalar analiz ediliyor ve API kontrolü başlıyor...")
            self.table_scan.setRowCount(0)
            
            self.scan_worker = FullScanWorker(dir_path)
            self.scan_worker.progress_signal.connect(self.update_scan_progress)
            self.scan_worker.file_scanned_signal.connect(self.handle_scanned_file)
            self.scan_worker.finished_signal.connect(self.handle_scan_finished)
            self.scan_worker.start()

    def update_scan_progress(self, completed, total, timeout_reached, quota_reached):
        if timeout_reached or quota_reached:
            return
        if total > 0:
            percent = int((completed / total) * 100)
            self.scan_progress_bar.setValue(percent)
            self.lbl_scan_status.setText(f"🔍 Taranıyor... (%{percent} tamamlandı - {completed}/{total} dosya)")

    def handle_scanned_file(self, res):
        if res["status"] != "clean":
            row = self.table_scan.rowCount()
            self.table_scan.insertRow(row)
            self.table_scan.setItem(row, 0, QTableWidgetItem(res["path"]))
            self.table_scan.setItem(row, 1, QTableWidgetItem(res["hash"]))
            self.table_scan.setItem(row, 2, QTableWidgetItem(res["message"]))

    def handle_scan_finished(self, total_count, timeout_flag, quota_flag):
        self.btn_select_dir.setEnabled(True)
        threat_count = self.table_scan.rowCount()
        
        if quota_flag:
            self.lbl_scan_status.setText(f"🛑 API Kotası Doldu (429)! Sistem korunmak için taramayı durdurdu. Taranan: {total_count}")
        elif timeout_flag:
            self.lbl_scan_status.setText(f"⚠️ 7 Dakikalık Zaman Aşımı Sınırına Ulaşıldı! Tarama durduruldu. Taranan: {total_count}")
        else:
            self.lbl_scan_status.setText(f"✅ Tarama Tamamlandı. Toplam taranan dosya: {total_count} | Tehdit/Uyarı: {threat_count}")

    # --- Sayfa 2: İnternet Hız Testi ---
    def init_network_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(35, 35, 35, 35)

        title = QLabel("İnternet Hız Testi (Download / Upload)")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #ffffff;")

        self.btn_speedtest = QPushButton("Hız Testini Başlat")
        self.btn_speedtest.setObjectName("action_btn")
        self.btn_speedtest.clicked.connect(self.run_speedtest_action)

        self.net_progress_bar = QProgressBar()
        self.net_progress_bar.setRange(0, 0)
        self.net_progress_bar.setFixedHeight(22)
        self.net_progress_bar.setVisible(False)

        self.lbl_speed_result = QLabel("Test bekleniyor...")
        self.lbl_speed_result.setStyleSheet("font-size: 15px; color: #b0b0b0; margin-top: 15px;")

        layout.addWidget(title)
        layout.addWidget(self.btn_speedtest)
        layout.addWidget(self.net_progress_bar)
        layout.addWidget(self.lbl_speed_result)
        layout.addStretch()

        self.stacked_widget.addWidget(page)

    def run_speedtest_action(self):
        self.btn_speedtest.setEnabled(False)
        self.net_progress_bar.setVisible(True)
        self.lbl_speed_result.setText("Sunucuya bağlanılıyor ve hız testi yapılıyor, lütfen bekleyin...")
        
        self.speed_worker = SpeedTestWorker()
        self.speed_worker.finished_signal.connect(self.handle_speedtest_finished)
        self.speed_worker.start()

    def handle_speedtest_finished(self, result):
        self.btn_speedtest.setEnabled(True)
        self.net_progress_bar.setVisible(False)
        
        if result["success"]:
            text = (
                f"<b>✅ Test Başarılı!</b><br><br>"
                f"📥 İndirme (Download): <b>{result['download']} Mbps</b><br>"
                f"📤 Yükleme (Upload): <b>{result['upload']} Mbps</b><br>"
                f"⚡ Ping: <b>{result['ping']} ms</b>"
            )
            self.lbl_speed_result.setText(text)
        else:
            self.lbl_speed_result.setText(f"❌ {result['message']}")

    # --- Sayfa 3: Depolama Analizi ---
    def init_storage_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(35, 35, 35, 35)

        title = QLabel("Depolama, Sürücü ve Klasör Boyutları Analizi")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #ffffff;")

        self.table_storage = QTableWidget()
        self.table_storage.setColumnCount(4)
        self.table_storage.setHorizontalHeaderLabels(["Birim / Klasör Adı", "Konum / Yol", "Boyut / Kullanım", "Doluluk / Detay"])
        self.table_storage.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)

        layout.addWidget(title)
        layout.addWidget(self.table_storage)

        self.stacked_widget.addWidget(page)

    def load_storage_data(self):
        data = SystemCore.get_storage_analysis()
        partitions = data["partitions"]
        folders = data["folders"]

        total_rows = len(partitions) + len(folders)
        self.table_storage.setRowCount(total_rows)

        row = 0
        # 1. Disk Sürücülerini Ekle
        for part in partitions:
            total_gb = part['total'] / (1024**3)
            free_gb = part['free'] / (1024**3)
            used_gb = part['used'] / (1024**3)
            
            self.table_storage.setItem(row, 0, QTableWidgetItem(f"💽 Sürücü: {part['device']}"))
            self.table_storage.setItem(row, 1, QTableWidgetItem(part['mountpoint']))
            self.table_storage.setItem(row, 2, QTableWidgetItem(f"Toplam: {total_gb:.2f} GB | Boş: {free_gb:.2f} GB"))
            self.table_storage.setItem(row, 3, QTableWidgetItem(f"%{part['percent']} dolu"))
            row += 1

        # 2. Kritik Kullanıcı Klasörlerini (Masaüstü, İndirilenler vb.) Ekle
        for fold in folders:
            size_mb = fold['size'] / (1024**2)
            if size_mb > 1024:
                size_str = f"{size_mb / 1024:.2f} GB"
            else:
                size_str = f"{size_mb:.2f} MB"

            self.table_storage.setItem(row, 0, QTableWidgetItem(f"📁 Klasör: {fold['name']}"))
            self.table_storage.setItem(row, 1, QTableWidgetItem(fold['path']))
            self.table_storage.setItem(row, 2, QTableWidgetItem(size_str))
            self.table_storage.setItem(row, 3, QTableWidgetItem("Kullanıcı Klasörü"))
            row += 1


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())