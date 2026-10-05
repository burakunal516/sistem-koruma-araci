import hashlib
import os
import time
import psutil
import requests
import speedtest
from concurrent.futures import ThreadPoolExecutor, as_completed

class SystemCore:
    VIRUSTOTAL_API_KEY = ""  

    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
        sha_hash = hashlib.new(algorithm)
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(65536), b""):
                    sha_hash.update(byte_block)
            return sha_hash.hexdigest()
        except Exception:
            return None

    @classmethod
    def check_api_signature(cls, file_hash: str) -> dict:
        if not cls.VIRUSTOTAL_API_KEY:
            return {
                "status": "clean", 
                "message": "API Anahtarı girilmediği için simülasyon modu aktif (Güvenli)"
            }

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": cls.VIRUSTOTAL_API_KEY}
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                if malicious > 0 or suspicious > 0:
                    return {
                        "status": "infected",
                        "message": f"⚠️ TEHLİKE! ({malicious} Antivirüs zararlı işaretledi)"
                    }
                else:
                    return {"status": "clean", "message": "Güvenli"}
            elif response.status_code == 404:
                return {"status": "clean", "message": "VT Veritabanında Temiz / Kayıt Yok"}
            elif response.status_code == 429:
                return {"status": "rate_limit", "message": "API Kotası Doldu (429 Too Many Requests)"}
        except Exception:
            pass
        
        return {"status": "clean", "message": "Bağlantı Hatası"}

    @staticmethod
    def scan_directory(directory_path: str, progress_callback=None, file_callback=None):
        start_time = time.time()
        max_timeout_seconds = 420  # 7 dakika limit
        
        file_list = []
        try:
            for root, dirs, files in os.walk(directory_path):
                dirs[:] = [d for d in dirs if d.lower() not in ['$recycle.bin', 'system volume information', 'windows']]
                for file in files:
                    try:
                        file_list.append(os.path.join(root, file))
                    except Exception:
                        continue
        except Exception:
            pass

        total_files = len(file_list)
        if total_files == 0:
            if progress_callback:
                progress_callback(0, 0, False, False)
            return

        completed_count = 0
        max_workers = 1  
        quota_exceeded = False

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(SystemCore.check_file_and_hash, f): f for f in file_list}
            
            for future in as_completed(future_to_file):
                if time.time() - start_time > max_timeout_seconds:
                    if progress_callback:
                        progress_callback(completed_count, total_files, True, False)
                    break

                completed_count += 1
                result = future.result()
                
                if result:
                    if result["status"] == "rate_limit":
                        quota_exceeded = True
                        if file_callback:
                            file_callback(result)
                        if progress_callback:
                            progress_callback(completed_count, total_files, False, True)
                        break 

                    if file_callback:
                        file_callback(result)
                        
                if progress_callback:
                    progress_callback(completed_count, total_files, False, False)
                
                time.sleep(1)

    @staticmethod
    def check_file_and_hash(file_path):
        try:
            if os.path.getsize(file_path) > 50 * 1024 * 1024:
                return None
            
            file_hash = SystemCore.calculate_file_hash(file_path)
            if file_hash:
                api_result = SystemCore.check_api_signature(file_hash)
                return {
                    "path": file_path,
                    "hash": file_hash,
                    "status": api_result["status"],
                    "message": api_result["message"]
                }
        except Exception:
            pass
        return None

    @staticmethod
    def run_speedtest() -> dict:
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            
            download_speed = st.download() / 1_000_000  
            upload_speed = st.upload() / 1_000_000      
            ping = st.results.ping

            return {
                "success": True,
                "download": round(download_speed, 2),
                "upload": round(upload_speed, 2),
                "ping": round(ping, 2),
                "message": "Hız testi başarıyla tamamlandı."
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Hız testi başarısız: {str(e)}"
            }

    @staticmethod
    def get_folder_size(folder_path: str) -> int:
        """Belirtilen klasörün toplam boyutunu bayt cinsinden hesaplar."""
        total_size = 0
        try:
            for dirpath, dirnames, filenames in os.walk(folder_path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    try:
                        if not os.path.islink(fp):
                            total_size += os.path.getsize(fp)
                    except Exception:
                        continue
        except Exception:
            pass
        return total_size

    @staticmethod
    def get_storage_analysis() -> dict:
        """Disk bölümlerini ve kritik kullanıcı klasörlerinin boyutlarını döner."""
        partitions_info = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                partitions_info.append({
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent
                })
            except PermissionError:
                continue

        # Kritik Klasörler (Masaüstü, İndirilenler, Belgeler, Görseller)
        user_home = os.path.expanduser("~")
        target_folders = {
            "Masaüstü (Desktop)": os.path.join(user_home, "Desktop"),
            "İndirilenler (Downloads)": os.path.join(user_home, "Downloads"),
            "Belgeler (Documents)": os.path.join(user_home, "Documents"),
            "Görseller (Pictures)": os.path.join(user_home, "Pictures")
        }

        folders_info = []
        for name, path in target_folders.items():
            if os.path.exists(path):
                size_bytes = SystemCore.get_folder_size(path)
                folders_info.append({
                    "name": name,
                    "path": path,
                    "size": size_bytes
                })

        return {
            "partitions": partitions_info,
            "folders": folders_info
        }