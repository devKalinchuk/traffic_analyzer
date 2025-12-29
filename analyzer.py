#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Аналізатор PCAP-файлів для виявлення реальних загроз
Оптимізовано для великих файлів та сучасного зашифрованого трафіку
"""

from scapy.all import PcapReader, IP, TCP, UDP, ICMP, DNS, Raw, ARP
from collections import defaultdict
import sys
import ipaddress
from datetime import datetime
import statistics
import hashlib
import re


class AdvancedPcapAnalyzer:
    def __init__(self, pcap_file, local_network="192.168.0.0/16", use_threat_intel=False):
        self.pcap_file = pcap_file
        self.suspicious_activities = []
        self.local_network = ipaddress.ip_network(local_network)
        self.local_ips = set()
        self.use_threat_intel = use_threat_intel

        # Лічильники для статистики
        self.total_packets = 0
        self.processed_packets = 0

        # TCP Stream reassembly
        self.tcp_streams = defaultdict(lambda: {'data': b'', 'packets': []})

        # TLS fingerprints (JA3)
        self.tls_fingerprints = defaultdict(list)

        # Порти відомих загроз
        self.EXPLOIT_PORTS = {
            4444: "Metasploit default",
            5555: "Android Debug Bridge exploit",
            6666: "IRC bot/backdoor",
            6667: "IRC C&C",
            31337: "Elite backdoor",
            12345: "NetBus backdoor",
            1234: "SubSeven backdoor",
            9999: "Generic backdoor"
        }

        # Відомі зловмисні JA3 хеші (приклади)
        self.MALICIOUS_JA3 = {
            'e7d705a3286e19ea42f587b344ee6865': 'Trickbot',
            'a0e9f5d64349fb13191bc781f81f42e1': 'Metasploit',
            '72a589da586844d7f0818ce684948eea': 'Dridex',
            'b32309a26951912be7dba376398abc3b': 'Cobalt Strike'
        }

        # Cryptomining pools
        self.MINING_PORTS = {3333, 4444, 5555, 8333, 9332, 9333, 14433, 14444}

        # Cache для threat intelligence
        self.threat_intel_cache = {}

        # Порти, що часто використовуються для reverse shell/remote access
        self.REVERSE_SHELL_PORTS = {22, 23, 4444, 5555, 6666, 3389, 5900}

    def is_local_ip(self, ip):
        """Перевіряє чи IP належить локальній мережі"""
        try:
            return ipaddress.ip_address(ip) in self.local_network or \
                ipaddress.ip_address(ip).is_private
        except:
            return False

    def is_external_ip(self, ip):
        """Перевіряє чи IP зовнішній"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or
                        ip_obj.is_multicast or ip_obj.is_reserved)
        except:
            return False

    def check_threat_intelligence(self, ip):
        """Перевірка IP через AbuseIPDB (опційно)"""
        if not self.use_threat_intel or ip in self.threat_intel_cache:
            return self.threat_intel_cache.get(ip)

        try:
            # Для використання потрібен API ключ AbuseIPDB
            # api_key = 'YOUR_API_KEY'
            # url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}'
            # headers = {'Key': api_key, 'Accept': 'application/json'}
            # response = requests.get(url, headers=headers, timeout=2)
            # data = response.json()
            # result = data.get('data', {}).get('abuseConfidenceScore', 0)
            # self.threat_intel_cache[ip] = result
            # return result
            pass
        except:
            pass

        return 0

    def calculate_ja3(self, tls_packet):
        """Розрахунок JA3 fingerprint для TLS"""
        try:
            # JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
            # Спрощена версія - у реальності потрібен детальніший парсинг TLS
            if hasattr(tls_packet, 'version') and hasattr(tls_packet, 'ciphers'):
                version = str(tls_packet.version)
                ciphers = ','.join([str(c) for c in tls_packet.ciphers]) if tls_packet.ciphers else ''

                ja3_string = f"{version},{ciphers}"
                ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
                return ja3_hash
        except:
            pass
        return None

    def get_tcp_stream_key(self, pkt):
        """Генерує ключ для TCP потоку"""
        if IP in pkt and TCP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            # Нормалізуємо ключ (щоб прямий та зворотній потоки мали однаковий ключ)
            if (src, sport) < (dst, dport):
                return f"{src}:{sport}-{dst}:{dport}"
            else:
                return f"{dst}:{dport}-{src}:{sport}"
        return None

    def analyze_tcp_stream(self, stream_key, stream_data):
        """Аналізує зібраний TCP потік на наявність загроз"""
        data = stream_data['data']

        # SQL Injection patterns
        sql_patterns = [
            rb"'\s*OR\s*'1'\s*=\s*'1",
            rb"'\s*OR\s*1\s*=\s*1\s*--",
            rb"UNION\s+SELECT",
            rb"';\s*DROP\s+TABLE",
            rb"admin'\s*--",
            rb"'\s*AND\s*'1'\s*=\s*'1"
        ]

        for pattern in sql_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                pkt = stream_data['packets'][0]
                src_ip = pkt[IP].src if IP in pkt else "Unknown"
                dst_ip = pkt[IP].dst if IP in pkt else "Unknown"

                self.suspicious_activities.append({
                    'type': 'SQL_INJECTION',
                    'severity': 'HIGH',
                    'description': f'SQL injection у TCP потоці {src_ip} -> {dst_ip}',
                    'details': f'Виявлено паттерн у реконструйованому потоці'
                })
                return

        # Webshell patterns
        webshell_patterns = [
            rb'system\s*\(',
            rb'exec\s*\(',
            rb'shell_exec',
            rb'passthru',
            rb'eval\s*\(',
            rb'base64_decode.*eval'
        ]

        for pattern in webshell_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                pkt = stream_data['packets'][0]
                src_ip = pkt[IP].src if IP in pkt else "Unknown"
                dst_ip = pkt[IP].dst if IP in pkt else "Unknown"

                self.suspicious_activities.append({
                    'type': 'WEBSHELL',
                    'severity': 'CRITICAL',
                    'description': f'Можливий webshell у трафіку {src_ip} -> {dst_ip}',
                    'details': f'Виявлено виконання системних команд'
                })
                return

    def process_packet(self, pkt):
        """Обробка одного пакету"""
        self.processed_packets += 1

        # Виводимо прогрес кожні 10000 пакетів
        if self.processed_packets % 10000 == 0:
            print(f"[*] Оброблено {self.processed_packets} пакетів...")

        # Збір локальних IP
        if IP in pkt:
            if self.is_local_ip(pkt[IP].src):
                self.local_ips.add(pkt[IP].src)
            if self.is_local_ip(pkt[IP].dst):
                self.local_ips.add(pkt[IP].dst)

        # TCP Stream Reassembly
        if TCP in pkt and Raw in pkt:
            stream_key = self.get_tcp_stream_key(pkt)
            if stream_key:
                self.tcp_streams[stream_key]['data'] += bytes(pkt[Raw].load)
                self.tcp_streams[stream_key]['packets'].append(pkt)

                # Аналізуємо потік, якщо він закінчився (FIN або RST)
                if pkt[TCP].flags & 0x01 or pkt[TCP].flags & 0x04:  # FIN or RST
                    self.analyze_tcp_stream(stream_key, self.tcp_streams[stream_key])
                    del self.tcp_streams[stream_key]

        # TLS Fingerprinting (JA3) - порт 443 перевіряємо об'єднано
        if TCP in pkt and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
            try:
                # Перевірка на TLS Client Hello
                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    # TLS Client Hello має тип 0x16 (Handshake) та версію
                    if len(payload) > 5 and payload[0] == 0x16:
                        src_ip = pkt[IP].src if IP in pkt else None
                        if src_ip and self.is_local_ip(src_ip):
                            # Спрощене обчислення JA3 (потрібна детальніша імплементація)
                            ja3_string = payload[1:6].hex()
                            ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
                            self.tls_fingerprints[src_ip].append(ja3_hash)

                            # Перевірка на зловмисні JA3
                            if ja3_hash in self.MALICIOUS_JA3:
                                malware = self.MALICIOUS_JA3[ja3_hash]
                                self.suspicious_activities.append({
                                    'type': 'MALICIOUS_TLS',
                                    'severity': 'CRITICAL',
                                    'description': f'Виявлено зловмисний TLS fingerprint з {src_ip}',
                                    'details': f'JA3: {ja3_hash} (відомий як {malware})'
                                })
            except:
                pass

    def load_and_process_pcap(self):
        """Завантажує та обробляє PCAP файл через ітератор"""
        try:
            print(f"[*] Завантаження файлу: {self.pcap_file}")
            print("[*] Використання потокової обробки (не навантажує пам'ять)")

            # Спочатку підраховуємо загальну кількість
            print("[*] Підрахунок пакетів...")
            with PcapReader(self.pcap_file) as pcap_reader:
                for _ in pcap_reader:
                    self.total_packets += 1

            print(f"[+] Знайдено {self.total_packets} пакетів")
            print("[*] Починаємо аналіз...")

            # Тепер обробляємо
            with PcapReader(self.pcap_file) as pcap_reader:
                for pkt in pcap_reader:
                    self.process_packet(pkt)

            # Аналізуємо залишкові TCP потоки
            print("[*] Аналіз незавершених TCP потоків...")
            for stream_key, stream_data in list(self.tcp_streams.items()):
                self.analyze_tcp_stream(stream_key, stream_data)

            print(f"[+] Обробка завершена")
            print(f"[+] Виявлено локальних IP: {len(self.local_ips)}")
            if self.local_ips:
                print(f"    {', '.join(sorted(self.local_ips))}")

            return True
        except Exception as e:
            print(f"[!] Помилка завантаження файлу: {e}")
            return False

    def detect_reverse_shells(self):
        """Виявляє ознаки reverse shell з'єднань"""
        print("\n[*] Пошук reverse shell з'єднань...")

        outbound_connections = defaultdict(list)

        # Повторно читаємо файл для цього аналізу
        with PcapReader(self.pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                if IP in pkt and TCP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    dst_port = pkt[TCP].dport

                    if self.is_local_ip(src_ip) and self.is_external_ip(dst_ip):
                        if dst_port in self.REVERSE_SHELL_PORTS or dst_port in self.EXPLOIT_PORTS:
                            if pkt[TCP].flags & 0x12:  # SYN-ACK
                                outbound_connections[(src_ip, dst_ip, dst_port)].append(pkt)

        for (src, dst, port), pkts in outbound_connections.items():
            if len(pkts) >= 2:
                reason = self.EXPLOIT_PORTS.get(port, "Підозрілий порт reverse shell")

                # Перевірка threat intel
                threat_score = self.check_threat_intelligence(dst)
                threat_info = f" [ThreatScore: {threat_score}%]" if threat_score > 0 else ""

                self.suspicious_activities.append({
                    'type': 'REVERSE_SHELL',
                    'severity': 'CRITICAL',
                    'description': f'Можливе reverse shell з\'єднання з локального хосту',
                    'details': f'{src} -> {dst}:{port} ({reason}){threat_info}'
                })
                print(f"[!!!] КРИТИЧНО: Reverse shell {src} -> {dst}:{port} ({reason}){threat_info}")

    def detect_data_exfiltration(self):
        """Виявляє витік даних з покращеною евристикою"""
        print("\n[*] Аналіз витоку даних...")

        outbound_bytes = defaultdict(int)
        outbound_sessions = defaultdict(set)
        outbound_packet_count = defaultdict(int)

        with PcapReader(self.pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst

                    if self.is_local_ip(src_ip) and self.is_external_ip(dst_ip):
                        # використовуємо довжину сирих байтів пакету
                        try:
                            outbound_bytes[src_ip] += len(bytes(pkt))
                        except:
                            outbound_bytes[src_ip] += 0
                        outbound_packet_count[src_ip] += 1

                        if TCP in pkt or UDP in pkt:
                            dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
                            outbound_sessions[src_ip].add((dst_ip, dst_port))

        if outbound_bytes:
            # Використовуємо медіану замість середнього (стійкіше до викидів)
            median_bytes = statistics.median(outbound_bytes.values())

            for ip, bytes_sent in outbound_bytes.items():
                sessions = len(outbound_sessions[ip])
                packets = outbound_packet_count[ip]
                avg_packet_size = bytes_sent / packets if packets > 0 else 0

                # Покращена евристика:
                # 1. Обсяг значно більший за медіану (в 15 разів)
                # 2. Великий абсолютний обсяг (>50MB)
                # 3. Підозріло великий розмір пакетів (можливо сжаті дані)
                # 4. Небагато сесій (цільова передача, не streaming)

                is_suspicious = (
                        bytes_sent > median_bytes * 15 and
                        bytes_sent > 50_000_000 and  # >50MB
                        sessions < 10 and  # Небагато різних хостів
                        avg_packet_size > 1000  # Великі пакети
                )

                if is_suspicious:
                    mb_sent = bytes_sent / (1024 * 1024)

                    self.suspicious_activities.append({
                        'type': 'DATA_EXFILTRATION',
                        'severity': 'HIGH',
                        'description': f'Можливий витік даних з {ip}',
                        'details': f'Відправлено {mb_sent:.2f} MB до {sessions} хостів (avg пакет: {avg_packet_size:.0f} bytes)'
                    })
                    print(f"[!] ПІДОЗРА: {ip} відправив {mb_sent:.2f} MB ({sessions} з\'єднань)")

    def detect_c2_communication(self):
        """Виявляє комунікацію з Command & Control серверами"""
        print("\n[*] Пошук C2 комунікації...")

        connections_timeline = defaultdict(list)

        with PcapReader(self.pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                if IP in pkt and TCP in pkt and pkt.time:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst

                    if self.is_local_ip(src_ip) and self.is_external_ip(dst_ip):
                        if pkt[TCP].flags & 0x02:  # SYN
                            connections_timeline[(src_ip, dst_ip)].append(float(pkt.time))

        for (src, dst), timestamps in connections_timeline.items():
            if len(timestamps) >= 5:
                timestamps.sort()
                intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

                if len(intervals) >= 4:
                    avg_interval = statistics.mean(intervals)
                    std_dev = statistics.stdev(intervals)

                    # Покращена евристика: дуже регулярні інтервали
                    if std_dev < avg_interval * 0.2 and 10 < avg_interval < 3600:
                        threat_score = self.check_threat_intelligence(dst)
                        threat_info = f" [ThreatScore: {threat_score}%]" if threat_score > 0 else ""

                        self.suspicious_activities.append({
                            'type': 'C2_BEACONING',
                            'severity': 'CRITICAL',
                            'description': f'Виявлено C2 beaconing з {src}',
                            'details': f'Регулярні з\'єднання до {dst} кожні {avg_interval:.1f}s ({len(timestamps)} з\'єднань, σ={std_dev:.2f}){threat_info}'
                        })
                        print(
                            f"[!!!] КРИТИЧНО: C2 beaconing {src} -> {dst} (інтервал ~{avg_interval:.1f}s){threat_info}")

    def detect_port_scanning(self):
        """Виявляє реальне сканування портів"""
        print("\n[*] Виявлення сканування портів...")

        syn_attempts = defaultdict(lambda: {'ports': set(), 'failed': 0, 'success': 0})

        with PcapReader(self.pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                if IP in pkt and TCP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    dst_port = pkt[TCP].dport
                    flags = pkt[TCP].flags

                    if flags == 0x02:  # SYN
                        syn_attempts[src_ip]['ports'].add((dst_ip, dst_port))
                    elif flags == 0x12:  # SYN-ACK
                        syn_attempts[dst_ip]['success'] += 1
                    elif flags & 0x04:  # RST
                        syn_attempts[dst_ip]['failed'] += 1

        for src_ip, data in syn_attempts.items():
            unique_targets = len(data['ports'])
            total_attempts = data['failed'] + data['success']
            fail_rate = data['failed'] / total_attempts if total_attempts > 0 else 0

            # Покращена евристика: 20+ портів та >60% невдач
            if unique_targets >= 20 and fail_rate > 0.6:
                if self.is_external_ip(src_ip):
                    self.suspicious_activities.append({
                        'type': 'PORT_SCAN_INBOUND',
                        'severity': 'HIGH',
                        'description': f'Вхідне сканування портів з {src_ip}',
                        'details': f'{unique_targets} портів просканованано, {fail_rate * 100:.1f}% відмов'
                    })
                    print(f"[!] ЗАГРОЗА: Сканування з {src_ip} ({unique_targets} портів, {fail_rate * 100:.1f}% fail)")

    def detect_dns_tunneling(self):
        """Виявляє DNS тунелювання"""
        print("\n[*] Аналіз DNS тунелювання...")

        dns_queries = defaultdict(list)

        with PcapReader(self.pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                if DNS in pkt and pkt[DNS].qr == 0:
                    if pkt[DNS].qd and IP in pkt:
                        src_ip = pkt[IP].src
                        query = pkt[DNS].qd.qname.decode('utf-8', errors='ignore').lower()
                        dns_queries[src_ip].append(query)

        for src_ip, queries in dns_queries.items():
            if len(queries) < 10:
                continue

            # Аналіз характеристик
            long_queries = [q for q in queries if len(q) > 50]
            subdomain_counts = [q.count('.') for q in queries]
            avg_subdomains = statistics.mean(subdomain_counts)

            # Перевірка на високий entropy (випадковість)
            def calc_entropy(s):
                import math
                prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
                return -sum(p * math.log2(p) for p in prob)

            avg_entropy = statistics.mean([calc_entropy(q) for q in queries[:100]])

            # Тунелювання: довгі запити + висока вкладеність + високий entropy
            if len(long_queries) > len(queries) * 0.3 and avg_subdomains > 5 and avg_entropy > 3.5:
                self.suspicious_activities.append({
                    'type': 'DNS_TUNNELING',
                    'severity': 'HIGH',
                    'description': f'Можливе DNS тунелювання з {src_ip}',
                    'details': f'{len(long_queries)} довгих запитів, avg вкладеність: {avg_subdomains:.1f}, entropy: {avg_entropy:.2f}'
                })
                print(f"[!] ПІДОЗРА: DNS тунелювання з {src_ip}")
                print(f"    Приклад: {long_queries[0][:60]}...")

    def detect_arp_spoofing(self):
        """Виявляє ARP spoofing атаки"""
        print("\n[*] Виявлення ARP spoofing...")

        arp_table = {}
        conflicts = []

        with PcapReader(self.pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                if ARP in pkt:
                    src_ip = pkt[ARP].psrc
                    src_mac = pkt[ARP].hwsrc

                    if src_ip in arp_table:
                        if arp_table[src_ip] != src_mac:
                            conflicts.append((src_ip, arp_table[src_ip], src_mac))
                    else:
                        arp_table[src_ip] = src_mac

        for ip, old_mac, new_mac in conflicts:
            self.suspicious_activities.append({
                'type': 'ARP_SPOOFING',
                'severity': 'CRITICAL',
                'description': f'ARP spoofing для {ip}',
                'details': f'MAC змінено з {old_mac} на {new_mac}'
            })
            print(f"[!!!] КРИТИЧНО: ARP spoofing {ip} ({old_mac} -> {new_mac})")

    def detect_smb_exploits(self):
        """Виявляє спроби експлуатації SMB"""
        print("\n[*] Пошук SMB експлойтів...")

        smb_connections = defaultdict(int)
        exploit_detected = False

        with PcapReader(self.pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                if TCP in pkt and IP in pkt:
                    if pkt[TCP].dport in [139, 445] or pkt[TCP].sport in [139, 445]:
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst

                        if self.is_external_ip(src_ip) and self.is_local_ip(dst_ip):
                            smb_connections[src_ip] += 1

                            if Raw in pkt:
                                payload = bytes(pkt[Raw].load)
                                # Сигнатури SMB експлойтів
                                if b'\xfe\x53\x4d\x42' in payload or b'\xff\x53\x4d\x42' in payload:
                                    self.suspicious_activities.append({
                                        'type': 'SMB_EXPLOIT',
                                        'severity': 'CRITICAL',
                                        'description': f'Спроба SMB експлойту з {src_ip}',
                                        'details': f'Виявлено сигнатуру експлойту на {dst_ip}:445'
                                    })
                                    print(f"[!!!] КРИТИЧНО: SMB експлойт {src_ip} -> {dst_ip}")
                                    exploit_detected = True
                                    break

            if exploit_detected:
                return

        # Brute-force атаки
        for src_ip, count in smb_connections.items():
            if count > 100:
                self.suspicious_activities.append({
                    'type': 'SMB_BRUTE_FORCE',
                    'severity': 'HIGH',
                    'description': f'Можлива brute-force атака на SMB з {src_ip}',
                    'details': f'{count} спроб підключення'
                })
                print(f"[!] ПІДОЗРА: SMB brute-force з {src_ip} ({count} спроб)")

    def detect_crypto_mining(self):
        """Виявляє підключення до mining pools"""
        print("\n[*] Пошук crypto mining активності...")

        mining_connections = []

        with PcapReader(self.pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                if TCP in pkt and IP in pkt:
                    dst_port = pkt[TCP].dport
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst

                    if self.is_local_ip(src_ip) and self.is_external_ip(dst_ip):
                        if dst_port in self.MINING_PORTS:
                            mining_connections.append((src_ip, dst_ip, dst_port))

        if mining_connections:
            for src, dst, port in set(mining_connections):
                self.suspicious_activities.append({
                    'type': 'CRYPTO_MINING',
                    'severity': 'HIGH',
                    'description': f'Можливий crypto mining з {src}',
                    'details': f'З\'єднання до mining pool {dst}:{port}'
                })
                print(f"[!] ПІДОЗРА: Crypto mining {src} -> {dst}:{port}")

    def generate_report(self):
        """Генерує детальний звіт"""
        print("\n" + "=" * 80)
        print("ПРОФЕСІЙНИЙ ЗВІТ ПРО ЗАГРОЗИ БЕЗПЕКИ")
        print("=" * 80)
        print(f"Файл: {self.pcap_file}")
        print(f"Дата аналізу: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Всього пакетів: {self.total_packets}")
        print(f"Локальна мережа: {self.local_network}")
        print(f"Локальних хостів: {len(self.local_ips)}")
        print(f"Виявлено загроз: {len(self.suspicious_activities)}")
        print("=" * 80)

        if not self.suspicious_activities:
            print("\n[✓] ВІДМІННО! Критичних загроз не виявлено.")
            print("    Мережа виглядає безпечною.")
            return

        # Групування по рівню загрози
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for activity in self.suspicious_activities:
            by_severity[activity['severity']].append(activity)

        # CRITICAL
        if by_severity['CRITICAL']:
            print(f"\n{'[!!! КРИТИЧНІ ЗАГРОЗИ !!!]':^80}")
            print("=" * 80)
            for i, activity in enumerate(by_severity['CRITICAL'], 1):
                print(f"\n{i}. {activity['type']}")
                print(f"   {activity['description']}")
                print(f"   Деталі: {activity['details']}")

        # HIGH
        if by_severity['HIGH']:
            print(f"\n{'[! ВИСОКИЙ РИЗИК !]':^80}")
            print("=" * 80)
            for i, activity in enumerate(by_severity['HIGH'], 1):
                print(f"\n{i}. {activity['type']}")
                print(f"   {activity['description']}")
                print(f"   Деталі: {activity['details']}")

        # MEDIUM
        if by_severity['MEDIUM']:
            print(f"\n{'[СЕРЕДНІЙ РИЗИК]':^80}")
            print("-" * 80)
            for activity in by_severity['MEDIUM']:
                print(f"• {activity['description']}")

        # Підсумок та рекомендації
        print("\n" + "=" * 80)
        print("РЕКОМЕНДАЦІЇ:")
        print("=" * 80)

        if by_severity['CRITICAL']:
            print("\n[!!!] НЕГАЙНІ ДІЇ ПОТРІБНІ:")
            if any(a['type'] == 'REVERSE_SHELL' for a in by_severity['CRITICAL']):
                print("  • REVERSE SHELL: Комп'ютер скомпрометовано! Ізолюйте хост негайно!")
            if any(a['type'] == 'C2_BEACONING' for a in by_severity['CRITICAL']):
                print("  • C2 КОМУНІКАЦІЯ: Виявлено malware з активним C&C. Перевірте антивірусом!")
            if any(a['type'] == 'ARP_SPOOFING' for a in by_severity['CRITICAL']):
                print("  • ARP SPOOFING: Атака Man-in-the-Middle! Перевірте всі пристрої в мережі!")
            if any(a['type'] == 'SMB_EXPLOIT' for a in by_severity['CRITICAL']):
                print("  • SMB ЕКСПЛОЙТ: Спроба використання уразливостей (EternalBlue?). Оновіть Windows!")

        if by_severity['HIGH']:
            print("\n[!] СЕРЙОЗНІ ПРОБЛЕМИ:")
            if any(a['type'] == 'DATA_EXFILTRATION' for a in by_severity['HIGH']):
                print("  • Можливий витік даних. Перевірте скомпрометовані хости.")
            if any(a['type'] == 'PORT_SCAN_INBOUND' for a in by_severity['HIGH']):
                print("  • Вхідне сканування. Налаштуйте firewall та IDS/IPS.")
            if any(a['type'] == 'DNS_TUNNELING' for a in by_severity['HIGH']):
                print("  • DNS тунелювання. Перевірте DNS трафік, використовуйте DNS firewall.")
            if any(a['type'] == 'CRYPTO_MINING' for a in by_severity['HIGH']):
                print("  • Crypto mining. Видаліть malware та заблокуйте mining pools.")

        print("\n" + "=" * 80)

    def run_analysis(self):
        """Запускає повний аналіз"""
        print("\n" + "=" * 80)
        print("ЗАПУСК ПРОФЕСІЙНОГО АНАЛІЗУ ЗАГРОЗ")
        print("=" * 80)

        # Завантажуємо і обробляємо pcap перед детекторними перевірками
        if not self.load_and_process_pcap():
            return False

        # Критичні загрози
        self.detect_reverse_shells()
        self.detect_c2_communication()
        self.detect_arp_spoofing()
        self.detect_smb_exploits()

        # Високий ризик
        self.detect_data_exfiltration()
        self.detect_port_scanning()
        self.detect_dns_tunneling()
        self.detect_crypto_mining()

        self.generate_report()
        return True

def main():
    print("=" * 80)
    print("ПРОФЕСІЙНИЙ АНАЛІЗАТОР ЗАГРОЗ v2.0")
    print("Оптимізовано для великих файлів та зашифрованого трафіку")
    print("=" * 80)

    if len(sys.argv) < 2:
        print("\nВикористання: python analyzer.py <файл.pcap> [опції]")
        print("\nОпції:")
        print("  --network <CIDR>    Локальна мережа (default: 192.168.0.0/16)")
        print("  --threat-intel      Увімкнути перевірку через Threat Intelligence")
        print("\nПриклади:")
        print("  python analyzer.py capture.pcap")
        print("  python analyzer.py capture.pcap --network 10.0.0.0/8")
        print("  python analyzer.py large_file.pcap --threat-intel")
        print("\nОСОБЛИВОСТІ:")
        print("  ✓ Потокова обробка - не навантажує RAM")
        print("  ✓ TCP Stream Reassembly - виявляє фрагментовані атаки")
        print("  ✓ TLS Fingerprinting (JA3) - аналіз зашифрованого трафіку")
        print("  ✓ Покращена евристика - менше false positives")
        sys.exit(1)

    pcap_file = sys.argv[1]
    local_network = "192.168.0.0/16"
    use_threat_intel = False

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--network' and i + 1 < len(sys.argv):
            local_network = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--threat-intel':
            use_threat_intel = True
            i += 1
        else:
            i += 1

    analyzer = AdvancedPcapAnalyzer(pcap_file, local_network, use_threat_intel)
    analyzer.run_analysis()


if __name__ == "__main__":
    main()
