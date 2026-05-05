import re
import json
import os
import time
import threading
import feedparser
import requests as req
from bs4 import BeautifulSoup
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from ..utils.helpers import load_darkweb_config

breach_intel_bp = Blueprint('breach_intel', __name__)

_INDONESIA_CACHE_FILE = os.path.join(os.getcwd(), 'breach_indonesia_cache.json')
_MARKET_CACHE_FILE    = os.path.join(os.getcwd(), 'breach_market_cache.json')
_CACHE_TTL            = 6 * 3600  # 6 hours

HEADERS = {
    'User-Agent': 'Cybermon/1.0 (Security Intelligence Platform)'
}

# Data class risk scoring — how "valuable" is the data for criminals
DATA_CLASS_RISK = {
    'Passwords':               10,
    'Credit cards':            10,
    'Bank account numbers':    10,
    'Social security numbers': 10,
    'Passport numbers':         9,
    'Auth tokens':              9,
    'Private messages':         8,
    'Financial data':           8,
    'Health records':           8,
    'IP addresses':             6,
    'Phone numbers':            6,
    'Physical addresses':       6,
    'Email addresses':          5,
    'Names':                    4,
    'Usernames':                4,
    'Dates of birth':           5,
    'Government issued IDs':   10,
}

def score_breach(data_classes, pwn_count):
    """Score a breach by data sensitivity + scale."""
    class_score = sum(DATA_CLASS_RISK.get(dc, 3) for dc in data_classes)
    size_bonus  = min(pwn_count // 1_000_000, 20)  # up to +20 for massive breaches
    return class_score + size_bonus

def risk_label(score):
    if score >= 30: return 'CRITICAL'
    if score >= 20: return 'HIGH'
    if score >= 10: return 'MEDIUM'
    return 'LOW'

def classify_post(title, summary=''):
    combined = (title + ' ' + summary).lower()
    if any(k in combined for k in ['ransomware', 'encrypt', 'ransom', 'lockbit', 'blackcat', 'akira', 'qilin']): return 'RANSOMWARE'
    if any(k in combined for k in ['breach', 'leaked', 'database', 'dump', 'exposed', 'million records', 'data theft']): return 'BREACH'
    if any(k in combined for k in ['malware', 'trojan', 'rat ', 'stealer', 'infostealer', 'botnet', 'backdoor']): return 'MALWARE'
    if any(k in combined for k in ['apt', 'nation-state', 'chinese', 'russian', 'north korea', 'iranian']): return 'APT'
    if any(k in combined for k in ['phishing', 'credential', 'spoofing', 'smishing', 'vishing']): return 'PHISHING'
    if any(k in combined for k in ['cve', 'vulnerability', 'exploit', 'rce', 'zero-day', '0-day', 'patch']): return 'EXPLOIT'
    if any(k in combined for k in ['ddos', 'disruption', 'outage', 'takedown', 'infrastructure']): return 'DISRUPTION'
    return 'INTEL'

def fetch_rss_feed(url, limit=25):
    feed = feedparser.parse(url)
    results = []
    for entry in feed.entries[:limit]:
        title   = entry.get('title', '')
        summary = BeautifulSoup(entry.get('summary', ''), 'html.parser').get_text()[:300]
        link    = entry.get('link', '')
        date    = entry.get('published', entry.get('updated', ''))
        results.append({
            'title':   title,
            'summary': summary,
            'link':    link,
            'date':    date,
            'tag':     classify_post(title, summary),
        })
    return results


# ─── Curated Indonesian Breach Incidents ───────────────────────────────────────
# Documented major incidents not fully covered by HIBP — sourced from credible reports
INDONESIA_INCIDENTS = [
    {
        'id': 'pemda-jaksel-2025',
        'title': 'Pemda Jakarta Selatan',
        'org_type': 'Pemerintah Daerah',
        'date': '2025-02',
        'attacker': 'Unknown / Dark Web Forum',
        'attack_type': 'BREACH',
        'impact': 'Kebocoran data 7,5 juta catatan dari basis data pemerintah kota administratif Jakarta Selatan yang dijual di forum peretas',
        'records': '~7.500.000 records',
        'ransom': None,
        'risk': 'HIGH',
        'ref': 'https://cyberpress.org/',
        'tags': ['Government', 'Data Leak', 'Pemda'],
        'sector': 'Pemerintahan Daerah',
    },
    {
        'id': 'yogya-citizen-2026',
        'title': 'Database Warga Yogyakarta',
        'org_type': 'Pemerintah Daerah / Kependudukan',
        'date': '2026-05',
        'attacker': 'DailyDarkWeb (X) / Underground Forum',
        'attack_type': 'BREACH',
        'impact': 'Kebocoran data kependudukan warga Yogyakarta yang diklaim berisi NIK, Nama Lengkap, Tanggal Lahir, dan Nomor Telepon.',
        'records': 'Unknown / Large Scale',
        'ransom': None,
        'risk': 'CRITICAL',
        'ref': 'https://jogjapolitan.harianjogja.com/read/2026/05/01/510/1173000/data-penduduk-yogya-diduga-bocor-kominfo-diy-sebut-data-pusat-yang-diolah',
        'tags': ['Yogyakarta', 'Kependudukan', 'NIK', 'Darkweb Alert'],
        'sector': 'Pemerintahan Daerah',
    },
    {
        'id': 'ksp-2024',
        'title': 'KSP (Kantor Staf Presiden)',
        'org_type': 'Pemerintah',
        'date': '2024-10',
        'attacker': 'Unknown',
        'attack_type': 'BREACH',
        'impact': 'Dugaan peretasan dan kebocoran data staf KSP. Pihak istana berkoordinasi dengan BSSN untuk mitigasi.',
        'records': 'Data Staf & Internal',
        'ransom': None,
        'risk': 'HIGH',
        'ref': 'https://nasional.tempo.co/',
        'tags': ['Government', 'KSP', 'Internal Data'],
        'sector': 'Pemerintahan Pusat',
    },
    {
        'id': 'npwp-2024',
        'title': 'Ditjen Pajak Kemenkeu (Data NPWP)',
        'org_type': 'Pemerintah',
        'date': '2024-09',
        'attacker': 'Bjorka',
        'attack_type': 'BREACH',
        'impact': 'Sebanyak 6 juta data NPWP, termasuk milik Presiden dan pejabat tinggi negara, dijual di BreachForums seharga $10k.',
        'records': '6.000.000 records',
        'ransom': 'USD 10.000',
        'risk': 'CRITICAL',
        'ref': 'https://nasional.tempo.co/',
        'tags': ['Tax', 'Government', 'NPWP', 'Kemenkeu', 'Bjorka'],
        'sector': 'Perpajakan & Keuangan Negara',
    },
    {
        'id': 'bkn-2024',
        'title': 'BKN (Badan Kepegawaian Negara)',
        'org_type': 'Pemerintah',
        'date': '2024-08',
        'attacker': 'Topatork',
        'attack_type': 'BREACH',
        'impact': 'Kebocoran data milik 4,7 juta ASN (Aparatur Sipil Negara) yang dijual seharga $10k di BreachForums.',
        'records': '4.759.218 records',
        'ransom': 'USD 10.000',
        'risk': 'CRITICAL',
        'ref': 'https://nasional.tempo.co/',
        'tags': ['ASN', 'Government', 'BKN', 'PII'],
        'sector': 'Kepegawaian Negara',
    },
    {
        'id': 'pdns-2024',
        'title': 'PDNS (Pusat Data Nasional Sementara)',
        'org_type': 'Pemerintah',
        'date': '2024-06',
        'attacker': 'Brain Cipher (LockBit Variant)',
        'attack_type': 'RANSOMWARE',
        'impact': '282 lembaga pemerintah terdampak, data migrasi & layanan publik lumpuh',
        'records': '~210 GB data terenkripsi',
        'ransom': 'USD 8 juta (~Rp 131 miliar)',
        'risk': 'CRITICAL',
        'ref': 'https://www.antaranews.com/berita/4166295/kronologi-gangguan-pusat-data-nasional-akibat-serangan-ransomware',
        'tags': ['Ransomware', 'Government', 'Infrastructure'],
        'sector': 'Infrastruktur Nasional',
    },
    {
        'id': 'kpu-2023',
        'title': 'KPU RI (Komisi Pemilihan Umum)',
        'org_type': 'Pemerintah',
        'date': '2023-11',
        'attacker': 'Jimbo',
        'attack_type': 'BREACH',
        'impact': '204 juta data pemilih Indonesia bocor dan dijual di BreachForums',
        'records': '204.807.203 records',
        'ransom': 'USD 74.000',
        'risk': 'CRITICAL',
        'ref': 'https://cyberthreat.id/read/17085/data-204-juta-DPT-KPU-bocor',
        'tags': ['Election Data', 'Government', 'NIK', 'KTP'],
        'sector': 'Pemilu & Politik',
    },
    {
        'id': 'bsi-2023',
        'title': 'BSI (Bank Syariah Indonesia)',
        'org_type': 'BUMN',
        'date': '2023-05',
        'attacker': 'LockBit 3.0',
        'attack_type': 'RANSOMWARE',
        'impact': '1.5 TB data nasabah & karyawan, layanan ATM & mobile banking down 5 hari',
        'records': '~15 juta data nasabah',
        'ransom': 'USD 20 juta',
        'risk': 'CRITICAL',
        'ref': 'https://cyberthreat.id/read/16498/BSI-Diserang-LockBit',
        'tags': ['Ransomware', 'Banking', 'Financial', 'BUMN'],
        'sector': 'Perbankan',
    },
    {
        'id': 'kominfo-paspor-2023',
        'title': 'Kominfo — Data Paspor WNI',
        'org_type': 'Pemerintah',
        'date': '2023-07',
        'attacker': 'MoonzHaxor',
        'attack_type': 'BREACH',
        'impact': '34 juta data paspor WNI bocor dan dijual seharga ~USD 10.000',
        'records': '34.900.867 records',
        'ransom': 'USD 10.000',
        'risk': 'CRITICAL',
        'ref': 'https://www.cnbcindonesia.com/tech/20230710165800-37-453419',
        'tags': ['Passport', 'Government', 'PII', 'NIK'],
        'sector': 'Telekomunikasi & TI',
    },
    {
        'id': 'bpjs-2021',
        'title': 'BPJS Kesehatan',
        'org_type': 'BUMN',
        'date': '2021-05',
        'attacker': 'Unknown',
        'attack_type': 'BREACH',
        'impact': '279 juta data peserta bocor termasuk data penduduk meninggal, dijual di Raidforums',
        'records': '279.000.000 records',
        'ransom': 'USD 3.800 (6 BTC)',
        'risk': 'CRITICAL',
        'ref': 'https://cyberthreat.id/read/8892/Diduga-Data-BPJS-Kesehatan-Bocor',
        'tags': ['Healthcare', 'NIK', 'Government', 'PII'],
        'sector': 'Kesehatan',
    },
    {
        'id': 'pln-2022',
        'title': 'PLN (Perusahaan Listrik Negara)',
        'org_type': 'BUMN',
        'date': '2022-08',
        'attacker': 'Unknown',
        'attack_type': 'BREACH',
        'impact': 'Data 17 juta pelanggan & karyawan bocor, dijual di forum dark web',
        'records': '~17.000.000 records',
        'ransom': None,
        'risk': 'HIGH',
        'ref': 'https://cyberthreat.id/read/13721/Data-17-Juta-Pelanggan-PLN-Bocor',
        'tags': ['Energy', 'BUMN', 'Infrastructure', 'PII'],
        'sector': 'Energi & Infrastruktur',
    },
    {
        'id': 'bi-2022',
        'title': 'Bank Indonesia',
        'org_type': 'Pemerintah',
        'date': '2022-01',
        'attacker': 'Conti Ransomware Group',
        'attack_type': 'RANSOMWARE',
        'impact': '74 GB data dicuri dan dipublikasikan, termasuk data karyawan & dokumen internal',
        'records': '74 GB data',
        'ransom': 'Unknown',
        'risk': 'CRITICAL',
        'ref': 'https://www.cnbcindonesia.com/tech/20220123090155-37-309474',
        'tags': ['Ransomware', 'Central Bank', 'Financial', 'Government'],
        'sector': 'Perbankan & Moneter',
    },
    {
        'id': 'polri-2021',
        'title': 'Polri (Kepolisian Republik Indonesia)',
        'org_type': 'Pemerintah',
        'date': '2021-08',
        'attacker': 'Unknown',
        'attack_type': 'BREACH',
        'impact': 'Data pribadi perwira & personel Polri bocor termasuk nama, pangkat, NRP, dan alamat',
        'records': '~28.000 records personel',
        'ransom': None,
        'risk': 'HIGH',
        'ref': 'https://cyberthreat.id/read/10049/Data-Anggota-Polri-Bocor',
        'tags': ['Law Enforcement', 'Government', 'PII'],
        'sector': 'Penegakan Hukum',
    },
    {
        'id': 'bssn-2021',
        'title': 'BSSN (Badan Siber dan Sandi Negara)',
        'org_type': 'Pemerintah',
        'date': '2021-10',
        'attacker': 'Bjorka',
        'attack_type': 'BREACH',
        'impact': 'Website BSSN dideface dan data internal bocor — ironis karena BSSN adalah lembaga keamanan siber',
        'records': 'Classified documents',
        'ransom': None,
        'risk': 'CRITICAL',
        'ref': 'https://cyberthreat.id/read/11050/Website-BSSN-Dideface',
        'tags': ['Government', 'Cybersecurity Agency', 'Defacement'],
        'sector': 'Keamanan Siber',
    },
    {
        'id': 'indihome-2023',
        'title': 'IndiHome (Telkom Indonesia)',
        'org_type': 'BUMN',
        'date': '2023-08',
        'attacker': 'Unknown',
        'attack_type': 'BREACH',
        'impact': 'Riwayat browsing & data pribadi 26 juta pengguna bocor, termasuk data orang tua & anak',
        'records': '26.000.000 records + 1.7 miliar data browsing',
        'ransom': None,
        'risk': 'HIGH',
        'ref': 'https://cyberthreat.id/read/17020/indihome-breach',
        'tags': ['Telco', 'ISP', 'Browsing History', 'PII'],
        'sector': 'Telekomunikasi',
    },
    {
        'id': 'dukcapil-2023',
        'title': 'Dukcapil (Ditjen Kependudukan)',
        'org_type': 'Pemerintah',
        'date': '2023-07',
        'attacker': 'RaihanCyber01',
        'attack_type': 'BREACH',
        'impact': '337 juta data kependudukan Indonesia bocor — terbesar dalam sejarah RI',
        'records': '337.000.000 records',
        'ransom': None,
        'risk': 'CRITICAL',
        'ref': 'https://cyberthreat.id/read/16853/Data-337-Juta-Penduduk-Indonesia-Bocor',
        'tags': ['NIK', 'KTP', 'Government', 'Population Data'],
        'sector': 'Kependudukan',
    },
    {
        'id': 'garuda-2021',
        'title': 'Garuda Indonesia',
        'org_type': 'BUMN',
        'date': '2021-03',
        'attacker': 'Conti Ransomware Group',
        'attack_type': 'RANSOMWARE',
        'impact': '193 GB data dicuri termasuk 1.3 juta data penumpang, data karyawan & dokumen internal, dipublikasikan di blog Conti',
        'records': '1.3 juta data penumpang + data karyawan (~193 GB)',
        'ransom': None,
        'risk': 'CRITICAL',
        'ref': 'https://cyberthreat.id/read/8049/Garuda-Indonesia-Diserang-Ransomware-Conti',
        'tags': ['Ransomware', 'Conti', 'Aviation', 'BUMN', 'Passenger Data'],
        'sector': 'Penerbangan',
    },
    {
        'id': 'brilife-2021',
        'title': 'BRI Life (PT BRI Asuransi Indonesia)',
        'org_type': 'BUMN',
        'date': '2021-07',
        'attacker': 'Bjorka',
        'attack_type': 'BREACH',
        'impact': '2 juta data nasabah asuransi bocor termasuk KTP, dokumen keuangan, dan 463.000 dokumen sensitif dijual seharga USD 7.000',
        'records': '2.000.000 records nasabah + 463.000 dokumen',
        'ransom': 'USD 7.000',
        'risk': 'CRITICAL',
        'ref': 'https://cyberthreat.id/read/9754/Data-Nasabah-BRI-Life-Bocor',
        'tags': ['Bjorka', 'Insurance', 'BUMN', 'KTP', 'Financial', 'PII'],
        'sector': 'Asuransi',
    },
    {
        'id': 'bjorka-2022',
        'title': 'Bjorka Campaign — Multi-Target Gov',
        'org_type': 'Pemerintah',
        'date': '2022-09',
        'attacker': 'Bjorka',
        'attack_type': 'BREACH',
        'impact': 'Serangkaian serangan pada Sept 2022: data Kominfo, korespondensi Presiden ke BIN, data anggota DPR RI, dan informasi pejabat negara',
        'records': 'Kominfo (44 juta records) + dokumen rahasia negara',
        'ransom': None,
        'risk': 'CRITICAL',
        'ref': 'https://cyberthreat.id/read/13574/Bjorka-Bocorkan-Data-Presiden',
        'tags': ['Bjorka', 'Government', 'Multi-Target', 'Kominfo', 'DPR', 'BIN'],
        'sector': 'Multi-Sektor Pemerintahan',
    },
    {
        'id': 'kai-2023',
        'title': 'KAI (PT Kereta Api Indonesia)',
        'org_type': 'BUMN',
        'date': '2023-01',
        'attacker': 'Stormous',
        'attack_type': 'RANSOMWARE',
        'impact': 'Lebih dari 3 juta data penumpang kereta api bocor termasuk nama, NIK, email, dan nomor telepon',
        'records': '~3.500.000 records penumpang',
        'ransom': None,
        'risk': 'HIGH',
        'ref': 'https://cyberthreat.id/read/15085/Data-Penumpang-KAI-Bocor',
        'tags': ['Ransomware', 'Stormous', 'Transportation', 'BUMN', 'PII'],
        'sector': 'Transportasi',
    },
    {
        'id': 'djp-2023',
        'title': 'DJP (Direktorat Jenderal Pajak)',
        'org_type': 'Pemerintah',
        'date': '2023-05',
        'attacker': 'Unknown',
        'attack_type': 'BREACH',
        'impact': 'Data wajib pajak & SPT bocor termasuk data pajak pejabat tinggi negara, dijual di forum dark web',
        'records': 'Data tax return & NPWP wajib pajak',
        'ransom': None,
        'risk': 'HIGH',
        'ref': 'https://cyberthreat.id/read/16490/Data-DJP-Bocor',
        'tags': ['Tax Data', 'Government', 'NPWP', 'Financial', 'KEMENKEU'],
        'sector': 'Perpajakan',
    },
    {
        'id': 'ojk-2023',
        'title': 'OJK (Otoritas Jasa Keuangan)',
        'org_type': 'Pemerintah',
        'date': '2023-10',
        'attacker': 'Bjorka',
        'attack_type': 'BREACH',
        'impact': 'Dokumen internal, data pegawai, dan data industri jasa keuangan yang diregulasi OJK diklaim bocor',
        'records': 'Dokumen internal & data regulasi keuangan',
        'ransom': None,
        'risk': 'HIGH',
        'ref': 'https://www.cnbcindonesia.com/tech/20231031102917-37-485121/layanan-ojk-gangguan-diduga-kena-serangan-ransomware',
        'tags': ['Financial Regulator', 'Government', 'Ransomware', 'Internal Documents'],
        'sector': 'Regulasi Keuangan',
    },
    {
        'id': 'kpmg-2025',
        'title': 'KPMG Indonesia',
        'org_type': 'Swasta',
        'date': '2025-03',
        'attacker': 'DragonForce',
        'attack_type': 'RANSOMWARE',
        'impact': 'Data klien & dokumen internal KPMG Indonesia diklaim dicuri dan dipublikasikan di situs leak DragonForce',
        'records': 'Dokumen keuangan & data klien',
        'ransom': None,
        'risk': 'HIGH',
        'ref': 'https://ransomware.live/#/stats',
        'tags': ['Ransomware', 'DragonForce', 'Consulting', 'Financial'],
        'sector': 'Konsultansi & Audit',
    },
    {
        'id': 'clipan-2025',
        'title': 'Clipan Finance Indonesia (CFIN)',
        'org_type': 'Swasta',
        'date': '2025-04',
        'attacker': 'LockBit 5.0',
        'attack_type': 'RANSOMWARE',
        'impact': 'PT Clipan Finance Indonesia Tbk (CFIN) terkena ransomware LockBit 5.0, manajemen mematikan beberapa sistem kunci',
        'records': 'Data nasabah & dokumen operasional',
        'ransom': None,
        'risk': 'HIGH',
        'ref': 'https://www.idnfinancials.com/news/54205/cfin-experiences-cyberattack-management-shuts-down-several-key-system',
        'tags': ['Ransomware', 'LockBit 5.0', 'Finance', 'Leasing', 'CFIN'],
        'sector': 'Pembiayaan & Leasing',
    },
    {
        'id': 'pedulilindungi-2022',
        'title': 'PeduliLindungi (Kemenkes)',
        'org_type': 'Pemerintah',
        'date': '2022-09',
        'attacker': 'Unknown',
        'attack_type': 'BREACH',
        'impact': 'Data vaksinasi COVID-19 bocor termasuk data Presiden Jokowi',
        'records': '~105 juta records',
        'ransom': None,
        'risk': 'CRITICAL',
        'ref': 'https://cyberthreat.id/read/13849/PeduliLindungi-Bocor',
        'tags': ['Healthcare', 'COVID-19', 'Government', 'Vaccination'],
        'sector': 'Kesehatan',
    },
]

# ─── Routes ────────────────────────────────────────────────────────────────────

@breach_intel_bp.route('/darkweb/breach-intel')
@login_required
def breach_intel():
    return render_template('darkweb_breach_intel.html')


# Synchronized Sector Mapping
SECTOR_MAP = {
    'Keuangan':         ['bank', 'finance', 'crypto', 'pay', 'loan', 'invest', 'trading', 'credit', 'insurance', 'money', 'stock', 'billing', 'accounting', 'wallet', 'currency', 'exchange'],
    'E-commerce':       ['shop', 'store', 'market', 'order', 'delivery', 'food', 'fashion', 'commerce', 'customer', 'retail', 'clothing', 'jewel', 'sneaker', 'shopping', 'grocery'],
    'Hiburan':          ['movie', 'video', 'music', 'entertainment', 'travel', 'hotel', 'booking', 'dating', 'adult', 'lifestyle', 'hobby', 'fitness', 'fan', 'game', 'gaming', 'netflix', 'spotify', 'disney', 'cinema'],
    'Pemerintahan':     ['gov', 'ministry', 'agency', 'council', 'state', 'national', 'police', 'defense', 'military', 'public service', 'politics', 'embassy', 'regulator'],
    'Pendidikan':       ['school', 'univ', 'edu', 'college', 'learn', 'student', 'teacher', 'academy', 'library', 'course', 'scholar'],
    'Kesehatan':        ['health', 'med', 'hospital', 'pharma', 'clinic', 'dentist', 'patient', 'wellness', 'doctor', 'nursing', 'medical'],
    'Logistik':         ['logistics', 'shipping', 'cargo', 'transport', 'courier', 'freight', 'delivery', 'warehouse', 'railway', 'airline', 'transit'],
    'Media':            ['news', 'journal', 'paper', 'broadcast', 'radio', 'tv', 'press', 'magazine', 'publishing', 'media', 'advertising', 'marketing'],
    'Energi':           ['energy', 'oil', 'gas', 'power', 'electric', 'utility', 'solar', 'mining', 'petrol', 'nuclear', 'water service'],
    'Teknologi & IT':   ['tech', 'software', 'hosting', 'internet', 'social', 'network', 'cloud', 'it service', 'forum', 'community', 'ai', 'bot', 'developer', 'github', 'gitlab', 'bitbucket', 'system', 'digital', 'data', 'security']
}

def get_sector(b):
    title = (b.get('title') or '').lower()
    domain = (b.get('domain') or '').lower()
    desc = ' '.join(b.get('data_classes', [])).lower()
    for sector, keywords in SECTOR_MAP.items():
        if any(k in title for k in keywords) or any(k in domain for k in keywords) or any(k in desc for k in keywords):
            return sector
    return 'Lainnya'

def run_breach_market_sync():
    """Core logic to sync global breaches from HIBP."""
    try:
        r = req.get('https://haveibeenpwned.com/api/v3/breaches', headers=HEADERS, timeout=15)
        r.raise_for_status()
        breaches = r.json()
        
        enriched = []
        for b in breaches:
            if b.get('IsSpamList') or b.get('IsMalware'): continue
            data_classes = b.get('DataClasses', [])
            pwn_count    = b.get('PwnCount', 0)
            sc           = score_breach(data_classes, pwn_count)
            
            record = {
                'name':         b.get('Name'),
                'title':        b.get('Title'),
                'domain':       b.get('Domain', ''),
                'breach_date':  b.get('BreachDate', ''),
                'added_date':   b.get('AddedDate', ''),
                'pwn_count':    pwn_count,
                'data_classes': data_classes,
                'risk_score':   sc,
                'risk_label':   risk_label(sc),
                'is_verified':  b.get('IsVerified', False),
                'is_sensitive': b.get('IsSensitive', False),
                'is_stealer':   b.get('IsStealerLog', False),
                'logo':         b.get('LogoPath', ''),
                'has_passwords': 'Passwords' in data_classes,
                'has_cards':     'Credit cards' in data_classes,
            }
            record['sector'] = get_sector(record)
            enriched.append(record)

        # Save to cache
        with open(_MARKET_CACHE_FILE, 'w') as f:
            json.dump(enriched, f)
        return True, len(enriched), None
    except Exception as e:
        return False, 0, str(e)

@breach_intel_bp.route('/darkweb/breach-intel/market')
@login_required
def breach_market():
    """Serve breach database from local cache. Fetch from HIBP only if cache is stale (>6h)."""
    import os, time, json as _json

    sort_by  = request.args.get('sort', 'recent')
    filter_q = request.args.get('q', '').lower()
    page     = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 25, type=int), 100)
    force_refresh = request.args.get('refresh') == '1'

    # Try loading from cache first
    enriched = None
    if not force_refresh and os.path.exists(_MARKET_CACHE_FILE):
        try:
            age = time.time() - os.path.getmtime(_MARKET_CACHE_FILE)
            if age < _CACHE_TTL:
                with open(_MARKET_CACHE_FILE, 'r') as f:
                    enriched = _json.load(f)
        except:
            enriched = None

    # Sync if needed or forced
    if enriched is None:
        success, count, error = run_breach_market_sync()
        if not success:
            # Fallback to existing cache if possible
            if os.path.exists(_MARKET_CACHE_FILE):
                try:
                    with open(_MARKET_CACHE_FILE, 'r') as f: enriched = _json.load(f)
                except: pass
            if not enriched: return jsonify({'status': 'error', 'error': error}), 500
        else:
            # Reload from newly written cache
            try:
                with open(_MARKET_CACHE_FILE, 'r') as f: enriched = _json.load(f)
            except: pass

    # Filter logic: Standard or Sector-based keywords
    if filter_q:
        q_clean = filter_q.strip().lower()
        active_sector = None
        
        # Determine if the query is a specific sector name
        if q_clean == 'lainnya':
            active_sector = 'Lainnya'
        else:
            for s_name in SECTOR_MAP.keys():
                if s_name.lower() == q_clean:
                    active_sector = s_name
                    break
        
        filtered = []
        for b in enriched:
            # Categorize if missing (cached items)
            if not b.get('sector') or b.get('sector') == 'Lainnya':
                b['sector'] = get_sector(b)

            matches = False
            if active_sector:
                # STRICT mode: if searching for a sector (including 'Lainnya'), only show that sector
                if b.get('sector') == active_sector:
                    matches = True
            else:
                # Standard keyword search across all fields
                combined = f"{b.get('title','')} {b.get('domain','')} {' '.join(b.get('data_classes',[]))}".lower()
                if q_clean in combined:
                    matches = True
            
            if matches:
                filtered.append(b)
        enriched = filtered
    else:
        # Categorize all if no filter
        for b in enriched:
            if not b.get('sector') or b.get('sector') == 'Lainnya':
                b['sector'] = get_sector(b)

    # Sort
    if sort_by == 'risk':
        enriched.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
    elif sort_by == 'size':
        enriched.sort(key=lambda x: x.get('pwn_count', 0), reverse=True)
    else:  # recent
        enriched.sort(key=lambda x: x.get('added_date', ''), reverse=True)

    total = len(enriched)
    paged = enriched[(page-1)*per_page : page*per_page]

    return jsonify({
        'status':   'success',
        'total':    total,
        'page':     page,
        'per_page': per_page,
        'results':  paged,
    })

@breach_intel_bp.route('/darkweb/breach-intel/lookup', methods=['POST'])
@login_required
def breach_lookup():
    query = (request.json or {}).get('query', '').strip()
    if not query:
        return jsonify({'error': 'Query required'}), 400

    results = []
    errors  = []

    # --- BreachDirectory.org (free web scrape / RapidAPI if key configured) ---
    try:
        config = load_darkweb_config()
        bd_key = config.get('breachdirectory_api_key', '')

        if bd_key:
            r = req.get(
                'https://breachdirectory.p.rapidapi.com/',
                params={'func': 'auto', 'term': query},
                headers={'X-RapidAPI-Key': bd_key, 'X-RapidAPI-Host': 'breachdirectory.p.rapidapi.com'},
                timeout=15
            )
            data = r.json()
            if data.get('success') and data.get('result'):
                for entry in data['result'][:30]:
                    results.append({
                        'source': 'BreachDirectory',
                        'record': entry.get('password', entry.get('sha1', '[HASHED]')),
                        'type':   'EXPOSED' if entry.get('has_password') else 'HASHED',
                    })
        else:
            # Free web scrape fallback
            r = req.get(f'https://breachdirectory.org/?q={query}', headers=HEADERS, timeout=15)
            soup = BeautifulSoup(r.text, 'html.parser')
            for row in soup.select('table tbody tr')[:20]:
                cells = row.select('td')
                if len(cells) >= 2:
                    results.append({
                        'source': 'BreachDirectory',
                        'record': cells[0].get_text().strip(),
                        'type':   'DETECTED',
                    })
    except Exception as e:
        errors.append(f'BreachDirectory: {e}')

    # --- LeakCheck.net free public API ---
    try:
        r = req.get(
            f'https://leakcheck.net/api/public?check={query}',
            headers=HEADERS, timeout=10
        )
        data = r.json()
        if data.get('success') and data.get('sources'):
            for src in data['sources']:
                results.append({
                    'source': f"LeakCheck / {src.get('name', 'Unknown')}",
                    'record': f"Breach date: {src.get('date', 'N/A')}",
                    'type':   'BREACH',
                })
    except Exception as e:
        errors.append(f'LeakCheck: {e}')

    return jsonify({
        'status':  'success',
        'query':   query,
        'results': results,
        'errors':  errors,
        'count':   len(results),
    })

# ───────────────────────────────────────────────────────────────────────────
# Background cache builder — called once at startup and on REFRESH
# ───────────────────────────────────────────────────────────────────────────
def _build_indonesia_cache():
    """Fetch HIBP + Google News in background and write to disk cache."""
    results = {'hibp': [], 'news': [], 'errors': []}
    try:
        r = req.get('https://haveibeenpwned.com/api/v3/breaches', headers=HEADERS, timeout=20)
        r.raise_for_status()
        KW = ['indonesia', 'indonesian']
        for b in r.json():
            d = b.get('Domain', '').lower()
            t = b.get('Title', '').lower()
            s = b.get('Description', '').lower()
            if not (d.endswith('.id') or any(k in t for k in KW) or any(k in s for k in KW)):
                continue
            dc = b.get('DataClasses', [])
            pc = b.get('PwnCount', 0)
            sc = score_breach(dc, pc)
            results['hibp'].append({
                'name': b.get('Name'), 'title': b.get('Title'),
                'domain': b.get('Domain', ''), 'breach_date': b.get('BreachDate', ''),
                'added_date': b.get('AddedDate', ''), 'pwn_count': pc,
                'data_classes': dc, 'risk_label': risk_label(sc), 'risk_score': sc,
                'logo': b.get('LogoPath', ''), 'is_verified': b.get('IsVerified', False),
            })
        results['hibp'].sort(key=lambda x: x['added_date'], reverse=True)
    except Exception as e:
        results['errors'].append(f'HIBP: {e}')

    try:
        NEWS_URLS = [
            'https://news.google.com/rss/search?q=kebocoran+data+Indonesia+after:2021-01-01&hl=id&gl=ID&ceid=ID:id',
            'https://news.google.com/rss/search?q=ransomware+serangan+siber+Indonesia+after:2021-01-01&hl=id&gl=ID&ceid=ID:id',
            'https://news.google.com/rss/search?q=hacker+serang+perusahaan+Indonesia+after:2021-01-01&hl=id&gl=ID&ceid=ID:id',
            'https://news.google.com/rss/search?q=Indonesia+data+breach+ransomware+after:2021-01-01&hl=en-US&gl=US&ceid=US:en',
        ]
        seen = set()
        for url in NEWS_URLS:
            for entry in feedparser.parse(url).entries[:30]:
                t = entry.get('title', '').strip()
                if t in seen: continue
                seen.add(t)
                results['news'].append({
                    'title': t,
                    'summary': BeautifulSoup(entry.get('summary',''), 'html.parser').get_text()[:250],
                    'link': entry.get('link',''),
                    'date': entry.get('published', entry.get('updated','')),
                    'source': entry.get('source',{}).get('title','') if hasattr(entry.get('source',''),'get') else '',
                    'tag': classify_post(t, ''),
                })
        for inc in INDONESIA_INCIDENTS:
            if inc.get('ref'):
                fd = f"{inc['date']}-01T00:00:00Z" if len(inc['date'])==7 else inc['date']
                t  = f"[SEJARAH {inc['date'][:4]}] Kebocoran Data {inc['title']}"
                if t not in seen:
                    seen.add(t)
                    results['news'].append({'title':t,'summary':inc['impact'],'link':inc['ref'],
                                            'date':fd,'source':'Arsip Insiden Nasional','tag':inc['attack_type']})
        
        results['news'].sort(key=lambda x: x['date'] if x['date'] else '', reverse=True)
    except Exception as e:
        results['errors'].append(f'RSS News: {e}')

    try:
        CURATED_FEEDS = [
            {'url': 'https://dailydarkweb.net/category/data-breaches/feed/', 'source': 'Daily Dark Web'},
            {'url': 'https://dailydarkweb.net/feed/', 'source': 'Daily Dark Web (Global)'},
        ]
        results['curated'] = []
        for feed in CURATED_FEEDS:
            for entry in feedparser.parse(feed['url']).entries[:20]:
                t = entry.get('title', '').strip()
                if t in seen: continue
                seen.add(t)
                results['curated'].append({
                    'title': t,
                    'summary': BeautifulSoup(entry.get('summary',''), 'html.parser').get_text()[:350],
                    'link': entry.get('link',''),
                    'date': entry.get('published', entry.get('updated','')),
                    'source': feed['source'],
                    'tag': classify_post(t, entry.get('summary','')),
                })
        results['curated'].sort(key=lambda x: x['date'], reverse=True)
    except Exception as e:
        results['errors'].append(f'Curated Feeds: {e}')

    try:
        with open(_INDONESIA_CACHE_FILE, 'w') as f:
            json.dump(results, f)
    except:
        pass


def _maybe_warm_cache():
    """Start background refresh only if cache is missing or stale."""
    if os.path.exists(_INDONESIA_CACHE_FILE):
        age = time.time() - os.path.getmtime(_INDONESIA_CACHE_FILE)
        if age < _CACHE_TTL:
            return  # cache still fresh
    threading.Thread(target=_build_indonesia_cache, daemon=True).start()

# ── Warm the cache once at import time (app startup) ──────────────────────
_maybe_warm_cache()


@breach_intel_bp.route('/darkweb/breach-intel/indonesia')
@login_required
def indonesia_breach():
    """Serve Indonesia breach data instantly from disk cache.
    Cache is built at startup and refreshed every 6h or on demand.
    """
    incidents = sorted(INDONESIA_INCIDENTS, key=lambda x: x['date'], reverse=True)

    # Try cache
    if os.path.exists(_INDONESIA_CACHE_FILE):
        try:
            with open(_INDONESIA_CACHE_FILE, 'r') as f:
                data = json.load(f)
            
            # Combine static incidents with live DB intel
            full_incidents = list(incidents)
            seen_titles = {inc['title'] for inc in full_incidents}
            
            try:
                id_threats = Threat.query.filter(
                    Threat.source.in_(['Daily Dark Web', 'DarkWeb Informer']),
                    (Threat.title.ilike('%Indonesia%')) | (Threat.summary.ilike('%Indonesia%'))
                ).order_by(Threat.published.desc()).all()
                
                for it in id_threats:
                    # Clean title for display
                    display_title = it.title.replace('Indonesia ', '').replace('Indonesian ', '')
                    if display_title in seen_titles: continue
                    seen_titles.add(display_title)
                    
                    full_incidents.append({
                        'title': it.title,
                        'date': it.published.strftime('%Y-%m') if it.published else 'Unknown',
                        'impact': it.summary[:200],
                        'attack_type': it.category,
                        'risk': it.severity or 'High',
                        'attacker': it.source,
                        'records': 'Unknown',
                        'org_type': 'Private/Public',
                        'tags': ['INTEL', 'DARKWEB', it.category],
                        'ref': it.link
                    })
            except: pass
            
            # Sort all by date
            full_incidents.sort(key=lambda x: x['date'], reverse=True)
            
            data['incidents'] = full_incidents
            data['from_cache'] = True
            return jsonify({'status': 'success', **data})
        except:
            pass

    # Cache not ready yet (still building at startup) — return incidents only
    return jsonify({
        'status':   'success',
        'incidents': incidents,
        'hibp':     [],
        'news':     [],
        'errors':   ['Cache is being built, please refresh in a moment.'],
        'loading':  True,
    })


@breach_intel_bp.route('/darkweb/breach-intel/daily/search')
@login_required
def daily_search():
    """Search for Daily Darkweb entries in the database with filtering."""
    from app.models import Threat
    from datetime import datetime, timedelta
    
    days = request.args.get('days', 30, type=int)
    q = request.args.get('q', '').strip()
    
    since = datetime.utcnow() - timedelta(days=days)
    
    query = Threat.query.filter(Threat.source.in_(['Daily Dark Web', 'DarkWeb Informer']))
    query = query.filter(Threat.published >= since)
    
    if q:
        query = query.filter(Threat.title.like(f'%{q}%') | Threat.summary.like(f'%{q}%'))
    
    results = query.order_by(Threat.published.desc()).all()
    
    output = []
    for t in results:
        output.append({
            'title': t.title,
            'summary': t.summary[:350] + '...' if len(t.summary or '') > 350 else t.summary,
            'link': t.link,
            'date': t.published.isoformat() if t.published else t.published_str,
            'source': t.source,
            'tag': t.category.upper() if t.category else 'INTEL'
        })
    
    return jsonify({'status': 'success', 'count': len(output), 'results': output})


@breach_intel_bp.route('/darkweb/breach-intel/daily/deep-scan', methods=['POST'])
@login_required
def daily_deep_scan():
    """Trigger a deep crawl of all Darkweb intelligence sources."""
    def run_deep_scan():
        from scratch.deep_scrape_daily import scrape_daily_breaches
        from scratch.deep_scrape_dwi import scrape_dwi_fraud
        scrape_daily_breaches(max_pages=20)
        scrape_dwi_fraud(max_pages=10)
        
    threading.Thread(target=run_deep_scan, daemon=True).start()
    return jsonify({'status': 'ok', 'message': 'Deep scan started for all sources'})


@breach_intel_bp.route('/darkweb/breach-intel/indonesia/refresh', methods=['POST'])
@login_required
def indonesia_refresh():
    """Trigger a manual background refresh of Indonesia cache."""
    threading.Thread(target=_build_indonesia_cache, daemon=True).start()
    return jsonify({'status': 'ok', 'message': 'Refresh started in background'})

