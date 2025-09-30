import re
from wafinstaller.models import AppSetting

from wafinstaller.helper.adapters import detect_crs_version

MODSEC_KEYS = [
    "SecRuleEngine",
    "SecRequestBodyAccess",
    "SecRequestBodyLimit",
    "SecRequestBodyNoFilesLimit",
    "SecRequestBodyJsonDepthLimit",
    "SecArgumentsLimit",
    "SecResponseBodyAccess",
    "SecResponseBodyMimeType",
    "SecResponseBodyLimit",
    "SecAuditEngine",
    "SecAuditLogRelevantStatus",
    "SecAuditLogParts",
    "SecAuditLog",
    "SecTmpDir",
    "SecDataDir",
    "SecArgumentSeparator",
    "SecCookieFormat",
    "SecUnicodeMapFile",
    "SecStatusEngine",
    "SecPcreMatchLimit",
]

MODSEC_KEY_DESCRIPTIONS = {
    "SecRuleEngine": "Enables or disables the ModSecurity engine (On, Off, DetectionOnly).",
    "SecRequestBodyAccess": "Allow ModSecurity to inspect request bodies.",
    "SecRequestBodyLimit": "Maximum size of the request body (in bytes).",
    "SecRequestBodyNoFilesLimit": "Maximum size of non-file request bodies.",
    "SecRequestBodyJsonDepthLimit": "Limit for JSON nesting depth in request bodies.",
    "SecArgumentsLimit": "Maximum number of arguments allowed in a request.",
    "SecResponseBodyAccess": "Enable ModSecurity to inspect response bodies.",
    "SecResponseBodyMimeType": "MIME types of responses to inspect (e.g., text/html).",
    "SecResponseBodyLimit": "Maximum size of the response body (in bytes).",
    "SecAuditEngine": "Controls the audit logging engine (On, Off, RelevantOnly).",
    "SecAuditLogRelevantStatus": "Status codes that should trigger audit logging (e.g., 5xx).",
    "SecAuditLogParts": "Specifies which parts of the transaction to log.",
    "SecAuditLog": "Path to the audit log file.",
    "SecTmpDir": "Directory for temporary files used by ModSecurity.",
    "SecDataDir": "Directory for persistent data storage (e.g., IP collections).",
    "SecArgumentSeparator": "Separator character used between arguments in a request.",
    "SecCookieFormat": "Enable or disable support for RFC2109-style cookies.",
    "SecUnicodeMapFile": "Path to the Unicode mapping file for character encoding conversions.",
    "SecStatusEngine": "Enable or disable the ModSecurity status engine.",
    "SecPcreMatchLimit": "Limits the work of the PCRE engine during regex evaluation.",
}

APP_KEYS = {
    "AttackRetentionDays": {"default": "15", "description": "Number of days to retain WAF attack logs before auto deletion."}
}

RULE_PATTERN = re.compile(
    r'SecRule\s+([^\s]+)\s+"([^"]+)"\s+"[^"]*id:(\d+)[^"]*phase:(\d+)[^"]*(deny|pass|allow|drop|log|nolog)[^"]*(?:msg:\'([^"]*)\')?.*"'
)

def get_full_installed_crs_version():
    return detect_crs_version()

def load_app_settings():
    return {s.key: s.value for s in AppSetting.objects.all()}

def save_app_settings(settings_dict):
    for key, value in settings_dict.items():
        AppSetting.objects.update_or_create(key=key, defaults={"value": value})
