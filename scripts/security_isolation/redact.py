"""Sanitize pytest representations independently of application logging filters."""
import argparse
import hashlib
import json
from pathlib import Path
import re

JWT = re.compile(r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])')
BEARER = re.compile(r'(?i)(Bearer\s+)[A-Za-z0-9._~-]{8,}')
SENSITIVE = re.compile(r'''(?i)((?:authorization|cookie|access_token|refresh_token|sms_code|password|secret|api_v3_key)["']?\s*[:=]\s*["']?)([^\s,'"<>}]+)''')


def sanitize(text, secrets=()):
    for value in sorted({v for v in secrets if v and len(v) >= 8}, key=len, reverse=True):
        text = text.replace(value, '[REDACTED]')
    text = JWT.sub('[REDACTED_JWT]', text)
    text = BEARER.sub(r'\1[REDACTED_TOKEN]', text)
    return SENSITIVE.sub(r'\1[REDACTED]', text)


def sanitize_file(path, secrets=()):
    path = Path(path)
    if path.is_file():
        original = path.read_bytes()
        clean = sanitize(original.decode('utf-8', errors='replace'), secrets).encode('utf-8')
        path.write_bytes(clean)
        return {'file': path.name, 'original_sha256': hashlib.sha256(original).hexdigest(),
            'redacted_sha256': hashlib.sha256(clean).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('paths', nargs='+', type=Path)
    args = parser.parse_args()
    records = [sanitize_file(path) for path in args.paths]
    print(json.dumps(records, indent=2))


if __name__ == '__main__':
    main()
