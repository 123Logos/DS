"""Safe native Linux/WSL runner; no production dotenv or provider credentials."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]

def run_logged(command, cwd, env, log):
    from scripts.security_isolation.redact import sanitize
    secret_values = [value for key, value in env.items()
        if any(term in key for term in ('PASSWORD', 'SECRET', 'API_V3_KEY'))]
    with subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace') as child:
        for line in child.stdout:
            log.write(sanitize(line, secret_values))
            log.flush()
        return subprocess.CompletedProcess(command, child.wait())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifacts', type=Path, required=True)
    args, pytest_args = parser.parse_known_args()
    if os.environ.get('SECURITY_ISOLATION_ACK') != 'dedicated-services-no-production':
        parser.error('Explicit dedicated-services-no-production acknowledgement required')
    for key in ('MYSQL_HOST', 'MYSQL_PORT', 'MYSQL_USER', 'MYSQL_PASSWORD', 'REDIS_HOST', 'REDIS_PORT'):
        if key not in os.environ:
            parser.error('Missing explicit ' + key)
    run_id = 'dsiso_' + secrets.token_hex(8)
    output = args.artifacts.resolve() / run_id
    output.mkdir(parents=True, exist_ok=False)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('WECHAT', 'WX_', 'SMS_', 'ALIYUN'))}
    env.update(SECURITY_ISOLATION_RUN_ID=run_id, MYSQL_DATABASE=run_id,
        SECURITY_ISOLATION_RESOURCE_DIR=str(output), ENVIRONMENT='test', APP_ENV='test',
        ENABLE_BACKGROUND_TASKS='false', SKIP_STARTUP_DDL='true', RUN_MIGRATE_ON_STARTUP='false',
        REDIS_ENABLED='true', REDIS_DB='15', REDIS_KEY_PREFIX=run_id + ':',
        MYSQL_POOL_SIZE='6', UVICORN_WORKERS='1', JWT_SECRET_KEY=secrets.token_hex(32),
        ADMIN_USER_IDS='1', WX_MOCK_MODE='false', PYTHONPATH=str(ROOT), PYTHON_DOTENV_DISABLED='1')
    env['SMS_CODE_SECRET'] = secrets.token_hex(32)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['WX_PAY_BASE_URL'] = 'https://provider.invalid'
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    synthetic = output / 'synthetic-keys'
    synthetic.mkdir(mode=0o700)
    merchant = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    platform = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = synthetic / 'merchant-private.pem'
    private_path.write_bytes(merchant.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private_path.chmod(0o600)
    public_path = synthetic / 'platform-public.pem'
    public_path.write_bytes(platform.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    env.update(WECHAT_PAY_API_KEY_PATH=str(private_path), WECHAT_PAY_PUBLIC_KEY_PATH=str(public_path),
        WECHAT_PAY_PUB_KEY_ID='PUB_KEY_ID_ISOLATED_SYNTHETIC', WECHAT_PAY_MCH_ID='ISOLATED_MERCHANT',
        WECHAT_CERT_SERIAL_NO='1234567890ABCDEF', WECHAT_APP_ID='ISOLATED_APP',
        WECHAT_PAY_API_V3_KEY=secrets.token_hex(16))
    (output / 'run.json').write_text(json.dumps({'run_id': run_id,
        'provider_evidence': 'CONTROLLED_BOUNDARY_ONLY', 'database': run_id}, indent=2), encoding='utf-8')
    code = 1
    try:
        with (output / 'bootstrap.log').open('w', encoding='utf-8') as log:
            result = run_logged([sys.executable, '-m', 'scripts.security_isolation.bootstrap', 'create'], output, env, log)
            result.check_returncode()
        with (output / 'pytest.log').open('w', encoding='utf-8') as log:
            result = run_logged([sys.executable, '-m', 'pytest', str(ROOT / 'tests'),
                '-vv', '-ra', '-p', 'no:cacheprovider', '-p', 'scripts.security_isolation.pytest_guard',
                '--junitxml=' + str(output / 'junit.xml'), *pytest_args], output, env, log)
            code = result.returncode
    finally:
        with (output / 'cleanup.log').open('w', encoding='utf-8') as log:
            cleanup = run_logged([sys.executable, '-m', 'scripts.security_isolation.bootstrap', 'drop'], output, env, log)
        import hashlib
        key_metadata = {path.name: {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'purpose': 'synthetic-test-only'} for path in synthetic.iterdir() if path.is_file()}
        for path in synthetic.iterdir():
            if path.is_file():
                path.unlink()
        synthetic.rmdir()
        (output / 'synthetic-key-metadata.json').write_text(json.dumps(key_metadata, indent=2), encoding='utf-8')
        from scripts.security_isolation.redact import sanitize_file
        secret_values = [value for key, value in env.items()
            if any(term in key for term in ('PASSWORD', 'SECRET', 'API_V3_KEY'))]
        records = [sanitize_file(path, secret_values) for path in output.rglob('*')
            if path.suffix in ('.log', '.xml', '.jsonl')]
        (output / 'redaction.json').write_text(json.dumps(records, indent=2), encoding='utf-8')
        (output / 'exit.json').write_text(json.dumps({'test_exit_code': code,
            'cleanup_exit_code': cleanup.returncode}), encoding='utf-8')
        if code == 0 and cleanup.returncode:
            code = cleanup.returncode
        print(output)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
