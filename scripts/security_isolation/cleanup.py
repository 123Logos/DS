"""Cleanup each dedicated resource even when the other service is unavailable."""
import json
import pymysql


def drop_resources(cfg, cache, marker, run_id, output):
    errors = []
    try:
        with pymysql.connect(**cfg) as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s', (run_id,))
                if cur.fetchone():
                    conn.select_db(run_id)
                    cur.execute('SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s', (run_id, 'security_isolation_owner'))
                    owner = None
                    if cur.fetchone():
                        cur.execute('SELECT run_id FROM security_isolation_owner')
                        owner = cur.fetchone()
                    if owner is not None and owner != {'run_id': run_id}:
                        raise RuntimeError('Database ownership marker mismatch')
                    if owner is None:
                        claim = output / 'database-claim.json'
                        if not claim.is_file() or json.loads(claim.read_text(encoding='utf-8')) != {'run_id': run_id}:
                            raise RuntimeError('Missing bootstrap database ownership claim')
                    cur.execute(f'DROP DATABASE `{run_id}`')
    except Exception as exc:
        errors.append('database:' + type(exc).__name__)
    try:
        if cache.get(marker) == run_id:
            for key in cache.scan_iter(count=100):
                if key != marker:
                    cache.delete(key)
            if cache.dbsize() != 1:
                raise RuntimeError('Redis cleanup incomplete')
            cache.delete(marker)
        elif cache.exists(marker):
            raise RuntimeError('Redis ownership marker mismatch')
    except Exception as exc:
        errors.append('redis:' + type(exc).__name__)
    finally:
        cache.close()
    (output / 'cleanup.json').write_text(json.dumps({'database': run_id, 'errors': errors}), encoding='utf-8')
    if errors:
        raise RuntimeError('Isolation cleanup incomplete: ' + ','.join(errors))
