"""Create/drop exactly one generated database; never accept caller-supplied SQL."""
import json
import os
from pathlib import Path
import sys
import pymysql
import redis
from scripts.security_isolation.safety import guard, block_external_network


def main():
    run_id = guard()
    block_external_network()
    output = Path(os.environ['SECURITY_ISOLATION_RESOURCE_DIR'])
    cfg = dict(host=os.environ['MYSQL_HOST'], port=int(os.environ['MYSQL_PORT']),
        user=os.environ['MYSQL_USER'], password=os.environ['MYSQL_PASSWORD'], charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor, autocommit=True)
    cache = redis.Redis(host=os.environ['REDIS_HOST'], port=int(os.environ['REDIS_PORT']),
        password=os.environ.get('REDIS_PASSWORD') or None, db=15, decode_responses=True)
    marker = '__security_isolation_owner__'
    if sys.argv[1] == 'drop':
        from scripts.security_isolation.cleanup import drop_resources
        drop_resources(cfg, cache, marker, run_id, output)
        return
    with pymysql.connect(**cfg) as conn:
        with conn.cursor() as cur:
            if sys.argv[1] == 'create':
                if cache.dbsize() or not cache.set(marker, run_id, nx=True):
                    raise RuntimeError('Dedicated Redis DB15 must be empty')
                cur.execute('SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s', (run_id,))
                if cur.fetchone():
                    raise RuntimeError('Generated database already exists; refusing ownership')
                # Durable intent covers a crash between CREATE DATABASE and its ownership row.
                (output / 'database-claim.json').write_text(json.dumps({'run_id': run_id}), encoding='utf-8')
                cur.execute(f'CREATE DATABASE `{run_id}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')
                conn.select_db(run_id)
                cur.execute('CREATE TABLE security_isolation_owner (run_id VARCHAR(32) PRIMARY KEY) ENGINE=InnoDB')
                cur.execute('INSERT INTO security_isolation_owner VALUES (%s)', (run_id,))
                from database_setup import initialize_database
                from scripts.migrate import run_migrations
                initialize_database()
                run_migrations()
                required = {
                    'users': {'id', 'true_total_points', 'password_hash'},
                    'orders': {'id', 'status', 'refund_no', 'transaction_id'},
                    'product_skus': {'stock', 'price'},
                    'sessions': {'user_id', 'token', 'expired_at'},
                    'points_log': {'operator_id', 'balance_before', 'event_id', 'source'},
                    'auth_sms_limits': {'scope_hash', 'attempt_count'},
                    'auth_sms_challenges': {'session_id', 'code_hash', 'consumed_at'},
                    'security_operator_audit': {'operator_id', 'target_id', 'action'},
                    'payment_refund_intents': {'out_refund_no', 'logical_key', 'state'},
                    'payment_events': {'event_key', 'transaction_id'},
                    'payment_merchant_transfers': {'out_batch_no', 'state'},
                    'finance_requests': {'actor_id', 'request_key', 'payload_hash'},
                    'finance_events': {'event_kind', 'event_key', 'payload_hash'},
                }
                for table, columns in required.items():
                    cur.execute('SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s', (run_id, table))
                    found = {row['COLUMN_NAME'] for row in cur.fetchall()}
                    if columns - found:
                        raise RuntimeError('Incomplete bootstrap schema: ' + table + ':' + ','.join(sorted(columns - found)))
                    cur.execute('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s', (run_id, table))
                    if cur.fetchone()['ENGINE'] != 'InnoDB':
                        raise RuntimeError('Nontransactional isolation table: ' + table)
                cur.execute('SELECT version,sha256 FROM schema_migrations ORDER BY version')
                (output / 'migrations.json').write_text(json.dumps(cur.fetchall(), indent=2), encoding='utf-8')
                cur.execute('SELECT VERSION() version, @@transaction_isolation isolation_level, @@sql_mode sql_mode, @@character_set_server charset')
                info = cur.fetchone()
                info['redis_version'] = cache.info('server')['redis_version']
                (output / 'environment.json').write_text(json.dumps(info, indent=2), encoding='utf-8')
            else:
                raise RuntimeError('Expected create or drop')
    cache.close()


if __name__ == '__main__':
    main()
