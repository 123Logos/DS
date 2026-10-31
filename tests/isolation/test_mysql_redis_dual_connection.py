def test_distinct_mysql_connections_and_real_redis(db, isolated_redis, race, evidence):
    import threading
    barrier = threading.Barrier(2)
    def read():
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT CONNECTION_ID() id, @@autocommit autocommit, @@transaction_isolation isolation_level')
                row = cur.fetchone()
                barrier.wait(timeout=10)
                return row
    rows = race(read, read)
    assert rows[0]['id'] != rows[1]['id']
    assert all(row['autocommit'] == 0 for row in rows)
    evidence({'connections': rows})
    assert isolated_redis.ping()
