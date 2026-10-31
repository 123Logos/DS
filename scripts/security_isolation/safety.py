"""Fail-closed safeguards shared by bootstrap and the actual-app test process."""
import os
import re
import socket
import sys


LOCAL_HTTP_ENDPOINTS = set()

def guard():
    run_id = os.environ.get("SECURITY_ISOLATION_RUN_ID", "")
    if (not re.fullmatch(r"dsiso_[a-f0-9]{16}", run_id)
        or os.environ.get("MYSQL_DATABASE") != run_id
        or os.environ.get("SECURITY_ISOLATION_ACK") != "dedicated-services-no-production"
        or os.environ.get("ENVIRONMENT") != "test"
        or os.environ.get("REDIS_DB") != "15"):
        raise RuntimeError("Refusing unsafe isolation environment")
    return run_id


def block_external_network():
    allowed = set()
    for prefix in ("MYSQL", "REDIS"):
        host, port = os.environ[prefix + "_HOST"], int(os.environ[prefix + "_PORT"])
        allowed.add((host, port))
        for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
            allowed.add((item[4][0], port))

    def audit(event, args):
        if event == "socket.connect":
            address = args[1]
            if not isinstance(address, tuple) or address[:2] not in allowed | LOCAL_HTTP_ENDPOINTS:
                raise PermissionError("Isolation denies outbound network except dedicated database services")
        elif event == "socket.getaddrinfo":
            if (args[0], args[1]) not in allowed | LOCAL_HTTP_ENDPOINTS:
                raise PermissionError("Isolation denies external DNS")
    sys.addaudithook(audit)
