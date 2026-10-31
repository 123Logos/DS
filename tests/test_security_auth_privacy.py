"""Boundary projection regressions; no external provider proof."""
from contextlib import contextmanager


def test_bankcard_status_never_returns_provider_secrets(monkeypatch):
    from services import bankcard_service as module
    class Cursor:
        def __enter__(self):
            return self
        def __exit__(self,*args):
            return False
        def execute(self,*args):
            return None
        def fetchone(self):
            return {'id':42,'status':1,'verify_result':'VERIFY_SUCCESS','bind_at':None,'sub_mchid':'synthetic-sub'}
    class Connection:
        def cursor(self):
            return Cursor()
    @contextmanager
    def connection():
        yield Connection()
    monkeypatch.setattr(module,'get_conn',connection)
    monkeypatch.setattr(module.wxpay_client,'query_settlement_account',lambda _: {
        'account_type':'ACCOUNT_TYPE_PRIVATE','account_bank':'synthetic-bank','verify_result':'VERIFY_SUCCESS',
        'account_number':'SYNTHETIC-SECRET-CARD','account_name':'SYNTHETIC-SECRET-NAME','admin_key':'SYNTHETIC-SECRET-KEY'})
    result=module.BankcardService.query_bind_status(42)
    assert set(result['wechat_display_info']) == {'account_type','account_bank','verify_result'}
    assert 'SYNTHETIC-SECRET' not in str(result)
