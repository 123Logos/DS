# core/exceptions.py - 统一异常定义

class FinanceException(Exception):
    """财务系统基础异常"""
    pass


class OrderException(FinanceException):
    """订单相关异常"""
    pass


class InsufficientBalanceException(FinanceException):
    """余额不足异常"""
    def __init__(self, account_type: str, required_amount, balance):
        self.account_type = account_type
        self.required_amount = required_amount
        self.balance = balance
        message = f"账户 {account_type} 余额不足: 需要 {required_amount}, 当前 {balance}"
        super().__init__(message)
