"""
统一日志配置模块
提供统一的日志配置，确保整个项目的日志格式和输出方式一致
日志文件存储位置：logs/api.log
"""
import logging
import sys
from pathlib import Path
from core.config import LOG_FILE, LOG_DIR

# 确保日志目录存在
LOG_DIR.mkdir(parents=True, exist_ok=True)

# 验证日志文件路径（Path对象已经是绝对路径或相对路径）
LOG_FILE_ABS = LOG_FILE.resolve() if not LOG_FILE.is_absolute() else LOG_FILE


def setup_logging(
    level: int = logging.INFO,
    log_to_file: bool = True,
    log_to_console: bool = False,
    log_format: str = None
) -> None:
    """
    统一配置日志系统
    
    日志文件存储位置：logs/api.log（由 core.config.LOG_FILE 定义）
    
    Args:
        level: 日志级别，默认为 INFO
        log_to_file: 是否输出到文件，默认为 True（输出到 logs/api.log）
        log_to_console: 是否输出到控制台，默认为 False
        log_format: 日志格式，如果为 None 则使用默认格式
    """
    if log_format is None:
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    handlers = []
    
    # 文件处理器 - 日志存储到 logs/api.log
    if log_to_file:
        # 确保日志文件路径是绝对路径（相对于项目根目录）
        log_file_path = LOG_FILE.resolve() if not LOG_FILE.is_absolute() else LOG_FILE
        # 确保日志目录存在
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 创建文件处理器，日志写入 logs/api.log
        file_handler = logging.FileHandler(str(log_file_path), encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)
    
    # 控制台处理器
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(console_handler)
    
    # 配置根日志记录器
    logging.basicConfig(
        level=level,
        format=log_format,
        handlers=handlers,
        force=True  # 强制重新配置，覆盖之前的配置
    )


def get_logger(name: str) -> logging.Logger:
    """
    获取日志记录器实例
    
    Args:
        name: 日志记录器名称，通常使用 __name__
    
    Returns:
        Logger 实例
    """
    return logging.getLogger(name)


# 在模块导入时自动配置日志（仅输出到文件）
# 如果需要同时输出到控制台，可以在 main.py 中调用 setup_logging(log_to_console=True)
setup_logging(log_to_file=True, log_to_console=False)
