# core/middleware.py - 统一中间件配置
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi import FastAPI


def setup_cors(app: FastAPI):
    """配置 CORS 中间件"""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def setup_static_files(app: FastAPI):
    """配置静态文件服务"""
    static_dir = Path("static")
    if static_dir.exists() and static_dir.is_dir():
        try:
            app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
        except Exception as e:
            print(f"⚠️ 静态文件目录挂载失败（可忽略）: {e}")
