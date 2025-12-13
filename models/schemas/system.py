# models/schemas/system.py - 系统配置 Pydantic 模型
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime


class SystemSentenceModel(BaseModel):
    """系统标语模型"""
    id: Optional[int] = None
    banner_sentence: Optional[str] = Field(None, max_length=128, description="轮播图标语")
    system_sentence: Optional[str] = Field(None, max_length=128, description="系统标语")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class SystemSentenceUpdate(BaseModel):
    """系统标语更新模型"""
    banner_sentence: Optional[str] = Field(None, max_length=128, description="轮播图标语")
    system_sentence: Optional[str] = Field(None, max_length=128, description="系统标语")

