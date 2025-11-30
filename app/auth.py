"""
Web API Key 认证模块
"""
import hmac
import hashlib
import logging
from typing import Optional
from flask import current_app, session, request, redirect, url_for

logger = logging.getLogger('app.auth')


def get_configured_api_key() -> str:
    """从配置中获取 API Key"""
    return current_app.config.get('AUTH_API_KEY', '') or ''


def is_auth_enabled() -> bool:
    """检查是否启用了认证"""
    api_key = get_configured_api_key()
    return bool(api_key and api_key.strip())


def _hash_api_key(api_key: str) -> str:
    """计算 API Key 的哈希值"""
    return hashlib.sha256(api_key.encode('utf-8')).hexdigest()


def verify_api_key(provided_key: str) -> bool:
    """
    使用常量时间比较验证 API Key
    防止时序攻击
    """
    if not provided_key:
        return False
    
    configured_key = get_configured_api_key()
    if not configured_key:
        return False
    
    # 使用 hmac.compare_digest 进行常量时间比较
    return hmac.compare_digest(provided_key.encode('utf-8'), configured_key.encode('utf-8'))


def is_authenticated() -> bool:
    """检查当前 Session 是否已认证"""
    if not is_auth_enabled():
        return True  # 未启用认证时，视为已认证
    
    if not session.get('authenticated'):
        return False
    
    # 检查 API Key 是否已变更
    stored_hash = session.get('api_key_hash', '')
    current_hash = _hash_api_key(get_configured_api_key())
    
    if stored_hash != current_hash:
        # API Key 已变更，清除认证状态
        logout()
        return False
    
    return True


def login(api_key: str) -> bool:
    """
    验证 API Key 并创建认证 Session
    返回是否登录成功
    """
    if verify_api_key(api_key):
        session['authenticated'] = True
        session['api_key_hash'] = _hash_api_key(get_configured_api_key())
        logger.info("用户登录成功")
        return True
    
    logger.warning("登录失败：API Key 错误")
    return False


def logout() -> None:
    """清除认证 Session"""
    session.pop('authenticated', None)
    session.pop('api_key_hash', None)
    session.pop('next_url', None)
    logger.info("用户已登出")


# 公开路由列表（无需认证）
PUBLIC_ROUTES = [
    'auth.login',
    'auth.logout', 
    'main.health_check',
]

PUBLIC_PREFIXES = [
    '/static/',
]


def is_public_route() -> bool:
    """检查当前请求是否为公开路由"""
    # 检查端点名称
    if request.endpoint in PUBLIC_ROUTES:
        return True
    
    # 检查路径前缀
    for prefix in PUBLIC_PREFIXES:
        if request.path.startswith(prefix):
            return True
    
    return False
