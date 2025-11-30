"""
认证相关路由
"""
import logging
from flask import Blueprint, render_template, request, redirect, url_for, session
from app.auth import login, logout, is_auth_enabled

logger = logging.getLogger('app.auth_routes')

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login_page():
    """登录页面"""
    # 如果未启用认证，直接重定向到首页
    if not is_auth_enabled():
        return redirect(url_for('main.index'))
    
    error = None
    
    if request.method == 'POST':
        api_key = request.form.get('api_key', '').strip()
        
        if not api_key:
            error = '请输入 API Key'
        elif login(api_key):
            # 登录成功，重定向到原始请求页面或首页
            next_url = session.pop('next_url', None) or url_for('main.index')
            logger.info(f"登录成功，重定向到: {next_url}")
            return redirect(next_url)
        else:
            error = 'API Key 错误'
    
    return render_template('login.html', error=error)


@auth_bp.route('/logout', methods=['POST'])
def logout_page():
    """登出"""
    logout()
    return redirect(url_for('auth.login'))
