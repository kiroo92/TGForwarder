"""
作者: 烟雨
网址: www.yanyuwangluo.cn
时间: 2025/3/16
转载请备注出处
"""
import os
import asyncio
import logging
import yaml
from flask import Flask, redirect, url_for, session
# 从dotenv import load_dotenv
from app.models import db
from app.telegram_client import init_telegram_client

# 获取应用日志记录器
logger = logging.getLogger('app')

# 加载配置文件
def load_config():
    # 修改为从项目根目录加载配置文件
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.yaml')
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

# load_dotenv()

def create_app():
    """创建并配置Flask应用"""
    app = Flask(__name__)
    
    # 加载配置
    config = load_config()
    
    # 配置
    app.config['SECRET_KEY'] = config['flask']['secret_key']
    app.config['SQLALCHEMY_DATABASE_URI'] = config['flask']['database_uri']
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # 加载认证配置
    auth_config = config.get('auth', {})
    app.config['AUTH_API_KEY'] = auth_config.get('api_key', '') or ''
    
    # 初始化数据库
    db.init_app(app)
    
    # 注册蓝图
    from app.routes import main_bp
    from app.auth_routes import auth_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    
    # 注册认证中间件
    @app.before_request
    def check_authentication():
        """请求前检查认证状态"""
        from app.auth import is_auth_enabled, is_authenticated, is_public_route
        from flask import request
        
        # 如果未启用认证，直接放行
        if not is_auth_enabled():
            return None
        
        # 公开路由直接放行
        if is_public_route():
            return None
        
        # 检查是否已认证
        if not is_authenticated():
            # 保存原始请求 URL
            session['next_url'] = request.url
            return redirect(url_for('auth.login_page'))
        
        return None
    
    # 在应用上下文中创建数据库表
    with app.app_context():
        db.create_all()
        
        # 注意：这里不要初始化Telegram客户端
        # 实际的客户端初始化会在app.py中的start_telegram_client函数中执行
    
    return app 