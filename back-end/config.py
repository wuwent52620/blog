import configparser
import os
from collections import defaultdict

from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))


def to_dict(items):
    d = dict()
    for item in items:
        d[item[0]] = item[1]
    return d


db_parser = configparser.ConfigParser()
db_parser.read('app/cfg/db.ini')
mysql_cfg = to_dict(db_parser.items('mysql'))


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'Do-it-instead-of-thinking'
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{mysql_cfg["user"]}:{mysql_cfg["password"]}@{mysql_cfg["host"]}:{mysql_cfg["port"]}/{mysql_cfg["db_name"]}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # 邮件配置
    ADMINS = ['wuwent930@163.com']  # 管理员的邮箱地址
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_SENDER = os.environ.get('MAIL_SENDER')
    # 分页设置
    POSTS_PER_PAGE = 10
    USERS_PER_PAGE = 10
    COMMENTS_PER_PAGE = 10
    MESSAGES_PER_PAGE = 10
