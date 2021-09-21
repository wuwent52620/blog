from datetime import datetime
from operator import itemgetter
import re
from flask import request, jsonify, url_for, g, current_app
from app.api import bp
from app.api.auth import token_auth
from app.api.errors import bad_request, error_response
from app.extensions import db
from app.models import User, Post
from app.utils.email import send_email


@bp.route('/users/', methods=['POST'])
def create_user():
    '''注册一个新用户'''
    data = request.get_json()
    if not data:
        return bad_request('You must post JSON data.')

    message = {}
    if 'username' not in data or not data.get('username', None).strip():
        message['username'] = 'Please provide a valid username.'
    pattern = '^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$'
    if 'email' not in data or not re.match(pattern, data.get('email', None)):
        message['email'] = 'Please provide a valid email address.'
    if 'password' not in data or not data.get('password', None).strip():
        message['password'] = 'Please provide a valid password.'

    if User.query.filter_by(username=data.get('username', None)).first():
        message['username'] = 'Please use a different username.'
    if User.query.filter_by(email=data.get('email', None)).first():
        message['email'] = 'Please use a different email address.'
    if message:
        return bad_request(message)

    user = User()
    user.from_dict(data, new_user=True)
    db.session.add(user)
    db.session.commit()

    # 发送确认账户的邮件
    
    response = jsonify(user.to_dict())
    response.status_code = 201
    # HTTP协议要求201响应包含一个值为新资源URL的Location头部
    response.headers['Location'] = url_for('api.get_user', id=user.id)
    return response


@bp.route('/users/', methods=['GET'])
@token_auth.login_required
def get_users():
    '''返回用户集合，分页'''
    page = request.args.get('page', 1, type=int)
    per_page = min(
        request.args.get(
            'per_page', current_app.config['USERS_PER_PAGE'], type=int), 100)
    data = User.to_collection_dict(User.query, page, per_page, 'api.get_users')
    return jsonify(data)


@bp.route('/users/<int:id>', methods=['GET'])
@token_auth.login_required
def get_user(id):
    '''返回一个用户'''
    user = User.query.get_or_404(id)
    if g.current_user == user:
        return jsonify(user.to_dict(include_email=True))
    # 如果是查询其它用户，添加 是否已关注过该用户 的标志位
    data = user.to_dict()
    data['is_following'] = g.current_user.is_following(user)
    return jsonify(data)


@bp.route('/users/<int:id>', methods=['PUT'])
@token_auth.login_required
def update_user(id):
    '''修改一个用户'''
    user = User.query.get_or_404(id)
    data = request.get_json()
    if not data:
        return bad_request('You must post JSON data.')

    message = {}
    if 'username' in data and not data.get('username', None).strip():
        message['username'] = 'Please provide a valid username.'

    pattern = '^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$'
    if 'email' in data and not re.match(pattern, data.get('email', None)):
        message['email'] = 'Please provide a valid email address.'

    if 'username' in data and data['username'] != user.username and \
            User.query.filter_by(username=data['username']).first():
        message['username'] = 'Please use a different username.'
    if 'email' in data and data['email'] != user.email and \
            User.query.filter_by(email=data['email']).first():
        message['email'] = 'Please use a different email address.'

    if message:
        return bad_request(message)

    user.from_dict(data, new_user=False)
    db.session.commit()
    return jsonify(user.to_dict())


@bp.route('/users/<int:id>', methods=['DELETE'])
@token_auth.login_required
def delete_user(id):
    '''删除一个用户'''
    user = User.query.get_or_404(id)
    if g.current_user != user:
        return error_response(403)
    db.session.delete(user)
    db.session.commit()
    return '', 204


###
# 与用户资源相关的资源
##
@bp.route('/users/<int:id>/posts/', methods=['GET'])
@token_auth.login_required
def get_user_posts(id):
    '''返回该用户的所有博客文章列表'''
    user = User.query.get_or_404(id)
    page = request.args.get('page', 1, type=int)
    per_page = min(
        request.args.get(
            'per_page', current_app.config['POSTS_PER_PAGE'], type=int), 100)
    data = Post.to_collection_dict(
        user.posts.order_by(Post.timestamp.desc()), page, per_page,
        'api.get_user_posts', id=id)
    return jsonify(data)


@bp.route('/users/<int:id>/liked-posts/', methods=['GET'])
@token_auth.login_required
def get_user_liked_posts(id):
    '''返回该用户喜欢别人的文章列表'''
    user = User.query.get_or_404(id)
    page = request.args.get('page', 1, type=int)
    per_page = min(
        request.args.get(
            'per_page', current_app.config['POSTS_PER_PAGE'], type=int), 100)
    data = Post.to_collection_dict(
        user.liked_posts.order_by(Post.timestamp.desc()), page, per_page,
        'api.get_user_liked_posts', id=id)
    return jsonify(data)


@bp.route('/users/<int:id>/followeds-posts/', methods=['GET'])
@token_auth.login_required
def get_user_followeds_posts(id):
    '''返回该用户所关注的大神的所有博客文章列表'''
    user = User.query.get_or_404(id)
    if g.current_user != user:
        return error_response(403)
    page = request.args.get('page', 1, type=int)
    per_page = min(
        request.args.get(
            'per_page', current_app.config['POSTS_PER_PAGE'], type=int), 100)
    data = Post.to_collection_dict(
        user.followeds_posts().order_by(Post.timestamp.desc()), page, per_page,
        'api.get_user_followeds_posts', id=id)
    # 标记哪些文章是新的
    last_read_time = user.last_followeds_posts_read_time or datetime(1900, 1, 1)
    for item in data['items']:
        if item['timestamp'] > last_read_time:
            item['is_new'] = True
    # 更新 last_followeds_posts_read_time 属性值
    user.last_followeds_posts_read_time = datetime.utcnow()
    # 将新文章通知的计数归零
    user.add_notification('unread_followeds_posts_count', 0)
    db.session.commit()
    return jsonify(data)


@bp.route('/resend-confirm', methods=['POST'])
@token_auth.login_required
def resend_confirmation():
    '''重新发送确认账户的邮件'''
    data = request.get_json()
    if not data:
        return bad_request('You must post JSON data.')
    if 'confirm_email_base_url' not in data or not data.get('confirm_email_base_url').strip():
        return bad_request('Please provide a valid confirm email base url.')

    token = g.current_user.generate_confirm_jwt()

    text_body = '''
    Dear {},
    Welcome to Madblog!
    To confirm your account please click on the following link: {}
    Sincerely,
    The Madblog Team
    Note: replies to this email address are not monitored.
    '''.format(g.current_user.username, data.get('confirm_email_base_url') + token)

    html_body = '''
    <p>Dear {0},</p>
    <p>Welcome to <b>Madblog</b>!</p>
    <p>To confirm your account please <a href="{1}">click here</a>.</p>
    <p>Alternatively, you can paste the following link in your browser's address bar:</p>
    <p><b>{1}</b></p>
    <p>Sincerely,</p>
    <p>The Madblog Team</p>
    <p><small>Note: replies to this email address are not monitored.</small></p>
    '''.format(g.current_user.username, data.get('confirm_email_base_url') + token)

    send_email('[Madblog] Confirm Your Account',
               sender=current_app.config['MAIL_SENDER'],
               recipients=[g.current_user.email],
               text_body=text_body,
               html_body=html_body)
    return jsonify({
        'status': 'success',
        'message': 'A new confirmation email has been sent to you by email.'
    })


@bp.route('/confirm/<token>', methods=['GET'])
@token_auth.login_required
def confirm(token):
    '''用户收到验证邮件后，验证其账户'''
    if g.current_user.confirmed:
        return bad_request('You have already confirmed your account.')
    if g.current_user.verify_confirm_jwt(token):
        g.current_user.ping()
        db.session.commit()
        # 给用户发放新 JWT，因为要包含 confirmed: true
        token = g.current_user.get_jwt()
        return jsonify({
            'status': 'success',
            'message': 'You have confirmed your account. Thanks!',
            'token': token
        })
    else:
        return bad_request('The confirmation link is invalid or has expired.')


@bp.route('/reset-password-request', methods=['POST'])
def reset_password_request():
    '''请求重置账户密码，需要提供注册时填写的邮箱地址'''
    data = request.get_json()
    if not data:
        return bad_request('You must post JSON data.')

    message = {}
    if 'confirm_email_base_url' not in data or not data.get('confirm_email_base_url').strip():
        message['confirm_email_base_url'] = 'Please provide a valid confirm email base url.'
    pattern = '^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$'
    if 'email' not in data or not re.match(pattern, data.get('email', None)):
        message['email'] = 'Please provide a valid email address.'
    if message:
        return bad_request(message)

    user = User.query.filter_by(email=data.get('email')).first()
    if user:  # 如果提供的邮箱地址对应的用户实例对象存在，就发邮件
        token = user.generate_reset_password_jwt()

        text_body = '''
        Dear {0},
        To reset your password click on the following link: {1}
        If you have not requested a password reset simply ignore this message.
        Sincerely,
        The Madblog Team
        Note: replies to this email address are not monitored.
        '''.format(user.username, data.get('confirm_email_base_url') + token)

        html_body = '''
        <p>Dear {0},</p>
        <p>To reset your password <a href="{1}">click here</a>.</p>
        <p>Alternatively, you can paste the following link in your browser's address bar:</p>
        <p><b>{1}</b></p>
        <p>If you have not requested a password reset simply ignore this message.</p>
        <p>Sincerely,</p>
        <p>The Madblog Team</p>
        <p><small>Note: replies to this email address are not monitored.</small></p>
        '''.format(user.username, data.get('confirm_email_base_url') + token)

        send_email('[Madblog] Reset Your Password',
                   sender=current_app.config['MAIL_SENDER'],
                   recipients=[user.email],
                   text_body=text_body,
                   html_body=html_body)
    # 不管前端提供的邮箱地址有没有对应的用户实例(不排除有人想恶意重置别人的账户)，都给他回应
    return jsonify({
        'status': 'success',
        'message': 'An email with instructions to reset your password has been sent to you.'
    })


@bp.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    '''用户点击邮件中的链接，通过验证 JWT 来重置对应的账户的密码'''
    data = request.get_json()
    if not data:
        return bad_request('You must post JSON data.')
    if 'password' not in data or not data.get('password', None).strip():
        return bad_request('Please provide a valid password.')
    user = User.verify_reset_password_jwt(token)
    if not user:
        return bad_request('The reset password link is invalid or has expired.')
    user.set_password(data.get('password'))
    db.session.commit()
    return jsonify({
        'status': 'success',
        'message': 'Your password has been reset.'
    })


@bp.route('/update-password', methods=['POST'])
@token_auth.login_required
def update_password():
    '''已登录的用户更新自己的密码'''
    data = request.get_json()
    if not data:
        return bad_request('You must post JSON data.')

    if 'old_password' not in data or not data.get('old_password', None).strip():
        return bad_request('Please provide a valid old password.')
    if 'new_password' not in data or not data.get('new_password', None).strip():
        return bad_request('Please provide a valid new password.')
    if data.get('old_password') == data.get('new_password'):
        return bad_request('The new password is equal to the old password.')
    # 验证旧密码
    if not g.current_user.check_password(data.get('old_password')):
        return bad_request('The old password is wrong.')
    g.current_user.set_password(data.get('new_password'))
    db.session.commit()
    return jsonify({
        'status': 'success',
        'message': 'Your password has been updated.'
    })
