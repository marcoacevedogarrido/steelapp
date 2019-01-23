import json
import sqlite3 as sql
from functools import wraps
from sqlite3.dbapi2 import Connection

import requests
from flask import render_template, redirect, flash, request, abort
from flask import url_for
from flask_login import login_user, current_user, login_required, logout_user
from werkzeug.urls import url_parse

from app.email import send_password_reset_email
from app.forms import LoginForm, UsuarioForm, BaseUserForm
from app.forms import ResetPasswordForm
from app.forms import ResetPasswordRequestForm
from app.models import *

if app.debug:
    @app.before_first_request
    def create_user():
        print("running debug mode DB and scripts")
        db.drop_all()
        db.create_all()

        # Create test user
        new_rol = Rol(name='admin', rol_email='admin@test.net')
        db.session.add(new_rol)
        new_rol = Rol(name='operador', rol_email='operadores@test.net')
        db.session.add(new_rol)
        db.session.commit()

        new_user = User(username="admin", email="admin@test.net", rol_id=1)

        new_user.set_password('password')
        db.session.add(new_user)
        db.session.commit()


def check_rol(role='ANY'):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            user_rol = current_user.get_rol().name
            if user_rol != role:
                return abort(404)
            return fn(*args, **kwargs)

        return decorated_view

    return wrapper


@app.route('/', methods=['GET'])
def main():
    return render_template('front.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('reportes'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('login')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/index', methods=['GET', 'POST'])
@login_required
@check_rol("admin")
def reportes():
    auth = requests.auth.HTTPBasicAuth('xbi', 'xbi102938')
    URL = 'http://Xsolution.cl:5071/biVentas/76783666k/2017-01-01/2017-12-01'
    parameters = {'token': 'pigFEWljiFkna0HsIthaGca58rzsFtG4'}

    try:
        rows = requests.get(URL, auth=auth, verify=False, headers=parameters)
    except:
        rows = []
    return render_template('index.html', rows=rows)


@app.route('/logout')
@login_required
@check_rol("admin")
def logout():
    logout_user()
    return redirect(url_for('main'))


@app.route('/administrador/usuario')
@login_required
@check_rol("admin")
def usuario():
    usuario = User.query.all()
    return render_template('administrador/lista_usuario.html', usuario=usuario)


@app.route('/administrador/usuario/crear', methods=['POST', 'GET'])
@login_required
@check_rol("admin")
def usuario_create():
    form = UsuarioForm()
    form.rol.choices = [(str(l.id), l.name) for l in Rol.query.order_by('name')]
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            rol_id=form.rol.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Usuario Registrado!')
        return redirect(url_for('usuario'))
    return render_template('administrador/reg_usuario.html', form=form)


@app.route('/administrador/usuario/<int:usuario_id>', methods=['POST', 'GET'])
@login_required
@check_rol("admin")
def usuario_edit(usuario_id):
    edited_usuario = User.query.filter_by(id=usuario_id).first_or_404()
    form = BaseUserForm()
    form.rol.choices = [(str(l.id), l.name) for l in Rol.query.order_by('name')]

    if form.validate_on_submit():
        edited_usuario.username = form.username.data
        edited_usuario.email = form.email.data
        edited_usuario.rol_id = form.rol.data
        if form.password.data:
            edited_usuario.set_password(form.password.data)
        db.session.add(edited_usuario)
        db.session.commit()
        flash('Usuario editado')
        return redirect(url_for('usuario'))

    form.username.data = edited_usuario.username
    form.email.data = edited_usuario.email
    form.rol.data = str(edited_usuario.rol_id)
    return render_template('administrador/usuario.html', form=form, edited_usuario=edited_usuario)


@app.route('/administrador/usuario/<int:usuario_id>/delete', methods=['GET'])
@login_required
@check_rol("admin")
def usuario_delete(usuario_id):
    edited_usuario = User.query.filter_by(id=usuario_id).first_or_404()
    db.session.delete(edited_usuario)
    db.session.commit()
    flash('Usuario eliminado')
    return redirect(url_for('usuario'))


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Revise su cuenta de correo para cambiar su password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)


@app.route('/nosotros', methods=['GET'])
def nosotros():
    return render_template('nosotros.html')
