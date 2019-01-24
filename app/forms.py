from flask_wtf import FlaskForm
from wtforms import SubmitField, SelectField, StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, length, EqualTo, Email, ValidationError, InputRequired
from app.models import User


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Recordarme')
    submit = SubmitField('Entrar')


class BaseUserForm(FlaskForm):
    username = StringField('Nuevo Usuario:', validators=[DataRequired(), length(min=5, max=20)])
    email = StringField('Email:', validators=[DataRequired(), Email()])
    password = PasswordField('Nueva Contraseña:',
                             validators=[EqualTo('password2', message='contraseñas deben coincidir!')])
    password2 = PasswordField('Repetir Contraseña:')
    rol = SelectField('Seleccione rol:')
    submit = SubmitField('Registrar')


class UsuarioForm(BaseUserForm):
    password = PasswordField('Nueva Contraseña:',
                             validators=[InputRequired(), EqualTo('password2', message='contraseñas deben coincidir!')])

    @staticmethod
    def validate_email(email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Email ya Registrado.')

    @staticmethod
    def validate_username(username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Usuario ya Registrado.')


class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email:', validators=[DataRequired(), Email(), length(min=0, max=64)])
    submit = SubmitField('Enviar')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password:', validators=[DataRequired()])
    password2 = PasswordField('Repetir password:', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Cambiar Password')
