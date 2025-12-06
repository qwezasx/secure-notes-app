
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, ValidationError
import bleach

class NoteForm(FlaskForm):
    title = StringField('Заголовок', validators=[
        DataRequired(message='Заголовок обязателен'),
        Length(min=1, max=200, message='Заголовок должен быть от 1 до 200 символов')
    ])
    
    content = TextAreaField('Содержание', validators=[
        DataRequired(message='Содержание обязательно'),
        Length(min=1, message='Содержание не может быть пустым')
    ])
    
    submit = SubmitField('Сохранить')

class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[
        DataRequired(message='Имя пользователя обязательно'),
        Length(min=2, max=50, message='Имя пользователя должно быть от 2 до 50 символов')
    ])
    
    password = PasswordField('Пароль', validators=[
        DataRequired(message='Пароль обязателен'),
        Length(min=1, message='Пароль не может быть пустым')
    ])
    
    submit = SubmitField('Войти')

class RegisterForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[
        DataRequired(message='Имя пользователя обязательно'),
        Length(min=2, max=50, message='Имя пользователя должно быть от 2 до 50 символов')
    ])
    
    password = PasswordField('Пароль', validators=[
        DataRequired(message='Пароль обязателен'),
        Length(min=3, message='Пароль должен быть не менее 3 символов')
    ])
    
    submit = SubmitField('Зарегистрироваться')
