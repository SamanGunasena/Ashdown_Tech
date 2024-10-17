from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, BooleanField, SubmitField
from wtforms.fields.simple import PasswordField
from wtforms.validators import DataRequired, Length, Email


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=5, max=100)])
    content = TextAreaField('Content', validators=[DataRequired(), Length(min=10)])
    file = FileField('File')
    show_author = BooleanField('Display Author Name')
    submit = SubmitField('Add Post')


class QuestionForm(FlaskForm):
    topic = StringField('Topic/Subject', validators=[DataRequired(), Length(min=5, max=100)])
    question = TextAreaField('Your Question', validators=[DataRequired(), Length(min=10)])
    submit = SubmitField('Submit Question')


class AnswerForm(FlaskForm):
    answer = TextAreaField('Your Answer', validators=[DataRequired(), Length(min=5)])
    submit = SubmitField('Submit Answer')


class RegistrationForm(FlaskForm):
    firstname = StringField('First Name', validators=[DataRequired(), Length(min=2, max=30)])
    lastname = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=30)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Register')
