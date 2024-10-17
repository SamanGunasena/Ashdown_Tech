from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length


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
