from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, BooleanField, SubmitField
from wtforms.validators import DataRequired


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    file = FileField('File')
    show_author = BooleanField('Display Author Name')
    submit = SubmitField('Add Post')
