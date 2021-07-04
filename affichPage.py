from wtforms import IntegerField, SubmitField, StringField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired

class Input_form(FlaskForm):
    value = StringField('value', validators=[DataRequired()])
    submit = SubmitField('Send')

class Input2_form(FlaskForm):
    name = StringField('value', validators=[DataRequired()])
    valeur = StringField('value', validators=[DataRequired()])
    submit = SubmitField('Send')