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

class Input3_form(FlaskForm):
    protocol = IntegerField('protocol', validators=[DataRequired()])
    service = StringField('service', validators=[DataRequired()])
    port = IntegerField('port', validators=[DataRequired()])
    addsrc = StringField('addsrc', validators=[DataRequired()])
    addst = StringField('addst', validators=[DataRequired()])
    autre = StringField('autre', validators=[DataRequired()])
    submit = SubmitField('Send')