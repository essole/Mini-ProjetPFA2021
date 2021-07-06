# -*- encoding: utf-8 -*-
from app.home import blueprint
from flask import render_template, request, Response
from flask_login import login_required
from jinja2 import TemplateNotFound
from app.home.dataAnalysis import *
from app.home.script import addrules
from app.home.affichPage import Input_form, Input2_form, Input3_form
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
import io
import sys

df = pd.read_csv('app/home/fic1.csv', header=None, sep="\t", names=['version', 'ihl', 'tos', 'len', 'id', 'flags', 'frag', 'ttl', 'proto', 'chksum', 'src', 'dst', 'options', 'service', 'time', 'sport', 'dport', 'seq', 'ack', 'dataofs', 'reserved', 'tcp_flags', 'window', 'tcp_chksum', 'urgptr', 'tcp_options', 'payload', 'payload_raw', 'payload_hex'])

#often the time type isn't accurate so this line convert the time type into datatime
df['time'] = [datetime.fromtimestamp(float(date)) for date in df['time'].values]
df['time'] = pd.to_datetime(df.time, format='DD/MM/YY')


@blueprint.route('/index')
@login_required
def index():

    return render_template('index.html', segment='index')

@blueprint.route('/plot.png')
@login_required
def plot_png():
    obj = datainfo(df)
    fig = obj.payplotsrc()
    output = io.BytesIO()
    FigureCanvas(fig).print_png(output)
    return Response(output.getvalue(), mimetype='image/png')

@blueprint.route('/Bad')
@login_required
def Bad():
    return render_template('graphes/Bad.html', segment='Bad')

@blueprint.route('/plot1.png')
@login_required
def plot1_png():
    obj = datainfo(df)
    fig = obj.timeplot()
    output = io.BytesIO()
    FigureCanvas(fig).print_png(output)
    return Response(output.getvalue(), mimetype='image/png')

@blueprint.route('/Timeplot')
@login_required
def Timeplot():
    return render_template('graphes/Timeplot.html', segment='Timeplot')

@blueprint.route('/plot2.png')
@login_required
def plot2_png():
    obj = datainfo(df)
    fig = obj.corplot()
    output = io.BytesIO()
    FigureCanvas(fig).print_png(output)
    return Response(output.getvalue(), mimetype='image/png')

@blueprint.route('/corplot')
@login_required
def corplot():
    return render_template('graphes/corplot.html', segment='corplot')

@blueprint.route('/plot3.png')
@login_required
def plot3_png():
    obj = datainfo(df)
    fig = obj.payplotdst()
    output = io.BytesIO()
    FigureCanvas(fig).print_png(output)
    return Response(output.getvalue(), mimetype='image/png')

@blueprint.route('/dstplot')
@login_required
def dstplot():
    return render_template('graphes/Targmach.html', segment='Targmach')


@blueprint.route('/plot4.png')
@login_required
def plot4_png():
    obj = datainfo(df)
    fig = obj.corplotbytime()
    output = io.BytesIO()
    FigureCanvas(fig).print_png(output)
    return Response(output.getvalue(), mimetype='image/png')

@blueprint.route('/cortime')
@login_required
def cortime():
    return render_template('graphes/cortime.html', segment='cortime')

@blueprint.route('/vizdata', methods=['GET','POST'])
@login_required
def vizdata():
    form = Input_form()
    obj = datainfo(df)
    var = obj.showData()
    if form.validate_on_submit():
        inputd = form.value.data
        line = 0
        if int(inputd) != 0:
            line = int(inputd)
            obj = datainfo(df,line)
            var = obj.showData()
            return render_template('stats/vizdata.html', segment=var, form=form)

    return render_template('stats/vizdata.html', segment=var, form=form)

@blueprint.route('/genstat')
@login_required
def genstat():
    obj = datainfo(df)
    var1 = obj.describeData()
    var2 = obj.dataSummary()
    var3 = obj.dataMedian()
    var4 = obj.summ()
    return render_template('stats/genstat.html', var1=var1, var2=var2, var3=var3, var4=var4)

@blueprint.route('/datatype')
@login_required
def datatype():
    obj = datainfo(df)
    old_stdout = sys.stdout
    new_stdout = io.StringIO()
    sys.stdout = new_stdout
    print(obj.infoData())
    var = new_stdout.getvalue()
    sys.stdout = old_stdout
    return render_template('stats/datatype.html', var=var)

@blueprint.route('/mainstatbad')
@login_required
def mainstatbad():
    obj = datainfo(df)
    var1 = obj.minMaxpay()
    var2 = obj.minMaxTIP()
    var3 = obj.frecSrcAd()
    var4 = obj.frecDstAd()
    var5 = obj.frecComm()
    var6 = obj.avSizeTopIp()
    return render_template('stats/mainstatbad.html', var1=var1, var2=var2, var3=var3, var4=var4, var5=var5, var6=var6)

@blueprint.route('/specdatainfo')
@login_required
def specdatainfo():
    obj = datainfo(df)
    var1 = obj.statService()
    var2 = obj.statProto()
    return render_template('stats/specdatainfo.html', var1=var1, var2=var2)

@blueprint.route('/analsbyserv', methods=['GET','POST'])
@login_required
def analsbyserv():
    obj = datainfo(df)
    form = Input_form()
    form2 = Input2_form()
    if form.validate_on_submit():
        inputd = form.value.data
        var1 = obj.servSummary(inputd)
        return render_template('Analysis/Analsbyservice.html', var1=var1, form=form, form2=form2)

    if form2.validate_on_submit():
        servname = form2.name.data
        inputd = form2.valeur.data
        var2 = obj.vizserv(servname)
        line = 0
        if int(inputd) != 0:
            line = int(inputd)
            obj = datainfo(df, line)
            var2 = obj.vizserv(servname)
            return render_template('Analysis/Analsbyservice.html', var2=var2, form2=form2, form=form)
        return render_template('Analysis/Analsbyservice.html', var2=var2, form2=form2, form=form)
    return render_template('Analysis/Analsbyservice.html', form=form, form2=form2)

@blueprint.route('/analservport', methods=['GET','POST'])
@login_required
def analservport():
    obj = datainfo(df)
    form = Input_form()
    form2 = Input2_form()
    if form.validate_on_submit():
        inputd = form.value.data
        var1 = obj.servAttack(inputd)
        return render_template('Analysis/analservport.html', var1=var1, form=form, form2=form2)

    if form2.validate_on_submit():
        servname = form2.name.data
        inputd = form2.valeur.data
        port = 0
        if int(inputd) != 0:
            port = int(inputd)
            var2 = obj.portAttack(servname, port)
            return render_template('Analysis/analservport.html', var2=var2, form2=form2, form=form)
    return render_template('Analysis/analservport.html', form=form, form2=form2)

@blueprint.route('/addrule', methods=['GET','POST'])
@login_required
def addrule():
    form = Input3_form()
    rule=""
    if form.validate_on_submit():
        protocol = form.protocol.data
        service = form.service.data
        port = form.port.data
        addsrc = form.addsrc.data
        addst = form.addst.data
        autre = form.autre.data
        if protocol == "" and service !="" and port !="" and addsrc !="" and addst != "" and autre !="":
            rule = "\n"+service +"|"+port+"|"+addsrc+"|"+addst+"|"+autre
        elif protocol != "" and service =="" and port !="" and addsrc !="" and addst != "" and autre !="":
            rule = "\n" + protocol + "|" + port + "|" + addsrc + "|"+ addst + "|" + autre
        elif protocol != "" and service !="" and port =="" and addsrc !="" and addst != "" and autre !="":
            rule = "\n"+protocol +"|"+ service + "|" + addsrc + "|"+ addst + "|" + autre
        elif protocol != "" and service !="" and port !="" and addsrc =="" and addst != "" and autre !="":
            rule = "\n" + protocol + "|" + service + "|" + port + "|" + addst + "|" + autre
        elif protocol != "" and service !="" and port !="" and addsrc !="" and addst == "" and autre !="":
            rule = "\n" + protocol + "|" + service + "|" + port + "|" + addsrc + "|" + autre
        elif protocol != "" and service !="" and port !="" and addsrc !="" and addst != "" and autre =="":
            rule = "\n" + protocol + "|" + service + "|" + port + "|" + addsrc + "|" + addst
        elif protocol == "" and service == "" and port == "" and addsrc == "" and addst == "" and autre == "":
            rule="\n"
        else:
            rule = "\n" + protocol + "|" + service + "|" + port + "|" + addsrc + "|" + addst + "|"+ autre
    addrules(rule)
    return render_template("stats/addrule.html", form=form)

@blueprint.route('/<template>')
@login_required
def route_template(template):
    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)

        # Serve the file (if exists) from app/templates/FILE.html
        return render_template(template, segment=segment)

    except TemplateNotFound:
        return render_template('page-404.html'), 404

    except:
        return render_template('page-500.html'), 500

# Helper - Extract current page name from request
def get_segment( request ):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None
