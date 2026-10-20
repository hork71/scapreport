import sys
import os
from flask import Blueprint, render_template, session, request, url_for, redirect, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from app import db
from app.auth.views import current_user, login_required, role_required
from app.models import User, Baseline, Role
from sqlalchemy import desc

sys.path.append(os.path.abspath("./app/main/"))
import utils
from app.main import scap_results


main = Blueprint('main', __name__, template_folder='templates')

class DataForm(FlaskForm):
  osversie = StringField("Os")
  level    = StringField("Level")
  status   = StringField("Status")
  rol      = StringField("Rol")
  submit   = SubmitField("Filter")

@main.route('/')
def home():
        return render_template('home.html')

#@main.route('/api/redhat_8')
#def data():
#       return {'data': [baseline.to_dict() for baseline in Baseline.query.filter(Baseline.os_version == 'rh_8', Baseline.cis_version == '3.0.0').all()]}

@main.route('/api/redhat_8v4')
def data():
        return {'data': [baseline.to_dict() for baseline in Baseline.query.filter(Baseline.os_version == 'rh_8v4').all()]}

@main.route('/api/redhat_9')
def data3():
        return {'data': [baseline.to_dict() for baseline in Baseline.query.filter(Baseline.os_version == 'rh_9', Baseline.cis_version == '2.0.0').all()]}

#@main.route('/api/redhat_9v2')
#def data6():
#       return {'data': [baseline.to_dict() for baseline in Baseline.query.filter(Baseline.os_version == 'rh_9v2').all()]}

@main.route('/api/sles_15')
def data1():
        return {'data': [baseline.to_dict() for baseline in Baseline.query.filter(Baseline.os_version == 'sl_15', Baseline.cis_version == '2.0.1').all()]}

@main.route('/api/sles_16')
def data6():
        return {'data': [baseline.to_dict() for baseline in Baseline.query.filter(Baseline.os_version == 'sl_16', Baseline.cis_version == '1.0.0').all()]}

#@main.route('/api/ubuntu_20')
#def data2():
#       return {'data': [baseline.to_dict() for baseline in Baseline.query.filter(Baseline.os_version == 'ub_20', Baseline.cis_version == '3.0.0').all()]}

@main.route('/api/ubuntu_22')
def data4():
        return {'data': [baseline.to_dict() for baseline in Baseline.query.filter(Baseline.os_version == 'ub_22', Baseline.cis_version == '3.0.0').all()]}

@main.route('/api/ubuntu_24')
def data5():
        return {'data': [baseline.to_dict() for baseline in Baseline.query.filter(Baseline.os_version == 'ub_24', Baseline.cis_version == '1.0.0').all()]}

@main.route('/benchmark/<id>')
@login_required
def show_osb(id):
    osb = {'data': [baseline.to_dict() for baseline in Baseline.query.filter_by(id=id).all()]}

    pdfinput = utils.start_eind(osb)
    eindbestand = utils.genereer_pdf(pdfinput)

    scap = scap_results.lookup(osb['data'][0]['os_version'], osb['data'][0]['ruleid']) if osb['data'] else None

    return render_template('show.html', osb=osb, eindbestand=eindbestand, scap=scap)

@main.route('/deletepdf/<id>')
@login_required
def delete_pdf(id):
    utils.verwijder_pdf(id)
    return ''

@main.route('/edit/<id>', methods = ['GET', 'POST'])
@login_required
@role_required(Role.ADMIN)
def get_osb(id):
    osb = Baseline.query.filter_by(id=id).first()
    if request.method == 'POST':
      [('comply', 'nee'), ('backlog', 'ja'), ('voortgang', '0'), ('tooling', ''), ('analyse', ''), ('verantwoording', '')]
      osb.comply = request.form.get("comply")
      osb.backlog = request.form.get("backlog")
      osb.voortgang = request.form.get("voortgang")
      osb.implementatie = request.form.get("implementatie")
      osb.analyse = request.form.get("analyse")
      osb.verantwoording = request.form.get("verantwoording")

      db.session.add(osb)
      db.session.commit()
      flash("Benchmark {} voor besturingssysteem {} is bijgewerkt".format(osb.ruleid, osb.os_version), "success")
      return redirect(url_for("main.show_osb", id=osb.id))

    return render_template('edit.html', osb=osb)
