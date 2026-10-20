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

def baseline_data(os_version, cis_version=None):
    """Baselines for one os_version, with SCAP fail/pass totals per referte added."""
    query = Baseline.query.filter(Baseline.os_version == os_version)
    if cis_version:
        query = query.filter(Baseline.cis_version == cis_version)

    totals = scap_results.summary(os_version)
    data = []
    for baseline in query.all():
        row = baseline.to_dict()
        scap = totals.get(row['ruleid'], {})
        row['scap_failed'] = scap.get('failed')
        row['scap_passed'] = scap.get('passed')
        data.append(row)
    return {'data': data}

#@main.route('/api/redhat_8')
#def data():
#       return baseline_data('rh_8', '3.0.0')

@main.route('/api/redhat_8v4')
def data():
        return baseline_data('rh_8v4')

@main.route('/api/redhat_9')
def data3():
        return baseline_data('rh_9', '2.0.0')

@main.route('/api/sles_15')
def data1():
        return baseline_data('sl_15', '2.0.1')

@main.route('/api/sles_16')
def data6():
        return baseline_data('sl_16', '1.0.0')

@main.route('/api/ubuntu_22')
def data4():
        return baseline_data('ub_22', '3.0.0')

@main.route('/api/ubuntu_24')
def data5():
        return baseline_data('ub_24', '1.0.0')

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
