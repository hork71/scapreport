import sys
import os
from flask import Blueprint, render_template, session, request, url_for, redirect, flash, abort
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from app import db
from app.auth.views import current_user, login_required, role_required
from app.models import User, Baseline, Role
from sqlalchemy import desc

sys.path.append(os.path.abspath("./app/main/"))
import utils
from app.main import scap_results
from app.main.tabs import TABS, TABS_BY_API, TABS_BY_OS


main = Blueprint('main', __name__, template_folder='templates')

@main.context_processor
def inject_tabs():
    return {'tabs': TABS}

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

@main.route('/api/<api>')
def baselines_api(api):
    tab = TABS_BY_API.get(api) or abort(404)
    return baseline_data(tab['os_version'], tab['cis_version'])

@main.route('/servers')
@login_required
def servers():
    return render_template('servers.html')

@main.route('/api/servers/<os_version>')
@login_required
def servers_api(os_version):
    TABS_BY_OS.get(os_version) or abort(404)
    return {'data': scap_results.servers(os_version)}

@main.route('/server/<os_version>/<certname>')
@login_required
def show_server(os_version, certname):
    tab = TABS_BY_OS.get(os_version) or abort(404)
    rows = scap_results.server(os_version, certname)
    if rows is None:
        abort(404)
    info = next((s for s in scap_results.servers(os_version) if s['certname'] == certname), {})

    # link each control to its benchmark page and show the CIS title
    baselines = {b.ruleid: b for b in Baseline.query.filter(Baseline.os_version == os_version,
                                                            Baseline.cis_version == tab['cis_version'])}
    for row in rows:
        baseline = baselines.get(row['referte'])
        row['baseline_id'] = baseline.id if baseline else None
        row['voorschrift'] = baseline.name if baseline else ''

    return render_template('server.html', tab=tab, certname=certname,
                           info=info, rows=rows)

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
