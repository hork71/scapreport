import sys
import os
import csv
import io
from datetime import date, timedelta
from itertools import islice
from flask import Blueprint, render_template, session, request, url_for, redirect, flash, abort, Response, stream_with_context
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from app import db
from app.auth.views import current_user, login_required, role_required
from app.models import User, Baseline, Role
from sqlalchemy import desc

sys.path.append(os.path.abspath("./app/main/"))
import utils
from app.main import scap_results, history
from app.main.tabs import TABS, TABS_BY_API, TABS_BY_OS


main = Blueprint('main', __name__, template_folder='templates')

@main.context_processor
def inject_tabs():
    return {'tabs': TABS}

@main.app_template_filter('datum')
def datum(value):
    return history.nl_date(value)

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

def baselines_by_ruleid(os_version, cis_version):
    """{ruleid: Baseline} of one os_version and CIS version, to link refertes to their benchmark page."""
    return {b.ruleid: b for b in Baseline.query.filter(Baseline.os_version == os_version,
                                                      Baseline.cis_version == cis_version)}

@main.route('/server/<os_version>/<certname>')
@login_required
def show_server(os_version, certname):
    tab = TABS_BY_OS.get(os_version) or abort(404)
    rows = scap_results.server(os_version, certname)
    if rows is None:
        abort(404)
    info = next((s for s in scap_results.servers(os_version) if s['certname'] == certname), {})

    # link each control to its benchmark page and show the CIS title
    baselines = baselines_by_ruleid(os_version, tab['cis_version'])
    hist = history.server(os_version, tab['cis_version'], certname)
    for row in rows:
        baseline = baselines.get(row['referte'])
        row['baseline_id'] = baseline.id if baseline else None
        row['voorschrift'] = baseline.name if baseline else ''
        # since: the date the control got its current status
        row['since'] = hist['since'].get(row['rule_id'], '')
        row['since_datum'] = history.nl_date(row['since'])
        row['since_start'] = bool(row['since'] and hist['start'] and row['since'] <= hist['start'])

    # changes of this server, with the same links and titles as the controls table
    titles = {row['rule_id']: row['titel'] for row in rows}
    for change in hist['changes']:
        add_baseline(change, baselines)
        change['titel'] = titles.get(change['rule_id'], '')

    return render_template('server.html', tab=tab, certname=certname,
                           info=info, rows=rows, hist=hist)

@main.route('/historie')
@login_required
def historie():
    return render_template('historie.html', periods=history.PERIODS, default_days=history.TREND_DAYS,
                           max_changes=history.MAX_LIST_CHANGES,
                           date_to=date.today(), date_from=date.today() - timedelta(days=history.LIST_DAYS - 1))

def add_baseline(row, baselines):
    """Benchmark page link, voorschrift and numeric sort key for a row with a referte."""
    baseline = baselines.get(row['referte'])
    row['referte'] = row['referte'] or ''
    row['referte_sort'] = scap_results.referte_sort_key(row['referte'])
    row['baseline_id'] = baseline.id if baseline else None
    row['voorschrift'] = baseline.name if baseline else ''
    return row

@main.route('/api/history/<os_version>/totals')
@login_required
def history_totals_api(os_version):
    tab = TABS_BY_OS.get(os_version) or abort(404)
    days = request.args.get('days', type=int)
    if days not in history.PERIODS:
        days = history.TREND_DAYS
    totals = history.os_totals(os_version, tab['cis_version'], days)
    baselines = baselines_by_ruleid(os_version, tab['cis_version'])
    for row in totals['worse'] + totals['better']:
        add_baseline(row, baselines)
    return totals

def date_arg(name, default):
    try:
        return date.fromisoformat(request.args.get(name, ''))
    except ValueError:
        return default

def csv_cell(value):
    """Plain text in Excel: a value starting with = + - or @ would be read as a formula."""
    value = '' if value is None else str(value)
    return "'" + value if value[:1] in ('=', '+', '-', '@') else value

@main.route('/api/history/<os_version>/changes')
@login_required
def history_changes_api(os_version):
    """Changes in a date range: ?from=2026-10-01&to=2026-10-07, &nieuw=1 to include new and
    removed servers, &format=csv for the export."""
    tab = TABS_BY_OS.get(os_version) or abort(404)
    date_to = date_arg('to', date.today())
    date_from = date_arg('from', date_to - timedelta(days=history.LIST_DAYS - 1))
    if date_from > date_to:
        date_from, date_to = date_to, date_from
    include_new = request.args.get('nieuw') == '1'
    titles = scap_results.rules(os_version)
    baselines = baselines_by_ruleid(os_version, tab['cis_version'])

    def rows(limit=None):
        for change in history.os_changes(os_version, tab['cis_version'], date_from.isoformat(),
                                         date_to.isoformat(), include_new, limit):
            change['titel'] = titles.get(change['rule_id'], {}).get('titel', '')
            yield add_baseline(change, baselines)

    if request.args.get('format') == 'csv':
        def generate():
            # BOM and ; so Excel with Dutch settings opens it in columns
            out = io.StringIO()
            writer = csv.writer(out, delimiter=';')
            writer.writerow(['datum', 'os_version', 'cis_version', 'server', 'referte', 'voorschrift',
                             'control', 'titel', 'oud', 'nieuw'])
            yield '\ufeff' + out.getvalue()
            for row in rows():
                out.seek(0)
                out.truncate()
                writer.writerow([csv_cell(v) for v in (
                    row['scan_date'], os_version, tab['cis_version'], row['certname'], row['referte'],
                    row['voorschrift'], row['rule_id'], row['titel'], row['old'], row['new'])])
                yield out.getvalue()

        filename = f"scap_wijzigingen_{os_version}_{date_from}_{date_to}.csv"
        return Response(stream_with_context(generate()), mimetype='text/csv',
                        headers={'Content-Disposition': f'attachment; filename="{filename}"'})

    data = list(islice(rows(history.MAX_LIST_CHANGES + 1), history.MAX_LIST_CHANGES + 1))
    return {'data': data[:history.MAX_LIST_CHANGES], 'truncated': len(data) > history.MAX_LIST_CHANGES,
            'from': date_from.isoformat(), 'to': date_to.isoformat()}

@main.route('/benchmark/<id>')
@login_required
def show_osb(id):
    osb = {'data': [baseline.to_dict() for baseline in Baseline.query.filter_by(id=id).all()]}

    pdfinput = utils.start_eind(osb)
    eindbestand = utils.genereer_pdf(pdfinput)

    scap, hist = None, None
    if osb['data']:
        baseline = osb['data'][0]
        scap = scap_results.lookup(baseline['os_version'], baseline['ruleid'])
        hist = history.referte(baseline['os_version'], baseline['cis_version'], baseline['ruleid'])

    return render_template('show.html', osb=osb, eindbestand=eindbestand, scap=scap, hist=hist)

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
