# One entry per OS tab, shared by the homepage and the server overview.
#   pane / table  html ids of the tab pane and its table
#   label / version  tab text
#   api           homepage data: /baseline/api/<api>
#   os_version / cis_version  baselines rows for that tab, and the SCAP reports/<os_version>/ folder
TABS = [
    {'pane': 'redhat8',  'table': 'rh8',  'label': 'RedHat 8',  'version': 'v3.0.0', 'api': 'redhat_8',  'os_version': 'rh_8',  'cis_version': '3.0.0'},
    {'pane': 'redhat9',  'table': 'rh9',  'label': 'RedHat 9',  'version': 'v2.0.0', 'api': 'redhat_9',  'os_version': 'rh_9',  'cis_version': '2.0.0'},
    {'pane': 'sles',     'table': 'sl',   'label': 'Sles 15',   'version': 'v1.1.1', 'api': 'sles_15',   'os_version': 'sl_15', 'cis_version': '2.0.1'},
    {'pane': 'sles16',   'table': 'sl16', 'label': 'Sles 16',   'version': 'v1.0.0', 'api': 'sles_16',   'os_version': 'sl_16', 'cis_version': '1.0.0'},
    {'pane': 'ubuntu22', 'table': 'ub22', 'label': 'Ubuntu 22', 'version': 'v1.0.0', 'api': 'ubuntu_22', 'os_version': 'ub_22', 'cis_version': '3.0.0'},
    {'pane': 'ubuntu24', 'table': 'ub24', 'label': 'Ubuntu 24', 'version': 'v1.0.0', 'api': 'ubuntu_24', 'os_version': 'ub_24', 'cis_version': '1.0.0'},
]

TABS_BY_API = {tab['api']: tab for tab in TABS}
TABS_BY_OS = {tab['os_version']: tab for tab in TABS}
