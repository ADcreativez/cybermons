import os
import json
import requests as req
from flask import Blueprint, render_template, current_app, jsonify
from flask_login import login_required, current_user
from ..utils.helpers import log_event

mitre_bp = Blueprint('mitre', __name__)

@mitre_bp.route('/mitre')
@login_required
def mitre_matrix():
    data_path = os.path.join(os.getcwd(), 'mitre_attack_data.json')
    try:
        if os.path.exists(data_path):
            with open(data_path, 'r') as f: mitre_data = json.load(f)
        else: mitre_data = []
    except Exception as e:
        mitre_data = []
        log_event(f"Error loading MITRE data: {str(e)}", "danger")
    total_techniques = sum(len(t.get('techniques', [])) for t in mitre_data)
    return render_template('mitre.html', mitre_data=mitre_data, total_techniques=total_techniques)

@mitre_bp.route('/mitre/update', methods=['POST'])
@login_required
def mitre_update():
    if current_user.role != 'admin': return jsonify({'success': False, 'message': 'Admin access required'}), 403
    stix_url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    try:
        resp = req.get(stix_url, timeout=60)
        resp.raise_for_status()
        stix_data = resp.json()
        tactics_map = {}
        for obj in stix_data.get('objects', []):
            if obj.get('type') == 'x-mitre-tactic' and not obj.get('revoked') and not obj.get('x_mitre_deprecated'):
                tid = next((r['external_id'] for r in obj.get('external_references', []) if r.get('source_name') == 'mitre-attack'), None)
                if tid:
                    tactics_map[obj['x_mitre_shortname']] = {
                        'tactic': obj['name'], 'tactic_id': tid, 'techniques': [], 'order': int(tid.replace('TA', ''))
                    }
        for obj in stix_data.get('objects', []):
            if obj.get('type') == 'attack-pattern' and not obj.get('revoked') and not obj.get('x_mitre_deprecated') and not obj.get('x_mitre_is_subtechnique'):
                tech_id = next((r['external_id'] for r in obj.get('external_references', []) if r.get('source_name') == 'mitre-attack'), None)
                if tech_id:
                    for phase in obj.get('kill_chain_phases', []):
                        if phase.get('kill_chain_name') == 'mitre-attack':
                            shortname = phase['phase_name']
                            if shortname in tactics_map: tactics_map[shortname]['techniques'].append({'id': tech_id, 'name': obj['name']})
        result = sorted(tactics_map.values(), key=lambda x: x['order'])
        for tactic in result:
            tactic['techniques'].sort(key=lambda t: t['id'])
            del tactic['order']
        data_path = os.path.join(current_app.root_path, 'mitre_attack_data.json')
        with open(data_path, 'w') as f: json.dump(result, f, indent=4)
        log_event(f"MITRE ATT&CK data updated.", "success")
        return jsonify({'success': True})
    except Exception as e:
        log_event(f"MITRE update failed: {str(e)}", "danger")
        return jsonify({'success': False, 'message': str(e)}), 500
