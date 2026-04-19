from flask import Blueprint, render_template, request, redirect, url_for, abort, jsonify
from flask_login import login_required, current_user
from sqlalchemy import or_, and_
from ..extensions import db
from ..models import Inventory, Threat, DismissedAlert
from ..utils.helpers import log_event, get_inventory_alerts, normalize_url

inventory_bp = Blueprint('inventory', __name__)



@inventory_bp.route('/inventory')
@login_required
def index():
    if not current_user.group_id:
        log_event('No group assigned.', 'warning')
        return render_template('inventory.html', items=[])
    items = Inventory.query.filter_by(group_id=current_user.group_id).all()
    return render_template('inventory.html', items=items)

@inventory_bp.route('/inventory/add', methods=['POST'])
@login_required
def add():
    if not current_user.group_id: return redirect(url_for('inventory.index'))
    brand = request.form.get('brand')
    module = request.form.get('module')
    version = request.form.get('version')
    if brand and module:
        new_item = Inventory(
            group_id=current_user.group_id, 
            brand=brand, 
            module=module, 
            version=version, 
            added_by_id=current_user.id
        )
        db.session.add(new_item)
        db.session.commit()
        log_event('Inventory item added.', 'success')
    return redirect(url_for('inventory.index'))

@inventory_bp.route('/inventory/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    item = Inventory.query.get_or_404(id)
    if item.group_id != current_user.group_id: abort(403)
    db.session.delete(item)
    db.session.commit()
    log_event('Item removed.', 'info')
    return redirect(url_for('inventory.index'))

@inventory_bp.route('/alerts')
@login_required
def alerts():
    severity_filter = request.args.get('severity')
    user_alerts = get_inventory_alerts(current_user.group_id, severity=severity_filter)
    return render_template('alerts.html', alerts=user_alerts, current_severity=severity_filter)

@inventory_bp.route('/alerts/dismiss/<int:threat_id>', methods=['POST'])
@login_required
def dismiss_alert(threat_id):
    existing = DismissedAlert.query.filter_by(group_id=current_user.group_id, threat_id=threat_id).first()
    if not existing:
        dismissal = DismissedAlert(group_id=current_user.group_id, threat_id=threat_id)
        db.session.add(dismissal)
        db.session.commit()
        log_event(f"Alert {threat_id} dismissed.", "info")
    return redirect(url_for('inventory.alerts'))

@inventory_bp.route('/api/threats/check', methods=['GET', 'POST'])
@login_required
def check_new_threats():
    if request.method == 'POST':
        # Matching for private items from local storage
        data = request.json
        items = data.get('items', [])
        severity_filter = data.get('severity')
        alerts = []
        
        dismissed_ids = [d.threat_id for d in DismissedAlert.query.filter_by(group_id=current_user.group_id).all()]
        
        for item in items:
            brand = item.get('brand', '').lower()
            module = item.get('module', '').lower()
            if not brand or not module: continue
            
            # Search threats for matches
            query = Threat.query.filter(or_(
                and_(Threat.title.ilike(f"%{brand}%"), Threat.title.ilike(f"%{module}%")),
                and_(Threat.summary.ilike(f"%{brand}%"), Threat.summary.ilike(f"%{module}%"))
            ))
            if severity_filter: query = query.filter(Threat.severity.ilike(severity_filter))
            if dismissed_ids: query = query.filter(Threat.id.notin_(dismissed_ids))
            
            matches = query.limit(20).all()
            for match in matches:
                alerts.append({
                    'inventory_item': f"{item.get('brand')} {item.get('module')} {item.get('version', '')}".strip(),
                    'threat': {
                        'id': match.id,
                        'title': match.title,
                        'link': normalize_url(match.link),
                        'severity': match.severity,
                        'category': match.category,
                        'summary': match.summary,
                        'published_str': match.published_str,
                        'published': match.published.isoformat() if match.published else None,
                        'source': match.source
                    }
                })
        
        # Sort by published date DESC
        alerts.sort(key=lambda x: x['threat']['published'] or '', reverse=True)
        return jsonify(alerts)

    # Standard GET logic for shared/cloud assets
    alerts = get_inventory_alerts(current_user.group_id)
    return jsonify({
        'status': 'success',
        'count': len(alerts),
        'has_alerts': len(alerts) > 0
    })
