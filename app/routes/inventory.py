from flask import Blueprint, render_template, request, redirect, url_for, abort, jsonify
from flask_login import login_required, current_user
from sqlalchemy import or_, and_
from ..extensions import db
from ..models import Inventory, Threat, DismissedAlert
from ..utils.helpers import log_event

inventory_bp = Blueprint('inventory', __name__)

def get_inventory_alerts(group_id):
    if not group_id: return []
    dismissed_ids = [d.threat_id for d in DismissedAlert.query.filter_by(group_id=group_id).all()]
    group_inventory = Inventory.query.filter_by(group_id=group_id).all()
    alerts = []
    for item in group_inventory:
        brand_lower = item.brand.lower()
        module_lower = item.module.lower()
        query = Threat.query.filter(or_(
            and_(Threat.title.ilike(f"%{brand_lower}%"), Threat.title.ilike(f"%{module_lower}%")),
            and_(Threat.summary.ilike(f"%{brand_lower}%"), Threat.summary.ilike(f"%{module_lower}%"))
        ))
        if dismissed_ids: query = query.filter(Threat.id.notin_(dismissed_ids))
        matches = query.all()
        for match in matches:
            alerts.append({
                'inventory_item': f"{item.brand} {item.module} {item.version if item.version else ''}".strip(),
                'threat': match
            })
    return alerts

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
        new_item = Inventory(group_id=current_user.group_id, brand=brand, module=module, version=version, added_by_id=current_user.id)
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
    user_alerts = get_inventory_alerts(current_user.group_id)
    return render_template('alerts.html', alerts=user_alerts)

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
