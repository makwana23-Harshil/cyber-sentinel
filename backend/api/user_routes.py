"""User API Routes"""
import csv
import io
from flask import Blueprint, jsonify, g, request, Response
from database import db
from auth.middleware import token_required
from datetime import datetime, timedelta, timezone

user_bp = Blueprint('user', __name__, url_prefix='/api/user')

def serialize_scan(scan):
    """Helper to convert MongoDB scan document for JSON response."""
    if not scan:
        return None
    scan = dict(scan)

    if '_id' in scan:
        scan['id'] = str(scan['_id'])
        del scan['_id']

    # Convert user_id to string
    if scan.get('user_id'):
        scan['user_id'] = str(scan['user_id'])

    # Ensure created_at is serialized with explicit UTC timezone
    if scan.get('created_at'):
        dt = scan['created_at']
        if isinstance(dt, datetime):
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            scan['created_at'] = dt.isoformat()
        else:
            scan['created_at'] = str(dt)

    # Calculate number of links found in the scan
    link_count = 0
    details = scan.get('details') or {}

    # If the scan already contains extracted URLs
    extracted_urls = details.get('extracted_urls')
    if isinstance(extracted_urls, list):
        link_count = len(extracted_urls)
    elif isinstance(details.get('link_inspections'), list):
        link_count = len(details['link_inspections'])
    elif isinstance(scan.get('link_count'), int):
        link_count = scan['link_count']

    scan['link_count'] = link_count
    return scan

def serialize_user(user):
    return {
        'id': str(user['_id']),
        'name': user.get('name'),
        'email': user.get('email'),
        'role': user.get('role'),
        'is_active': user.get('is_active'),
        'created_at': user.get('created_at').isoformat() if user.get('created_at') else None,
        'last_login': user.get('last_login').isoformat() if user.get('last_login') else None
    }

def _user_id_query(uid, extra=None):
    from bson import ObjectId
    clauses = [{"user_id": uid}, {"user_id": str(uid)}]
    try:
        if isinstance(uid, str) and ObjectId.is_valid(uid):
            clauses.append({"user_id": ObjectId(uid)})
    except Exception:
        pass
    q = {"$or": clauses}
    if extra:
        q.update(extra)
    return q

@user_bp.route('/history', methods=['GET'])
@token_required
def history():
    from datetime import datetime, timezone
    uid = g.current_user['_id']
    limit_val = request.args.get('limit', 'all')
    start_date = request.args.get('start')
    end_date = request.args.get('end')
    
    q = _user_id_query(uid)
    if start_date or end_date:
        date_query = {}
        if start_date:
            try:
                date_query["$gte"] = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except: pass
        if end_date:
            try:
                date_query["$lte"] = datetime.strptime(end_date, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
            except: pass
        if date_query:
            q["created_at"] = date_query
            
    query = db.scans.find(q).sort("created_at", -1)
    if limit_val != 'all':
        try:
            query = query.limit(int(limit_val))
        except ValueError:
            pass
            
    scans_cursor = query
    scans = [serialize_scan(s) for s in scans_cursor]
    return jsonify({'success': True, 'scans': scans})


@user_bp.route('/stats', methods=['GET'])
@token_required
def stats():
    uid = g.current_user['_id']
    total = db.scans.count_documents(_user_id_query(uid))
    sms_count = db.scans.count_documents(_user_id_query(uid, {"scan_type": "sms"}))
    email_addr_count = db.scans.count_documents(_user_id_query(uid, {"scan_type": "email_address"}))
    email_body_count = db.scans.count_documents(_user_id_query(uid, {"scan_type": {"$in": ["email_comprehensive", "email_body"]}}))
    url_count = db.scans.count_documents(_user_id_query(uid, {"scan_type": "url"}))

    dangerous = db.scans.count_documents(_user_id_query(uid, {"verdict": {"$in": ["DANGEROUS", "MALICIOUS"]}}))
    phishing = db.scans.count_documents(_user_id_query(uid, {"verdict": "PHISHING"}))
    spam = db.scans.count_documents(_user_id_query(uid, {"verdict": "SPAM"}))
    suspicious = db.scans.count_documents(_user_id_query(uid, {"verdict": {"$in": ["SUSPICIOUS", "FAKE", "UNVERIFIED"]}}))
    safe = db.scans.count_documents(_user_id_query(uid, {"verdict": {"$in": ["SAFE", "LEGITIMATE", "HAM", "CLEAN", "VALID"]}}))
    
    known_count = dangerous + phishing + spam + suspicious + safe
    unknown = total - known_count if total > known_count else 0

    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)    
    recent = db.scans.find(_user_id_query(uid, {"created_at": {"$gte": thirty_days_ago}}))

    daily = {}
    for s in recent:
        if 'created_at' in s and s['created_at']:
            dt = s['created_at']
            if isinstance(dt, datetime):
                day = dt.strftime('%Y-%m-%d')
                daily[day] = daily.get(day, 0) + 1

    return jsonify({
        'success': True,
        'stats': {
            'total_scans': total,
            'by_type': {
                'sms': sms_count,
                'email_address': email_addr_count,
                'email_body': email_body_count,
                'url': url_count
            },
            'by_verdict': {
                'dangerous': dangerous,
                'phishing': phishing,
                'spam': spam,
                'suspicious': suspicious,
                'safe': safe,
                'unknown': unknown
            },
            'daily_activity': daily,
            'threats_blocked': dangerous + phishing + spam + suspicious
        }
    })


@user_bp.route('/dashboard', methods=['GET'])
@token_required
def dashboard():
    uid = g.current_user['_id']    
    recent_cursor = db.scans.find(_user_id_query(uid)).sort("created_at", -1).limit(5)
    recent_scans = [serialize_scan(s) for s in recent_cursor]
    total = db.scans.count_documents(_user_id_query(uid))
    threats = db.scans.count_documents(_user_id_query(uid, {"verdict": {"$in": ['DANGEROUS', 'PHISHING', 'SPAM', 'SUSPICIOUS', 'FAKE', 'MALICIOUS']}}))
    safety_score = 100 if total == 0 else max(0, int(100 - (threats / total * 100)))

    return jsonify({
        'success': True,
        'dashboard': {
            'user': serialize_user(g.current_user),
            'total_scans': total,
            'threats_found': threats,
            'safety_score': safety_score,
            'recent_scans': recent_scans
        }
    })


@user_bp.route('/export/csv', methods=['GET'])
@token_required
def export_csv():
    """Export the current user's scan history as CSV, honouring scan_type and date filters."""
    uid = g.current_user['_id']
    scan_type = request.args.get('scan_type', 'all').strip()
    start_date = request.args.get('start', '').strip()
    end_date   = request.args.get('end', '').strip()

    # Query scans matching EITHER ObjectId OR string user_id
    q = {
        "$or": [
            {"user_id": uid},
            {"user_id": str(uid)}
        ]
    }

    if scan_type and scan_type != 'all' and scan_type != 'threats':
        q['scan_type'] = scan_type
    elif scan_type == 'threats':
        q['verdict'] = {"$in": ['DANGEROUS', 'PHISHING', 'SPAM', 'SUSPICIOUS', 'FAKE']}

    if start_date or end_date:
        date_q = {}
        if start_date:
            try:
                date_q['$gte'] = datetime.strptime(start_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        if end_date:
            try:
                date_q['$lte'] = datetime.strptime(end_date, '%Y-%m-%d').replace(
                    hour=23, minute=59, second=59, tzinfo=timezone.utc)
            except ValueError:
                pass
        if date_q:
            q['created_at'] = date_q

    scans = list(db.scans.find(q).sort('created_at', -1))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['#', 'Scan Type', 'Input / Content', 'Verdict', 'Risk Score', 'Confidence (%)', 'Scanned At'])

    type_labels = {
        'sms': 'SMS',
        'email_address': 'Email Address',
        'email-address': 'Email Address',
        'email_comprehensive': 'Email Comprehensive',
        'url': 'URL',
    }

    for i, s in enumerate(scans, 1):
        scan_type_label = type_labels.get(s.get('scan_type', ''), (s.get('scan_type') or 'Scan').replace('_', ' ').title())

        # Safely handle confidence (could be float, int, or None)
        confidence_raw = s.get('confidence')
        if isinstance(confidence_raw, (int, float)):
            confidence = round(confidence_raw * 100, 1) if confidence_raw <= 1 else round(confidence_raw, 1)
        else:
            confidence = 0.0

        # Safely handle created_at (could be datetime object or ISO string)
        created_val = s.get('created_at')
        created = ''
        if isinstance(created_val, datetime):
            ist_time = created_val + timedelta(hours=5, minutes=30)
            created = ist_time.strftime('%Y-%m-%d %I:%M:%S %p IST')
        elif isinstance(created_val, str) and created_val:
            try:
                clean_str = created_val.replace('Z', '').split('+')[0].strip()
                dt_obj = datetime.fromisoformat(clean_str)
                ist_time = dt_obj + timedelta(hours=5, minutes=30)
                created = ist_time.strftime('%Y-%m-%d %I:%M:%S %p IST')
            except Exception:
                created = str(created_val)

        writer.writerow([
            i,
            scan_type_label,
            (s.get('input_text') or '')[:500],
            s.get('verdict', ''),
            s.get('risk_score', ''),
            confidence,
            created,
        ])

    filename_parts = ['cybersentinel_history']
    if scan_type and scan_type != 'all':
        filename_parts.append(scan_type)
    if start_date:
        filename_parts.append(f'from_{start_date}')
    if end_date:
        filename_parts.append(f'to_{end_date}')
    filename = '_'.join(filename_parts) + '.csv'

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )
