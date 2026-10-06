"""User API Routes"""
from flask import Blueprint, jsonify, g, request
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

@user_bp.route('/history', methods=['GET'])
@token_required
def history():
    from datetime import datetime, timezone
    uid = g.current_user['_id']
    limit_val = request.args.get('limit', 'all')
    start_date = request.args.get('start')
    end_date = request.args.get('end')
    
    q = {"user_id": uid}
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
    total = db.scans.count_documents({"user_id": uid})
    sms_count = db.scans.count_documents({"user_id": uid, "scan_type": "sms"})
    email_addr_count = db.scans.count_documents({"user_id": uid, "scan_type": "email_address"})
    email_body_count = db.scans.count_documents({"user_id": uid, "scan_type": "email_comprehensive"})
    url_count = db.scans.count_documents({"user_id": uid, "scan_type": "url"})

    dangerous = db.scans.count_documents({"user_id": uid, "verdict": "DANGEROUS"})
    phishing = db.scans.count_documents({"user_id": uid, "verdict": "PHISHING"})
    spam = db.scans.count_documents({"user_id": uid, "verdict": "SPAM"})
    suspicious = db.scans.count_documents({"user_id": uid, "verdict": "SUSPICIOUS"})
    
    safe = db.scans.count_documents({"user_id": uid,"verdict": {"$in": ['SAFE', 'LEGITIMATE','HAM']}})
    
    known_count = dangerous + phishing + spam + suspicious + safe
    unknown = total - known_count if total > known_count else 0

    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)    
    recent = db.scans.find({"user_id": uid,"created_at": {"$gte": thirty_days_ago}})

    daily = {}
    for s in recent:
        if 'created_at' in s and s['created_at']:
            day = s['created_at'].strftime('%Y-%m-%d')
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
    recent_cursor = db.scans.find({"user_id": uid}).sort("created_at", -1).limit(5)
    recent_scans = [serialize_scan(s) for s in recent_cursor]
    total = db.scans.count_documents({"user_id": uid})
    threats = db.scans.count_documents({"user_id": uid,"verdict": {"$in": ['DANGEROUS', 'PHISHING', 'SPAM', 'SUSPICIOUS']}})
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
