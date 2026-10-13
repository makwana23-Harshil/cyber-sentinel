"""Admin API Routes"""
import csv
import io
import math
from flask import Blueprint, request, jsonify, g, Response
from database import db
from auth.middleware import admin_required
from datetime import datetime, timedelta, timezone
from bson.objectid import ObjectId

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

def serialize_user(user):
    if not user: return None
    user_dict = dict(user)
    user_dict['id'] = str(user_dict['_id'])
    del user_dict['_id']
    if user_dict.get('created_at'):
        user_dict['created_at'] = user_dict['created_at'].isoformat()
    if user_dict.get('last_login'):
        user_dict['last_login'] = user_dict['last_login'].isoformat()
    # Remove password hash before sending to frontend
    user_dict.pop('password_hash', None)
    return user_dict

def serialize_scan(scan):
    if not scan: return None
    scan_dict = dict(scan)
    scan_dict['id'] = str(scan_dict['_id'])
    del scan_dict['_id']
    user_id = scan.get('user_id')
    if user_id:
        try:
            obj_id = ObjectId(user_id) if not isinstance(user_id, ObjectId) else user_id
            user = db.users.find_one({"_id": obj_id}, {"name": 1})
            if user:
                scan_dict['user_id'] = user.get('name', 'Unknown User')
            else:
                scan_dict['user_id'] = 'Unknown User'
        except Exception:
            scan_dict['user_id'] = 'Unknown User'
    else:
        scan_dict['user_id'] = 'Anonymous'
    if scan_dict.get('created_at'):
        dt = scan_dict['created_at']
        if isinstance(dt, datetime):
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            scan_dict['created_at'] = dt.isoformat()
        else:
            scan_dict['created_at'] = str(dt)
    return scan_dict


def _scan_date_query(start_date, end_date):
    date_query = {}
    if start_date:
        date_query['$gte'] = datetime.strptime(start_date, '%Y-%m-%d').replace(
            tzinfo=timezone.utc)
    if end_date:
        date_query['$lt'] = datetime.strptime(end_date, '%Y-%m-%d').replace(
            tzinfo=timezone.utc) + timedelta(days=1)
    return date_query


@admin_bp.route('/users', methods=['GET'])
@admin_required
def get_users():
    purge_orphaned_scans()
    users_cursor = list(db.users.find().sort("created_at", -1))
    for u in users_cursor:
        uid_obj = u['_id']
        uid_str = str(uid_obj)
        # Count scans stored with EITHER ObjectId OR string user_id (handles both formats)
        actual_count = db.scans.count_documents({
            "$or": [
                {"user_id": uid_obj},
                {"user_id": uid_str}
            ]
        })
        u['total_scans'] = actual_count
    return jsonify({'success': True, 'users': [serialize_user(u) for u in users_cursor]})

@admin_bp.route('/user/<uid>', methods=['GET'])
@admin_required
def get_user(uid):
    try:
        user = db.users.find_one({"_id": ObjectId(uid)})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404            
        scans = db.scans.find({"user_id": uid}).sort("created_at", -1).limit(20)
        return jsonify({
            'success': True,
            'user': serialize_user(user),
            'scans': [serialize_scan(s) for s in scans]
        })
    except:
        return jsonify({'success': False, 'message': 'Invalid user ID'}), 400

@admin_bp.route('/user/<uid>/toggle', methods=['POST'])
@admin_required
def toggle_user(uid):
    try:
        user = db.users.find_one({"_id": ObjectId(uid)})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404            
        if user.get('role') == 'admin':
            return jsonify({'success': False, 'message': 'Cannot deactivate admin'}), 403
            
        new_status = not user.get('is_active', True)
        db.users.update_one({"_id": ObjectId(uid)}, {"$set": {"is_active": new_status}})
        return jsonify({'success': True,'message': f'User {"activated" if new_status else "deactivated"}', 
            'is_active': new_status
        })
    except:
        return jsonify({'success': False, 'message': 'Invalid ID'}), 400

def purge_orphaned_scans():
    """Delete scans from MongoDB scans collection ONLY if their user document is completely absent from the users collection in MongoDB."""
    try:
        all_scans = list(db.scans.find({"user_id": {"$ne": None}}, {"_id": 1, "user_id": 1}))
        orphaned_ids = []
        user_cache = {}

        for scan in all_scans:
            uid = scan.get('user_id')
            if not uid:
                continue
            uid_str = str(uid)

            if uid_str not in user_cache:
                u = None
                try:
                    u = db.users.find_one({"_id": ObjectId(uid_str)})
                except Exception:
                    pass
                if not u:
                    u = db.users.find_one({"_id": uid_str})
                
                # User is valid if the document exists in MongoDB users collection
                user_cache[uid_str] = (u is not None)

            # If user document is completely absent from MongoDB, scan is orphaned
            if not user_cache[uid_str]:
                orphaned_ids.append(scan['_id'])

        if orphaned_ids:
            db.scans.delete_many({"_id": {"$in": orphaned_ids}})
            db.link_inspections.delete_many({"scan_id": {"$in": orphaned_ids}})

        return len(orphaned_ids)
    except Exception as e:
        print("Error purging orphaned scans:", e)
        return 0


@admin_bp.route('/user/<uid>', methods=['DELETE'])
@admin_required
def delete_user(uid):
    try:
        user = db.users.find_one({"_id": ObjectId(uid)})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404            
        
        if user.get('role') == 'admin':
            return jsonify({'success': False, 'message': 'Cannot delete admin account'}), 403
            
        # Soft-delete user account (temporarily delete / deactivate while preserving scans for restore)
        db.users.update_one({"_id": ObjectId(uid)}, {"$set": {"is_deleted": True, "is_active": False}})

        return jsonify({'success': True, 'message': 'User account deleted temporarily. Scans preserved for restoration.'})
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid ID'}), 400


@admin_bp.route('/user/<uid>/restore', methods=['POST'])
@admin_bp.route('/user/<uid>/undelete', methods=['POST'])
@admin_required
def restore_user(uid):
    try:
        user = db.users.find_one({"_id": ObjectId(uid)})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
            
        if user.get('role') == 'admin':
            return jsonify({'success': False, 'message': 'Admin accounts are protected'}), 400

        db.users.update_one({"_id": ObjectId(uid)}, {"$set": {"is_deleted": False, "is_active": True}})
        return jsonify({'success': True, 'message': 'User account restored successfully', 'is_deleted': False, 'is_active': True})
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid ID'}), 400


@admin_bp.route('/scans/purge-orphaned', methods=['POST'])
@admin_required
def purge_orphaned_scans_endpoint():
    purged_count = purge_orphaned_scans()
    return jsonify({'success': True, 'message': f'Purged {purged_count} orphaned scan(s) from database', 'purged_count': purged_count})


@admin_bp.route('/scans', methods=['GET'])
@admin_required
def get_scans():
    purge_orphaned_scans()
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    scan_type = request.args.get('scan_type', 'all')
    start_date = request.args.get('start', '').strip()
    end_date = request.args.get('end', '').strip()
    per_page = 10
    skip = (page - 1) * per_page
    q = {}
    if scan_type != 'all':
        q['scan_type'] = scan_type

    if start_date or end_date:
        try:
            date_query = _scan_date_query(start_date, end_date)
        except ValueError:
            return jsonify({'success': False, 'message': 'Dates must use YYYY-MM-DD format'}), 400
        if date_query:
            q['created_at'] = date_query
        
    if search:
        matching_users = list(db.users.find({'name': {'$regex': search, '$options': 'i'}}))
        user_id_strs = [str(u['_id']) for u in matching_users]
        user_id_objs = [u['_id'] for u in matching_users]
        or_cond = [{'input_text': {'$regex': search, '$options': 'i'}}]
        if user_id_strs:
            or_cond.append({'user_id': {'$in': user_id_strs}})
        if user_id_objs:
            or_cond.append({'user_id': {'$in': user_id_objs}})
        q['$or'] = or_cond
    total = db.scans.count_documents(q)
    scans_cursor = db.scans.find(q).sort("created_at", -1).skip(skip).limit(per_page)
    pages = math.ceil(total / per_page)
    return jsonify({'success': True,'scans': [serialize_scan(s) for s in scans_cursor],
        'total': total,'pages': pages,'current_page': page
    })

@admin_bp.route('/stats', methods=['GET'])
@admin_required
def stats():
    purge_orphaned_scans()
    total_users = db.users.count_documents({"role": "user", "is_deleted": {"$ne": True}})
    total_scans = db.scans.count_documents({})
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    scans_today = db.scans.count_documents({"created_at": {"$gte": today_start}})
    threats_today = db.scans.count_documents({"created_at": {"$gte": today_start},
        "verdict": {"$in": ['DANGEROUS', 'PHISHING', 'SPAM']}
    })

    verdict_counts = db.scans.aggregate([{"$group": {"_id": "$verdict", "count": {"$sum": 1}}}])
    verdict_dist = {v["_id"]: v["count"] for v in verdict_counts if v["_id"]}
    type_counts = db.scans.aggregate([{"$group": {"_id": "$scan_type", "count": {"$sum": 1}}}])
    type_dist = {t["_id"]: t["count"] for t in type_counts if t["_id"]}
  
    # Daily & Hourly Activity
    thirty_ago = now - timedelta(days=30)
    seven_ago = now - timedelta(days=7)  
    recent_scans = db.scans.find({"created_at": {"$gte": thirty_ago}})
    daily = {}
    daily_by_type = {}
    hourly = {}
    
    for s in recent_scans:
        created_at = s.get('created_at')
        if created_at:
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
                
            day = created_at.strftime('%Y-%m-%d')
            daily[day] = daily.get(day, 0) + 1
            scan_type = s.get('scan_type') or 'unknown'
            scan_type = {'message': 'sms', 'email': 'email_body'}.get(scan_type, scan_type)
            type_counts_for_day = daily_by_type.setdefault(day, {})
            type_counts_for_day[scan_type] = type_counts_for_day.get(scan_type, 0) + 1
            if created_at >= seven_ago:
                h = created_at.strftime('%H')
                hourly[h] = hourly.get(h, 0) + 1

    # Top flagged domains
    top_domains_agg = db.link_inspections.aggregate([
        {"$match": {"verdict": {"$in": ['DANGEROUS', 'SUSPICIOUS']}}},
        {"$group": {"_id": "$url", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ])
    top_domains = [{'url': d['_id'], 'count': d['count']} for d in top_domains_agg]

    # Most active users (combines string and ObjectId user_id representations)
    all_scans = list(db.scans.find({"user_id": {"$ne": None}}, {"user_id": 1}))
    user_counts = {}
    for s in all_scans:
        uid = s.get('user_id')
        if not uid:
            continue
        uid_str = str(uid)
        user_counts[uid_str] = user_counts.get(uid_str, 0) + 1

    sorted_user_counts = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_users = []
    for uid_str, count in sorted_user_counts:
        try:
            u = None
            try:
                u = db.users.find_one({"_id": ObjectId(uid_str)})
            except Exception:
                pass
            if not u:
                u = db.users.find_one({"_id": uid_str})
            if u and not u.get('is_deleted', False):
                top_users.append({
                    'name': u.get('name') or 'User',
                    'email': u.get('email') or '',
                    'scans': count
                })
        except Exception:
            continue

    return jsonify({
        'success': True,
        'stats': {
            'total_users': total_users,
            'total_scans': total_scans,
            'scans_today': scans_today,
            'threats_blocked_today': threats_today,
            'verdict_distribution': verdict_dist,
            'type_distribution': type_dist,
            'daily_activity': daily,
            'daily_by_type': daily_by_type,
            'hourly_activity': hourly,
            'top_flagged_domains': top_domains,
            'top_users': top_users
        }
    })


@admin_bp.route('/dashboard', methods=['GET'])
@admin_required
def dashboard():
    purge_orphaned_scans()
    total_users = db.users.count_documents({"role": "user", "is_deleted": {"$ne": True}})
    total_scans = db.scans.count_documents({})
    recent_scans = db.scans.find().sort("created_at", -1).limit(10)
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    threats_today = db.scans.count_documents({"created_at": {"$gte": today_start},"verdict": {"$in": ['DANGEROUS', 'PHISHING', 'SPAM']}})
    new_users_today = db.users.count_documents({"created_at": {"$gte": today_start}, "is_deleted": {"$ne": True}})

    return jsonify({
        'success': True,
        'dashboard': {
            'admin': serialize_user(g.current_user),
            'total_users': total_users,
            'total_scans': total_scans,
            'threats_today': threats_today,
            'new_users_today': new_users_today,
            'recent_scans': [serialize_scan(s) for s in recent_scans]
        }
    })


@admin_bp.route('/export/csv', methods=['GET'])
@admin_required
def export_scans_csv():
    """Export all platform scans as CSV, honouring scan_type, search, and date filters."""
    purge_orphaned_scans()
    scan_type  = request.args.get('scan_type', 'all').strip()
    search     = request.args.get('search', '').strip()
    start_date = request.args.get('start', '').strip()
    end_date   = request.args.get('end', '').strip()

    q = {}
    if scan_type and scan_type != 'all':
        q['scan_type'] = scan_type

    if start_date or end_date:
        try:
            date_q = _scan_date_query(start_date, end_date)
        except ValueError:
            return jsonify({'success': False, 'message': 'Dates must use YYYY-MM-DD format'}), 400
        if date_q:
            q['created_at'] = date_q

    if search:
        matching_users = list(db.users.find({'name': {'$regex': search, '$options': 'i'}}))
        user_id_strs = [str(u['_id']) for u in matching_users]
        user_id_objs = [u['_id'] for u in matching_users]
        or_cond = [{'input_text': {'$regex': search, '$options': 'i'}}]
        if user_id_strs:
            or_cond.append({'user_id': {'$in': user_id_strs}})
        if user_id_objs:
            or_cond.append({'user_id': {'$in': user_id_objs}})
        q['$or'] = or_cond

    scans = list(db.scans.find(q).sort('created_at', -1))

    # Build user-id → name cache to avoid N+1 queries
    user_cache = {}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['#', 'Scan Type', 'User', 'Input / Content', 'Verdict', 'Risk Score', 'Confidence (%)', 'Scanned At'])

    type_labels = {
        'sms': 'SMS',
        'email_address': 'Email Address',
        'email-address': 'Email Address',
        'email_comprehensive': 'Email Comprehensive',
        'url': 'URL',
    }

    for i, s in enumerate(scans, 1):
        scan_type_label = type_labels.get(
            s.get('scan_type', ''),
            (s.get('scan_type') or 'Scan').replace('_', ' ').title()
        )
        uid = s.get('user_id')
        uid_str = str(uid) if uid else None
        if uid_str and uid_str not in user_cache:
            try:
                u = db.users.find_one({'_id': ObjectId(uid_str)}, {'name': 1})
                user_cache[uid_str] = u.get('name', 'Unknown') if u else 'Unknown'
            except Exception:
                user_cache[uid_str] = uid_str
        user_name = user_cache.get(uid_str, 'Anonymous') if uid_str else 'Anonymous'

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
            user_name,
            (s.get('input_text') or '')[:500],
            s.get('verdict', ''),
            s.get('risk_score', ''),
            confidence,
            created,
        ])

    filename_parts = ['cybersentinel_admin_scans']
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
