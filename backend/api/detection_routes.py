"""Detection API Routes"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from database import db
from auth.middleware import token_required,user_required
from detection.sms import sms_detector
from detection.email import email_detector
from detection.url import url_detector

detect_bp = Blueprint('detect', __name__, url_prefix='/api/scan')

def _save_scan(scan_type, input_text, result, user_id=None):

    # MongoDB handles nested dictionaries natively, no need for json.dumps
    details = {k: v for k, v in result.items() 
               if k not in ('link_inspections', 'deep_inspection')}

    # 1. Create the Scan Document
    scan_doc = {
        "user_id": user_id,
        "scan_type": scan_type,
        "input_text": input_text[:2000],
        "verdict": result.get('verdict', 'UNKNOWN'),
        "confidence": result.get('confidence', 0),
        "risk_score": result.get('risk_score', 0),
        "details": details,
        "created_at": datetime.now(timezone.utc)
    }
    # Insert Scan into MongoDB
    scan_result = db.scans.insert_one(scan_doc)
    scan_id = scan_result.inserted_id

    if user_id:
        db.users.update_one({"_id": user_id}, {"$inc": {"total_scans": 1}})

    # 2. Prepare Link Inspections
    links = result.get('link_inspections') or []
    if result.get('deep_inspection'):
        links = [result['deep_inspection']]

    link_docs = []
    for li in links:
        link_docs.append({
            "scan_id": scan_id,  
            "url": li.get('url', ''),
            "is_reachable": li.get('is_reachable', False),
            "final_url": li.get('final_url'),
            "redirect_count": li.get('redirect_count', 0),
            "ssl_valid": li.get('ssl_valid', False),
            "page_title": li.get('page_title'),
            "virustotal_score": li.get('virustotal_score'),
            "safe_browsing_flag": li.get('safe_browsing_flag', False),
            "verdict": li.get('verdict', 'UNKNOWN'),
            "risk_evidence": li.get('risk_evidence', []), # MongoDB handles lists natively
            "risk_score": li.get('risk_score', 0),
            "created_at": datetime.now(timezone.utc)
        })
        
    if link_docs:
        db.link_inspections.insert_many(link_docs)
    return str(scan_id)

@detect_bp.route('/sms', methods=['POST'])
@user_required
def scan_sms():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'success': False,'message': 'Invalid request body. JSON object expected.'}), 400

    input_text = str(data.get('input_text') or '').strip()
    if not input_text:
        return jsonify({'success': False,'message': 'SMS text is required'}), 400

    # Deep link inspection
    inspect = data.get('inspect_links', True)
    try:
        result = sms_detector.analyze_sms(input_text,inspect_links=inspect)

        # Save scan for the authenticated user
        scan_id = _save_scan('sms',input_text,result,user_id=g.current_user['_id'])
        return jsonify({'success': True,'scan_id': scan_id,'result': result})

    except FileNotFoundError as e:
        return jsonify({'success': False,'message': str(e)}), 503
    except Exception as e:
        print("SMS ANALYSIS ERROR:", repr(e))
        return jsonify({'success': False,'message': f'Analysis error: {str(e)}'}), 500
        
@detect_bp.route('/email-address', methods=['POST'])
@user_required
def scan_email_address():
    data = request.json
    email = data.get('email', '').strip()
    use_llm = data.get('use_llm', True)  

    if not email:
        return jsonify({'success': False, 'message': 'Email is required'})
        
 
    from detection.link.llm_inspector import analyze_email_with_llm
    sender_analysis = email_detector.analyze_email_address(email)    
    evidence = sender_analysis.get('risk_factors', [])
    risk_score = sender_analysis.get('risk_score', 0)
    
    email_llm_analysis = {}
    if use_llm:
        email_llm_analysis = analyze_email_with_llm(
            email=email,
            sender_analysis=sender_analysis,
            use_llm=use_llm
        )
        if email_llm_analysis.get('enabled') and email_llm_analysis.get('analysis'):
            evidence.append(f"AI Analysis: {email_llm_analysis.get('analysis')}")
    else:
        evidence.append("AI Deep Verification skipped via user toggle.")
    
    if not sender_analysis.get('is_valid', False):
        verdict = 'SUSPICIOUS' if risk_score < 70 else 'FAKE'
    else:
        verdict = 'SAFE'
        
    result = {"verdict": verdict,"risk_score": risk_score,"sender_analysis": sender_analysis,"llm_analysis": email_llm_analysis,"risk_evidence": evidence}
    try:
        scan_id = _save_scan('email-address',email,result,user_id=g.current_user['_id'])
    except Exception as e:
        print("Error saving to history:", repr(e))
        scan_id = None
    return jsonify({"success": True,"scan_id": str(scan_id) if scan_id else None,"result": result})

@detect_bp.route('/email-comprehensive/', methods=['POST'])
@user_required
def scan_email_comprehensive():
    try:
        data = request.get_json() or {}
        sender = data.get('sender', '').strip()
        subject = data.get('subject', '').strip()
        body = data.get('body', '').strip()
        use_llm = data.get('use_llm', True)
        inspect_links = data.get('inspect_links', True)

        if not sender and not body:
            return jsonify({'success': False,'error': 'Sender or email body is required'}), 400
        result = email_detector.analyze_email_comprehensive(sender=sender,subject=subject,body=body,inspect_links=inspect_links,use_llm=use_llm)
        return jsonify({'success': True,'result': result}), 200
    except FileNotFoundError as e:
        return jsonify({'success': False,'message': str(e)}), 503
    except Exception as e:
        print("EMAIL COMPREHENSIVE ANALYSIS ERROR:",repr(e))
        return jsonify({'success': False,'message': f'Analysis error: {str(e)}'}), 500

@detect_bp.route('/url', methods=['POST'])
@user_required
def scan_url():
    data = request.get_json()
    url = (data.get('url') or '').strip()
    if not url:
        return jsonify({'success': False, 'message': 'URL is required'}), 400
    inspect = data.get('deep_inspect', True)
    try:
        result = url_detector.analyze_url(url, do_inspect=inspect)
        scan_id = _save_scan('url', url, result, user_id=g.current_user['_id'])
        return jsonify({'success': True, 'scan_id': scan_id, 'result': result})
    except FileNotFoundError as e:
        return jsonify({'success': False, 'message': str(e)}), 503
    except Exception as e:
        return jsonify({'success': False, 'message': f'Analysis error: {str(e)}'}), 500


@detect_bp.route('/unified', methods=['POST'])
@user_required
def scan_unified():
    """Scan all types at once if fields provided"""
    data = request.get_json()
    results = {}
    if data.get('sms_text'):
        try:
            results['sms'] = sms_detector.analyze_sms(data['sms_text'])
            _save_scan('sms', data['sms_text'], results['sms'], g.current_user['_id'])
        except Exception as e:
            results['sms'] = {'error': str(e)}

    if data.get('email_address'):
        try:
            results['email_address'] = email_detector.analyze_email_address(data['email_address'])
            _save_scan('email_address', data['email_address'], results['email_address'], g.current_user['_id'])
        except Exception as e:
            results['email_address'] = {'error': str(e)}

    if data.get('email_comprehensive') or data.get('body') or data.get('sender'):
        try:
            comp_data = data.get('email_comprehensive') if isinstance(data.get('email_comprehensive'), dict) else data
            sender = comp_data.get('sender', '')
            subject = comp_data.get('subject', '')
            body = comp_data.get('body', '')
            
            results['email_comprehensive'] = email_detector.analyze_email_comprehensive(sender=sender,subject=subject,body=body)
            preview_text = f"Sender: {sender} | Subject: {subject} | Body: {body}"
            _save_scan('email_comprehensive', preview_text, results['email_comprehensive'], g.current_user['_id'])
        except Exception as e:
            results['email_comprehensive'] = {'error': str(e)}

    if data.get('url'):
        try:
            results['url'] = url_detector.analyze_url(data['url'])
            _save_scan('url', data['url'], results['url'], g.current_user['_id'])
        except Exception as e:
            results['url'] = {'error': str(e)}

    return jsonify({'success': True, 'results': results})