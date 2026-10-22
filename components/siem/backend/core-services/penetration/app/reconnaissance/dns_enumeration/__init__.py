import requests
from flask import Blueprint, request, jsonify
import dns.resolver

def dns_lookup(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [answer.to_text() for answer in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return ['Domain does not exist']
    except Exception as e:
        return [f'Error: {str(e)}']


# Define the blueprint
dns_bp = Blueprint('dns_enumeration', __name__, url_prefix='/dns')

@dns_bp.route('/lookup', methods=['GET'])
def lookup():
    domain = request.args.get('domain')
    record_type = request.args.get('type', 'A')
    if not domain:
        return jsonify({'error': 'Domain parameter is required'}), 400
    
    results = dns_lookup(domain, record_type)
    return jsonify({'domain': domain, 'record_type': record_type, 'results': results})