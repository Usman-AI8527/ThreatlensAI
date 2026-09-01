import base64
from urllib.parse import urlparse
import requests
import whois

def get_virustotal(target, target_type, api_key):
    if not api_key: return {'source':'VirusTotal','status':'error','data':{},'error':'VirusTotal API key not provided.'}
    try:
        if target_type == 'IP Address': endpoint=f'https://www.virustotal.com/api/v3/ip_addresses/{target}'
        elif target_type == 'Domain': endpoint=f'https://www.virustotal.com/api/v3/domains/{target}'
        elif target_type == 'URL':
            uid=base64.urlsafe_b64encode(target.encode()).decode().strip('='); endpoint=f'https://www.virustotal.com/api/v3/urls/{uid}'
        else: raise ValueError('Unsupported target type.')
        r=requests.get(endpoint,headers={'x-apikey':api_key},timeout=20)
        if r.status_code==401: raise Exception('Invalid VirusTotal API key.')
        if r.status_code==404: raise Exception('Target not found in VirusTotal.')
        if r.status_code==429: raise Exception('VirusTotal API rate limit reached.')
        r.raise_for_status(); a=r.json()['data']['attributes']; s=a.get('last_analysis_stats',{})
        return {'source':'VirusTotal','status':'success','data':{'malicious':s.get('malicious',0),'suspicious':s.get('suspicious',0),'harmless':s.get('harmless',0),'undetected':s.get('undetected',0),'reputation':a.get('reputation'),'country':a.get('country'),'asn':a.get('asn'),'owner':a.get('as_owner')},'error':None}
    except Exception as e: return {'source':'VirusTotal','status':'error','data':{},'error':str(e)}

def get_whois(target, target_type):
    try:
        if target_type=='URL': target=urlparse(target).hostname
        r=whois.whois(target)
        def clean(v): return [str(x) for x in v] if isinstance(v,list) else (None if v is None else str(v))
        data={k:clean(getattr(r,a,None)) for k,a in {'domain_name':'domain_name','registrar':'registrar','creation_date':'creation_date','expiration_date':'expiration_date','name_servers':'name_servers','organization':'org','country':'country'}.items()}
        data={k:v for k,v in data.items() if v not in [None,'','None','[]']}
        return {'source':'WHOIS','status':'success' if data else 'unavailable','data':data,'error':None if data else 'No WHOIS information available.'}
    except Exception as e: return {'source':'WHOIS','status':'error','data':{},'error':str(e)}

SOURCES={'VirusTotal':get_virustotal,'WHOIS':get_whois}
