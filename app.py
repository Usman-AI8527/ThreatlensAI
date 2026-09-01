import json,ipaddress,re
from urllib.parse import urlparse
import google.generativeai as genai
import streamlit as st
from sources import SOURCES
st.set_page_config(page_title='ThreatLens',page_icon='🛡️',layout='centered')
st.title('🛡️ ThreatLens'); st.caption('IP • Domain • URL Security Analyzer')
with st.sidebar:
    st.header('⚙️ Settings')
    vt_api_key=st.text_input('VirusTotal API Key',type='password')
    gemini_api_key=st.text_input('Gemini API Key',type='password')
    st.divider(); st.caption('Keys are used for the current session and are not stored by the app.')
def validate_target(t,typ):
    if not t.strip(): return False
    if typ=='IP Address':
        try: ipaddress.ip_address(t); return True
        except ValueError: return False
    if typ=='Domain': return bool(re.match(r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$',t))
    p=urlparse(t); return typ=='URL' and p.scheme in {'http','https'} and bool(p.netloc)
def collect(t,typ,key):
    out={}
    for n,f in SOURCES.items():
        try: out[n]=f(t,typ,key) if n=='VirusTotal' else f(t,typ)
        except Exception as e: out[n]={'source':n,'status':'error','data':{},'error':str(e)}
    return out
def verdict(r):
    v=r.get('VirusTotal',{}); d=v.get('data',{}) if v.get('status')=='success' else {}; m=d.get('malicious',0) or 0; s=d.get('suspicious',0) or 0
    return 'MALICIOUS' if m>=5 else ('SUSPICIOUS' if m>0 or s>=2 else ('SAFE' if v.get('status')=='success' else 'UNKNOWN'))
def prompt(t,typ,level,r):
    inst={'Beginner':'Use simple language and explain what was found, why it matters, and what to do.','Intermediate':'Give a moderately technical assessment covering detections, reputation, WHOIS, risk and actions.','Expert':'Give a detailed analyst assessment covering detection ratios, reputation, WHOIS, conflicts, limitations, confidence and actions.'}[level]
    return f'''You are ThreatLens AI. Analyze ONLY this supplied VirusTotal and WHOIS data. Do not independently investigate or invent facts. Missing data is unavailable. SAFE is not a guarantee.\nTarget: {t}\nType: {typ}\nLevel: {level}\nData: {json.dumps(r,default=str,indent=2)}\n{inst}\nReturn ONLY JSON: {{"verdict":"SAFE","confidence":"HIGH","summary":"Short assessment","key_findings":["Finding"],"risk_factors":["Risk"],"recommendation":"Action"}}. Allowed verdicts SAFE,SUSPICIOUS,MALICIOUS,UNKNOWN; confidence LOW,MEDIUM,HIGH.'''
def gemini(p,key):
    try:
        genai.configure(api_key=key); x=genai.GenerativeModel('gemini-2.5-flash').generate_content(p).text.strip().replace('```json','').replace('```','').strip(); return json.loads(x)
    except Exception as e: return {'verdict':'UNKNOWN','confidence':'LOW','summary':'Gemini analysis failed.','key_findings':[],'risk_factors':[],'recommendation':str(e)}
typ=st.selectbox('Target Type',['IP Address','Domain','URL']); t=st.text_input('Enter Target',placeholder={'IP Address':'8.8.8.8','Domain':'example.com','URL':'https://example.com'}[typ]); level=st.selectbox('Knowledge Level',['Beginner','Intermediate','Expert'])
if st.button('🔎 Analyze Target',type='primary',use_container_width=True):
    if not vt_api_key or not gemini_api_key: st.error('Enter both API keys in the sidebar.'); st.stop()
    if not validate_target(t,typ): st.error(f'Please enter a valid {typ}.'); st.stop()
    with st.spinner('🔍 Collecting threat intelligence...'): r=collect(t.strip(),typ,vt_api_key)
    v=verdict(r)
    with st.spinner('🤖 Generating AI insight...'): a=gemini(prompt(t.strip(),typ,level,r),gemini_api_key)
    st.divider(); st.write(f'**Target:** `{t}`'); st.write(f'**Type:** {typ}')
    {'SAFE':st.success,'SUSPICIOUS':st.warning,'MALICIOUS':st.error}.get(v,st.info)(f'🟢 SAFE' if v=='SAFE' else f'🟠 SUSPICIOUS' if v=='SUSPICIOUS' else f'🔴 MALICIOUS' if v=='MALICIOUS' else '⚪ UNKNOWN')
    st.subheader('🤖 AI Security Insight'); st.write('**Confidence:**',a.get('confidence','LOW')); st.write(a.get('summary','No summary available.'))
    for title,key in [('Key Findings','key_findings'),('Risk Factors','risk_factors')]:
        vals=a.get(key,[])
        if vals: st.markdown(f'**{title}**'); [st.write('•',x) for x in vals]
    st.markdown('**Recommendation**'); st.write(a.get('recommendation','No recommendation available.'))
    st.subheader('🔍 Source Results')
    for n,x in r.items():
        with st.expander(n):
            if x['status']=='success':
                for k,val in x['data'].items(): st.write(f'**{k.replace("_"," ").title()}:**',val)
            else: st.warning(x.get('error','Source unavailable.'))
    st.caption('ThreatLens provides an intelligence-based assessment, not a guarantee of safety.')
