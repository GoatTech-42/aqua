"""Session-gate browser checks against real page scripts; no live services."""
import http.server,json,pathlib,subprocess,tempfile,threading,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class GateTest(unittest.TestCase):
    def test_session_gate(self):
        for page in ['console.html','playground.html']:
            for mode in ['owner','friend','history','denied','network','malformed','pending','timeout']:
                with self.subTest(page=page,mode=mode):self.run_case(page,mode)
    def run_case(self,page,mode):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                self.send_response(200);self.send_header('content-type','text/html');self.end_headers()
                if self.path=='/':
                    self.wfile.write(b'<body data-gate="redirected"></body>');return
                before='''<script>if(localStorage.getItem('history-restore-probe')==='yes'){localStorage.removeItem('history-restore-probe');document.addEventListener('DOMContentLoaded',()=>document.body.dataset.gate='pass');}localStorage.setItem('aqua_key','existing-key');window.calls=[];window.fetch=async function(url,opts){calls.push({url:String(url),credentials:opts&&opts.credentials,cache:opts&&opts.cache});if(String(url).endsWith('/auth/me')){if(MODE==='network')throw Error('offline');if(MODE==='pending'||MODE==='timeout')return new Promise((_,reject)=>opts.signal.addEventListener('abort',()=>reject(Error('aborted'))));return {ok:MODE!=='denied',json:async()=>MODE==='malformed'?{role:'owner'}:{login:'sam',role:MODE==='owner'?'owner':'friend'}};}return {ok:true,json:async()=>({data:[],users:{},units_per_usd:1e9,default_friend_caps:{daily:2e9,monthly:15e9},accounting_available:true})};};</script>'''.replace('MODE',json.dumps(mode))
                after='''<script>addEventListener('load',async()=>{await new Promise(r=>setTimeout(r,150));try{const mode=MODE;if(mode==='history'&&document.body.dataset.gate==='pass')return;const visible=getComputedStyle(document.documentElement).visibility!=='hidden';if(mode==='pending'){if(visible)throw Error('pending session revealed UI');if(calls.some(x=>!x.url.endsWith('/auth/me')))throw Error('API before session');}else if(mode==='owner'||mode==='friend'||mode==='history'){if(!visible)throw Error('valid session blocked');const me=calls.filter(x=>x.url.endsWith('/auth/me'));if(me.length!==1||me[0].credentials!=='include'||me[0].cache!=='no-store')throw Error('session request not credentialed fresh single check');if(mode==='history'){dispatchEvent(new PageTransitionEvent('pagehide',{persisted:true}));if(getComputedStyle(document.documentElement).visibility!=='hidden')throw Error('cached interactive frame remains visible');localStorage.setItem('history-restore-probe','yes');dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));return;}if(PAGE==='console.html'&&document.querySelector('#aqua-usage'))throw Error('admin controls remain in console');}else throw Error('failed session did not redirect');document.body.dataset.gate='pass';}catch(e){document.body.dataset.gate='FAIL '+e.message;}});</script>'''.replace('MODE',json.dumps(mode)).replace('PAGE',json.dumps(page))
                html=(ROOT/'ui'/page).read_text();self.wfile.write(html.replace('<head>','<head>'+before,1).replace('</body>',after+'</body>').encode())
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as profile:
                cmd=['google-chrome','--headless','--no-sandbox','--disable-gpu','--disable-dev-shm-usage','--user-data-dir='+profile,'--virtual-time-budget='+('11000' if mode=='timeout' else '500'),'--dump-dom','http://127.0.0.1:'+str(server.server_port)+'/'+page]
                r=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
                expected='redirected' if mode in ['denied','network','malformed','timeout'] else 'pass'
                self.assertIn('data-gate="'+expected+'"',r.stdout,r.stdout[-1800:]+r.stderr[-300:])
        finally:server.shutdown();server.server_close()
if __name__=='__main__':unittest.main()
