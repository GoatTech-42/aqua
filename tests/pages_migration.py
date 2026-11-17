"""Real-Chrome Pages base/sign-in migration checks. No external API requests."""
import http.server, json, pathlib, subprocess, tempfile, threading, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
NEW='https://aqua-api.goattech.us/v1'
OLD='https://api.aqua.goattech.us/v1'
class MigrationTest(unittest.TestCase):
    def test_pages_storage_and_signin(self):
        cases=[('clean','aqua.goattech.us',None,NEW),('retired','aqua.goattech.us',OLD,NEW),('retired_slash','aqua.goattech.us',OLD+'/',NEW),('dev_override','aqua.goattech.us','http://localhost:3000/v1','http://localhost:3000/v1'),('custom_path','aqua.goattech.us',OLD+'/custom',OLD+'/custom'),('other_host','localhost',OLD,OLD),('same_origin','localhost',None,None)]
        for page in ['landing.html','console.html','playground.html']:
            for label,host,stored,expected in cases:
                with self.subTest(page=page,case=label):self.run_case(page,host,stored,expected)
    def run_case(self,page,host,stored,expected):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                self.send_response(200);self.send_header('content-type','text/html');self.end_headers()
                before='<script>localStorage.clear();const prior='+json.dumps(stored)+';if(prior!==null)localStorage.setItem("aqua_api_base",prior);window.calls=[];window.fetch=async function(url,opts){calls.push({url:String(url),credentials:opts&&opts.credentials});return {ok:true,json:async()=>String(url).endsWith("/auth/me")?{login:"test",role:"friend"}:{data:[]}};};</script>'
                after='''<script>addEventListener('load',async()=>{try{await Promise.resolve();const expected=EXPECTED;const origin=expected.replace(/\/v1$/,'');if(AQUA.baseUrl()!==expected)throw Error('wrong base '+AQUA.baseUrl());for(const a of document.querySelectorAll('[data-aqua-signin]'))if(a.getAttribute('href')!==origin+'/login/github')throw Error('stale sign-in');const me=calls.find(x=>x.url.endsWith('/auth/me'));if(PAGE==='console.html'&&(!me||me.url!==origin+'/auth/me'||me.credentials!=='include'))throw Error('stale session request');if(STORED!==null&&localStorage.getItem('aqua_api_base')!==expected)throw Error('storage was not preserved or migrated');document.body.dataset.migration='pass';}catch(e){document.body.dataset.migration='FAIL '+e.message;}});</script>'''
                want=expected or 'http://localhost:'+str(self.server.server_port)+'/v1'
                after=after.replace('EXPECTED',json.dumps(want)).replace('PAGE',json.dumps(page)).replace('STORED',json.dumps(stored))
                html=(ROOT/'ui'/page).read_text();self.wfile.write(html.replace('<head>','<head>'+before,1).replace('</body>',after+'</body>').encode())
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as profile:
                cmd=['google-chrome','--headless','--no-sandbox','--disable-gpu','--disable-dev-shm-usage','--no-proxy-server','--host-resolver-rules=MAP aqua.goattech.us 127.0.0.1','--user-data-dir='+profile,'--virtual-time-budget=1500','--dump-dom','http://'+host+':'+str(server.server_port)+'/'+page]
                result=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
                self.assertIn('data-migration="pass"',result.stdout,result.stdout[-2000:]+result.stderr[-300:])
        finally:server.shutdown();server.server_close()
if __name__=='__main__':unittest.main()
