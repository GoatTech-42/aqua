"""Real-Chrome checks for the owner usage panel. No live accounts/providers."""
import http.server, json, pathlib, subprocess, tempfile, threading, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
class PanelTest(unittest.TestCase):
    def run_case(self, mode, check, screenshot=None, width=1440, height=1000):
        posts=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                self.send_response(200);self.send_header('content-type','application/json' if self.path!='/console.html' else 'text/html');self.end_headers()
                if self.path=='/auth/me': data={'login':'luke','role':'friend' if mode=='friend' else 'owner'}
                elif self.path=='/v1/models': data={'data':[]}
                elif self.path=='/v1/admin/usage':
                    data={'units_per_usd':1000000000,'accounting_available':mode!='outage','unknown_owner_requests_since_startup':0,'default_friend_caps':{'daily':2000000000,'monthly':15000000000},'users':{'luke':{'cap':None,'unknown_requests':0,'day':{'models':{'coder-a':{'confirmed':1234567,'held':0}}},'month':{'models':{'coder-a':{'confirmed':1234567,'held':0}}}},'sam':{'cap':{'daily':2000000000,'monthly':15000000000},'unknown_requests':1,'day':{'models':{'coder-a':{'confirmed':0,'held':20000000}}},'month':{'models':{'coder-a':{'confirmed':0,'held':20000000}}}}}}
                    if mode=='empty':data['users']={}
                    if mode=='zero':data['users']['sam']['cap']={'daily':0,'monthly':0}
                else:
                    html=(ROOT/'ui/console.html').read_text()
                    script="""<script>
                    addEventListener('load',async()=>{
                      try {
                        for(let i=0;i<100;i++) {if(document.querySelector('#aqua-usage-status')?.textContent.includes('Updated') || document.querySelector('#aqua-usage-status')?.textContent.includes('unavailable') || document.querySelector('#aqua-usersub')?.textContent==='friend') break; await new Promise(r=>setTimeout(r,10));}
                        CHECK
                        document.body.dataset.testResult='pass';
                      } catch(e) {document.body.dataset.testResult='FAIL: '+e.message;}
                    });</script>""".replace('CHECK',check)
                    self.wfile.write(html.replace('</body>',script+'</body>').encode());return
                self.wfile.write(json.dumps(data).encode())
            def do_POST(self):
                posts.append(json.loads(self.rfile.read(int(self.headers['content-length']))));self.send_response(200);self.send_header('content-type','application/json');self.end_headers();self.wfile.write(b'{}')
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as profile:
                cmd=['google-chrome','--headless','--no-sandbox','--disable-gpu','--disable-dev-shm-usage','--no-first-run','--no-default-browser-check','--user-data-dir='+profile,'--window-size='+str(width)+','+str(height),'--virtual-time-budget=3000','--dump-dom']
                if screenshot:cmd+=['--screenshot='+screenshot]
                cmd+=['http://127.0.0.1:'+str(server.server_port)+'/console.html']
                result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=30)
                self.assertIn('data-test-result="pass"',result.stdout,result.stdout[-3500:]+result.stderr[-600:])
        finally:server.shutdown();server.server_close()
        return posts
    def test_owner_sees_usage_and_submits_decimal_cap_strings(self):
        posts=self.run_case('owner',"""
          const panel=document.querySelector('#aqua-usage');if(!panel || panel.hidden)throw Error('owner panel missing');
          if(!panel.textContent.includes('$0.001235') || !panel.textContent.includes('Uncapped'))throw Error('usage/owner exemption missing');
          document.querySelector('#aqua-cap-name').value='sam';document.querySelector('#aqua-cap-daily').value='3';document.querySelector('#aqua-cap-monthly').value='20';
          document.querySelector('#aqua-cap-form').requestSubmit();await new Promise(r=>setTimeout(r,100));
          if(!document.querySelector('#aqua-cap-message').textContent.includes('Saved'))throw Error('save feedback missing');
        """)
        self.assertEqual(posts,[{'name':'sam','daily':'3','monthly':'20'}])
    def test_friend_cannot_see_owner_panel(self):
        self.assertEqual(self.run_case('friend',"if(!document.querySelector('#aqua-usage')?.hidden)throw Error('friend panel exposed');"),[])
    def test_zero_accounts_says_no_usage_not_fake_totals(self):
        self.run_case('empty',"if(!document.querySelector('#aqua-usage').textContent.includes('No usage recorded'))throw Error('empty state missing');")
    def test_zero_cap_round_trips_without_blank_or_owner_submission(self):
        posts=self.run_case('zero',"""
          const name=document.querySelector('#aqua-cap-name');name.value='sam';name.dispatchEvent(new Event('change'));
          if(document.querySelector('#aqua-cap-daily').value!=='0'||document.querySelector('#aqua-cap-monthly').value!=='0')throw Error('zero limit became blank');
          name.value='luke';document.querySelector('#aqua-cap-form').requestSubmit();await new Promise(r=>setTimeout(r,30));
          if(!document.querySelector('#aqua-cap-message').textContent.includes('uncapped'))throw Error('owner cap accepted');
        """)
        self.assertEqual(posts,[])
    def test_accounting_outage_is_visible(self):
        self.run_case('outage',"if(!document.querySelector('#aqua-usage-status').textContent.includes('unavailable'))throw Error('outage hidden');")
if __name__=='__main__':unittest.main()
