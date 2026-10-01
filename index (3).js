const GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN = "https://oauth2.googleapis.com/token";
const GMAIL_SEND = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send";
const GMAIL_PROFILE = "https://gmail.googleapis.com/gmail/v1/users/me/profile";

const HTML = `<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Grv Mailer</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f5f7fb;margin:0;color:#182033}
.wrap{max-width:900px;margin:auto;padding:24px}
.card{background:white;border-radius:18px;padding:20px;margin:14px 0;box-shadow:0 4px 18px #00000010}
h1{margin:0 0 6px}.muted{color:#667085}
input,textarea{width:100%;box-sizing:border-box;padding:12px;border:1px solid #d0d5dd;border-radius:10px;margin:6px 0 12px;font-size:15px}
textarea{min-height:150px;resize:vertical}
button{border:0;border-radius:10px;padding:12px 18px;font-weight:700;cursor:pointer}
.primary{background:#111827;color:white}.google{background:#fff;border:1px solid #d0d5dd}
.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.badge{display:inline-block;padding:5px 9px;border-radius:999px;background:#eef2ff}
pre{white-space:pre-wrap;background:#f8fafc;padding:12px;border-radius:10px}
@media(max-width:650px){.row{grid-template-columns:1fr}.wrap{padding:14px}}
</style>
</head>
<body><div class="wrap">
<div class="card">
<h1>Grv Mailer</h1>
<div class="muted">Live Gmail sending & campaign status</div>
<p><span class="badge" id="auth">Checking Gmail...</span></p>
<div id="login"><button class="google" onclick="location.href='/auth/google'">Continue with Google</button></div>
</div>

<div class="card" id="app" style="display:none">
<label>Recipients — one email per line</label>
<textarea id="recipients" placeholder="name@example.com&#10;another@example.com"></textarea>
<div class="row">
<div><label>Subject</label><input id="subject" placeholder="Subject"></div>
<div><label>Sender name</label><input id="sender" placeholder="Gaurav Sahu"></div>
</div>
<label>Reply-To (optional)</label>
<input id="replyTo" placeholder="reply@example.com">
<label>Message</label>
<textarea id="body" placeholder="Write your email..."></textarea>
<label><input type="checkbox" id="permission" style="width:auto"> I confirm these recipients are permitted to receive this email and I will honor opt-outs.</label>
<br><br><button class="primary" onclick="sendCampaign()">Send individually</button>
</div>

<div class="card">
<h3>Campaign status</h3>
<pre id="status">No campaign yet.</pre>
</div>

<div class="muted">Designed by Grv Sahu • Gmail API OAuth • No demo metrics</div>
</div>
<script>
let timer;
async function check(){
 const r=await fetch('/api/me'); const d=await r.json();
 document.getElementById('auth').textContent=d.connected?('Connected: '+d.email):'Not connected';
 document.getElementById('login').style.display=d.connected?'none':'block';
 document.getElementById('app').style.display=d.connected?'block':'none';
}
async function sendCampaign(){
 if(!document.getElementById('permission').checked){alert('Please confirm recipient permission first.');return;}
 const recipients=document.getElementById('recipients').value.split(/\\s*[\\n,;]+\\s*/).map(x=>x.trim()).filter(Boolean);
 const payload={recipients,subject:subject.value,body:body.value,senderName:sender.value,replyTo:replyTo.value};
 const r=await fetch('/api/campaign',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
 const d=await r.json(); if(!r.ok){alert(d.error||'Could not start campaign');return;}
 document.getElementById('status').textContent=JSON.stringify(d,null,2);
 if(timer)clearInterval(timer); timer=setInterval(()=>poll(d.campaignId),2000);
}
async function poll(id){
 const r=await fetch('/api/campaign/'+encodeURIComponent(id)); const d=await r.json();
 document.getElementById('status').textContent=JSON.stringify(d,null,2);
 if(d.done)clearInterval(timer);
}
check();
</script>
</body></html>`;

function json(data,status=200){
 return new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store"}});
}
function b64urlBytes(bytes){
 let s=""; for(const b of bytes)s+=String.fromCharCode(b);
 return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function b64urlText(s){return b64urlBytes(new TextEncoder().encode(s));}
function htmlEscape(s=""){return s.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function randomId(){return crypto.randomUUID().replaceAll("-","");}
function decodeJwtPayload(jwt){
 try{
  const p=jwt.split(".")[1].replace(/-/g,"+").replace(/_/g,"/");
  return JSON.parse(atob(p+"=".repeat((4-p.length%4)%4)));
 }catch{return null}
}
function validEmail(x){return /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(x)}

async function tokenFor(request,env){
 const cookie=request.headers.get("Cookie")||"";
 const m=cookie.match(/grv_session=([^;]+)/);
 if(!m)return null;
 const session=await env.GRV_KV.get("session:"+m[1],"json");
 if(!session)return null;
 const saved=await env.GRV_KV.get("token:"+session.sub,"json");
 if(!saved)return null;
 if(saved.expiresAt>Date.now()+60000)return {...saved,sub:session.sub,email:session.email};
 const body=new URLSearchParams({
  client_id:env.GOOGLE_CLIENT_ID,client_secret:env.GOOGLE_CLIENT_SECRET,
  refresh_token:saved.refreshToken,grant_type:"refresh_token"
 });
 const tr=await fetch(GOOGLE_TOKEN,{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body});
 const td=await tr.json();
 if(!tr.ok||!td.access_token)throw new Error("Gmail authorization expired. Please connect Google again.");
 const fresh={refreshToken:saved.refreshToken,accessToken:td.access_token,expiresAt:Date.now()+((td.expires_in||3600)*1000)};
 await env.GRV_KV.put("token:"+session.sub,JSON.stringify(fresh));
 return {...fresh,sub:session.sub,email:session.email};
}

async function gmailSend(accessToken,to,subject,body,senderName,replyTo){
 const lines=[
  `To: ${to}`,
  `Subject: ${subject.replace(/[\\r\\n]/g," ")}`,
  `MIME-Version: 1.0`,
  `Content-Type: text/plain; charset="UTF-8"`,
  `Content-Transfer-Encoding: 8bit`
 ];
 if(senderName)lines.unshift(`From: ${senderName.replace(/[\\r\\n]/g," ")} <me>`);
 if(replyTo)lines.splice(senderName?1:0,0,`Reply-To: ${replyTo.replace(/[\\r\\n]/g," ")}`);
 const raw=lines.join("\\r\\n")+"\\r\\n\\r\\n"+body;
 const r=await fetch(GMAIL_SEND,{method:"POST",headers:{Authorization:`Bearer ${accessToken}`,"content-type":"application/json"},body:JSON.stringify({raw:b64urlText(raw)})});
 const d=await r.json();
 if(!r.ok)throw new Error(d?.error?.message||"Gmail send failed");
 return d.id;
}

export default {
 async fetch(request,env,ctx){
  try{
   const url=new URL(request.url);

   if(url.pathname==="/")return new Response(HTML,{headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store"}});

   if(url.pathname==="/auth/google"){
    if(!env.GOOGLE_CLIENT_ID||!env.GRV_KV)
      return new Response("Server OAuth configuration is incomplete.",{status:500});
    const state=randomId();
    const verifier=randomId()+randomId()+randomId()+randomId();
    const digest=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(verifier));
    const challenge=b64urlBytes(new Uint8Array(digest));
    await env.GRV_KV.put("oauth:"+state,JSON.stringify({created:Date.now(),verifier}),{expirationTtl:600});
    const redirect=url.origin+"/oauth/google/callback";
    const p=new URLSearchParams({
      client_id:env.GOOGLE_CLIENT_ID,redirect_uri:redirect,response_type:"code",
      access_type:"offline",prompt:"consent",
      scope:"openid email profile https://www.googleapis.com/auth/gmail.send",
      state,code_challenge:challenge,code_challenge_method:"S256"
    });
    return Response.redirect(GOOGLE_AUTH+"?"+p.toString(),302);
   }

   if(url.pathname==="/oauth/google/callback"){
    const code=url.searchParams.get("code"),state=url.searchParams.get("state"),err=url.searchParams.get("error");
    if(err)return new Response("Google authorization failed: "+err,{status:400});
    const valid=state?await env.GRV_KV.get("oauth:"+state,"json"):null;
    if(!valid)return new Response("Invalid or expired OAuth state.",{status:400});
    await env.GRV_KV.delete("oauth:"+state);
    const redirect=url.origin+"/oauth/google/callback";
    const tr=await fetch(GOOGLE_TOKEN,{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},
      body:new URLSearchParams({code,client_id:env.GOOGLE_CLIENT_ID,redirect_uri:redirect,grant_type:"authorization_code",code_verifier:valid.verifier})});
    const td=await tr.json();
    if(!tr.ok||!td.access_token)return new Response("Google token exchange failed: "+(td.error_description||td.error||"unknown error"),{status:400});
    const claims=decodeJwtPayload(td.id_token||"");
    const profile=await fetch(GMAIL_PROFILE,{headers:{Authorization:"Bearer "+td.access_token}});
    const pd=await profile.json();
    const sub=claims?.sub||pd.emailAddress;
    const email=claims?.email||pd.emailAddress;
    if(!sub)return new Response("Could not determine Google account.",{status:400});
    await env.GRV_KV.put("token:"+sub,JSON.stringify({
      refreshToken:td.refresh_token,
      accessToken:td.access_token,
      expiresAt:Date.now()+((td.expires_in||3600)*1000)
    }));
    const session=randomId();
    await env.GRV_KV.put("session:"+session,JSON.stringify({sub,email}),{expirationTtl:2592000});
    return new Response(null,{status:302,headers:{Location:"/", "Set-Cookie":`grv_session=${session}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`}});
   }

   if(url.pathname==="/api/me"){
    try{
      const t=await tokenFor(request,env);
      return json(t?{connected:true,email:t.email}:{connected:false});
    }catch(e){return json({connected:false,error:e.message})}
   }

   if(url.pathname==="/api/campaign" && request.method==="POST"){
    const t=await tokenFor(request,env);
    if(!t)return json({error:"Connect Gmail first."},401);
    const data=await request.json();
    const recipients=[...new Set((data.recipients||[]).map(x=>String(x).trim()).filter(validEmail))];
    if(!recipients.length)return json({error:"Add at least one valid recipient."},400);
    if(recipients.length>100)return json({error:"Maximum 100 recipients per campaign."},400);
    if(!data.subject||!data.body)return json({error:"Subject and message are required."},400);
    if(data.replyTo && !validEmail(data.replyTo))return json({error:"Reply-To email is invalid."},400);
    const id=randomId();
    const campaign={campaignId:id,createdAt:new Date().toISOString(),total:recipients.length,sent:0,failed:0,pending:recipients.length,done:false,results:[]};
    await env.GRV_KV.put("campaign:"+id,JSON.stringify(campaign),{expirationTtl:86400});
    // Run sequentially. The response is immediate; the client polls status.
    // Cloudflare may terminate long-running work after the request lifecycle, so use waitUntil.
    const work=(async()=>{
      for(const to of recipients){
        let result;
        try{
          const msgId=await gmailSend(t.accessToken,to,String(data.subject),String(data.body),String(data.senderName||""),String(data.replyTo||""));
          result={to,status:"sent",messageId:msgId};
          campaign.sent++;
        }catch(e){
          result={to,status:"failed",error:e.message};
          campaign.failed++;
        }
        campaign.pending=campaign.total-campaign.sent-campaign.failed;
        campaign.results.push(result);
        await env.GRV_KV.put("campaign:"+id,JSON.stringify(campaign),{expirationTtl:86400});
        // small pause to avoid bursting requests
        await new Promise(r=>setTimeout(r,700));
      }
      campaign.done=true;
      campaign.finishedAt=new Date().toISOString();
      await env.GRV_KV.put("campaign:"+id,JSON.stringify(campaign),{expirationTtl:86400});
    })();
    ctx.waitUntil(work);
    // In Workers, waitUntil is available from execution context; attach through ctx when provided.
    return json({campaignId:id,total:recipients.length,started:true});
   }

   if(url.pathname.startsWith("/api/campaign/")){
    const id=url.pathname.split("/").pop();
    const c=await env.GRV_KV.get("campaign:"+id,"json");
    return c?json(c):json({error:"Campaign not found."},404);
   }

   return new Response("Not Found",{status:404});
  }catch(e){
   return json({error:e.message||"Server error"},500);
  }
 }
};
