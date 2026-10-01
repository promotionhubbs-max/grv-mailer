const GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN = "https://oauth2.googleapis.com/token";
const GMAIL_SEND = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send";

function htmlEscape(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function b64url(bytes) {
  let bin = "";
  for (let i=0;i<bytes.length;i+=0x8000) bin += String.fromCharCode(...bytes.slice(i,i+0x8000));
  return btoa(bin).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function utf8b64url(str) {
  return b64url(new TextEncoder().encode(str));
}
function randomId(n=24) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return b64url(a);
}
function json(data, status=200, extra={}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {"content-type":"application/json; charset=utf-8", "cache-control":"no-store", ...extra}
  });
}
function cookie(name, value, maxAge=3600) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const p of raw.split(";")) {
    const [k,...v] = p.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}
function parseJwtPayload(token) {
  try {
    const p = token.split(".")[1].replace(/-/g,"+").replace(/_/g,"/");
    return JSON.parse(atob(p + "=".repeat((4-p.length%4)%4)));
  } catch { return null; }
}
function standardB64(bytes) {
  let bin = "";
  for (let i=0;i<bytes.length;i+=0x8000) bin += String.fromCharCode(...bytes.slice(i,i+0x8000));
  return btoa(bin);
}
function mimeEncode(s) {
  const text = String(s ?? "");
  if (/^[\\x00-\\x7F]*$/.test(text)) return text;
  return "=?UTF-8?B?" + standardB64(new TextEncoder().encode(text)) + "?=";
}
function buildRaw({to, subject, body, senderName, replyTo, fromEmail}) {
  const headers = [
    `To: ${to}`,
    `Subject: ${mimeEncode(subject)}`,
    `From: ${mimeEncode(senderName || "Grv Mailer")} <${fromEmail}>`,
    ...(replyTo ? [`Reply-To: ${replyTo}`] : []),
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: 8bit"
  ];
  return headers.join("\r\n") + "\r\n\r\n" + String(body || "");
}
async function refreshAccessToken(env, token) {
  if (token.expires_at && Date.now() < token.expires_at - 60000) return token;
  const r = await fetch(GOOGLE_TOKEN, {
    method:"POST",
    headers:{"content-type":"application/x-www-form-urlencoded"},
    body:new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      grant_type:"refresh_token",
      refresh_token: token.refresh_token
    })
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error_description || data.error || "Token refresh failed");
  const updated = {...token, access_token:data.access_token, expires_at:Date.now() + (data.expires_in||3600)*1000};
  await env.GRV_KV.put("token", JSON.stringify(updated));
  return updated;
}
async function getToken(env) {
  const raw = await env.GRV_KV.get("token");
  return raw ? JSON.parse(raw) : null;
}
async function currentSession(request, env) {
  const sid = getCookie(request,"gm_session");
  if (!sid) return null;
  const s = await env.GRV_KV.get("session:"+sid, "json");
  if (!s || s.expires_at < Date.now()) return null;
  return {sid, ...s};
}
async function requireSession(request, env) {
  const s = await currentSession(request, env);
  if (!s) throw new Error("Not signed in");
  return s;
}
async function dashboard(env, request) {
  const session = await currentSession(request, env);
  return new Response(DASHBOARD_HTML.replace("__SIGNED_IN__", session ? "true":"false"), {
    headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store"}
  });
}

const DASHBOARD_HTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Grv Mailer</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f7fb;color:#172033}
.wrap{max-width:980px;margin:auto;padding:18px}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:16px}
.logo{font-size:25px;font-weight:800}.muted{color:#6b7280}.card{background:#fff;border:1px solid #e5e7eb;border-radius:16px;padding:18px;margin:12px 0;box-shadow:0 4px 18px #00000008}
button{border:0;border-radius:10px;padding:11px 15px;font-weight:700;cursor:pointer;background:#111827;color:#fff}button.secondary{background:#eef2f7;color:#111827}
input,textarea{width:100%;border:1px solid #d8dee9;border-radius:10px;padding:11px;font:inherit;margin-top:7px}textarea{min-height:150px;resize:vertical}
label{display:block;font-weight:700;margin:12px 0}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.stat{background:#f8fafc;border-radius:12px;padding:14px}.num{font-size:24px;font-weight:800}.status{padding:9px 11px;border-radius:10px;background:#f3f4f6;margin-top:10px;white-space:pre-wrap}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #edf0f4;font-size:14px}
.small{font-size:13px}.danger{color:#b91c1c}.ok{color:#047857}.warn{color:#92400e}
@media(max-width:700px){.grid,.stats{grid-template-columns:1fr 1fr}.top{align-items:flex-start}.logo{font-size:22px}}
@media(max-width:460px){.grid,.stats{grid-template-columns:1fr}.wrap{padding:12px}}
</style></head>
<body><div class="wrap">
<div class="top"><div><div class="logo">Grv Mailer</div><div class="muted">Live Gmail sending & campaign status</div></div><div id="auth"></div></div>

<div id="loginCard" class="card" style="display:none">
<h2>Connect Gmail</h2><p class="muted">Authorize the Gmail account you want to send from. Your Google password is never entered into Grv Mailer.</p>
<button onclick="location.href='/auth/google'">Continue with Google</button>
<p class="small muted">Use only recipient lists you are authorized to contact. Include an unsubscribe option for marketing mail.</p>
</div>

<div id="app" style="display:none">
<div class="card">
<h3>New campaign</h3>
<div class="grid">
<label>Sender name<input id="senderName" placeholder="Gaurav Sahu"></label>
<label>Reply-To<input id="replyTo" type="email" placeholder="reply@example.com"></label>
</div>
<label>Recipients <span class="muted small">(one email per line or comma separated)</span>
<textarea id="recipients" placeholder="person@example.com&#10;another@example.com"></textarea></label>
<label>Subject<input id="subject" placeholder="Your subject"></label>
<label>Message<textarea id="body" placeholder="Write your message here..."></textarea></label>
<div><button id="sendBtn" onclick="startCampaign()">Start sending</button></div>
<div id="status" class="status">Ready.</div>
</div>

<div class="card"><h3>Live status</h3><div class="stats">
<div class="stat"><div class="muted">Total</div><div id="sTotal" class="num">0</div></div>
<div class="stat"><div class="muted">Sent</div><div id="sSent" class="num">0</div></div>
<div class="stat"><div class="muted">Failed</div><div id="sFailed" class="num">0</div></div>
<div class="stat"><div class="muted">Remaining</div><div id="sRemaining" class="num">0</div></div>
</div></div>

<div class="card"><h3>Recent campaigns</h3><div id="campaigns" class="small muted">Loading…</div></div>
</div>

<div class="card small muted">Designed by Grv Sahu • Gmail API OAuth • No demo metrics</div>
</div>
<script>
const SIGNED_IN=__SIGNED_IN__;
const $=id=>document.getElementById(id);
async function api(path,opts={}){const r=await fetch(path,{...opts,headers:{'content-type':'application/json',...(opts.headers||{})}});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||'Request failed');return d}
function setAuth(signed){$('loginCard').style.display=signed?'none':'block';$('app').style.display=signed?'block':'none';$('auth').innerHTML=signed?'<button class="secondary" onclick="location.href=\\'/auth/logout\\'">Sign out</button>':''}
async function refresh(){if(!SIGNED_IN)return;try{const d=await api('/api/campaigns');let t=0,s=0,f=0;d.campaigns.forEach(c=>{t+=c.total;s+=c.sent;f+=c.failed});$('sTotal').textContent=t;$('sSent').textContent=s;$('sFailed').textContent=f;$('sRemaining').textContent=Math.max(0,t-s-f);$('campaigns').innerHTML=d.campaigns.length?'<table><tr><th>Campaign</th><th>Total</th><th>Sent</th><th>Failed</th><th>Created</th></tr>'+d.campaigns.slice(0,20).map(c=>'<tr><td>'+esc(c.id)+'</td><td>'+c.total+'</td><td class="ok">'+c.sent+'</td><td class="danger">'+c.failed+'</td><td>'+new Date(c.created_at).toLocaleString()+'</td></tr>').join('')+'</table>':'No campaigns yet.'}catch(e){$('campaigns').textContent=e.message}}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
async function startCampaign(){
 const raw=$('recipients').value.split(/[\\s,;]+/).map(x=>x.trim().toLowerCase()).filter(Boolean);
 const recipients=[...new Set(raw)].filter(x=>/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(x));
 if(!recipients.length)return $('status').textContent='Add at least one valid recipient.';
 if(recipients.length>100)return $('status').textContent='For this version, use up to 100 recipients per campaign.';
 const subject=$('subject').value.trim(),body=$('body').value,senderName=$('senderName').value.trim()||'Grv Mailer',replyTo=$('replyTo').value.trim();
 if(!subject||!body)return $('status').textContent='Subject and message are required.';
 $('sendBtn').disabled=true;$('status').textContent='Creating campaign…';
 try{
  const c=await api('/api/campaigns',{method:'POST',body:JSON.stringify({recipients,subject,body,senderName,replyTo})});
  let sent=0,failed=0;
  for(let i=0;i<recipients.length;i++){
   $('status').textContent='Sending '+(i+1)+'/'+recipients.length+'…';
   try{await api('/api/send',{method:'POST',body:JSON.stringify({campaignId:c.id,to:recipients[i]})});sent++}
   catch(e){failed++;$('status').textContent='Sending '+(i+1)+'/'+recipients.length+'… '+e.message}
   await new Promise(r=>setTimeout(r,900));
   $('sSent').textContent=sent;$('sFailed').textContent=failed;$('sTotal').textContent=recipients.length;$('sRemaining').textContent=recipients.length-sent-failed;
  }
  $('status').textContent='Finished. Sent: '+sent+' • Failed: '+failed;
  await refresh();
 }catch(e){$('status').textContent=e.message}
 finally{$('sendBtn').disabled=false}
}
setAuth(SIGNED_IN);refresh();setInterval(refresh,5000);
</script></body></html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (request.method === "GET" && url.pathname === "/") return dashboard(env, request);

      if (request.method === "GET" && url.pathname === "/auth/google") {
        const state = randomId(32);
        await env.GRV_KV.put("oauth_state:"+state, JSON.stringify({created_at:Date.now()}), {expirationTtl:600});
        const params = new URLSearchParams({
          client_id: env.GOOGLE_CLIENT_ID,
          redirect_uri: url.origin + "/oauth/google/callback",
          response_type:"code",
          access_type:"offline",
          prompt:"consent",
          scope:"https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/userinfo.email",
          state
        });
        return Response.redirect(GOOGLE_AUTH+"?"+params.toString(),302);
      }

      if (request.method === "GET" && url.pathname === "/oauth/google/callback") {
        const state=url.searchParams.get("state"), code=url.searchParams.get("code");
        if(!state || !code) return new Response("OAuth cancelled or missing parameters.",{status:400});
        const ok=await env.GRV_KV.get("oauth_state:"+state);
        await env.GRV_KV.delete("oauth_state:"+state);
        if(!ok) return new Response("Invalid or expired OAuth state.",{status:400});
        const tokenRes=await fetch(GOOGLE_TOKEN,{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body:new URLSearchParams({
          code,client_id:env.GOOGLE_CLIENT_ID,client_secret:env.GOOGLE_CLIENT_SECRET,
          redirect_uri:url.origin+"/oauth/google/callback",grant_type:"authorization_code"
        })});
        const tok=await tokenRes.json();
        if(!tokenRes.ok) return new Response("Google token exchange failed: "+(tok.error_description||tok.error),{status:400});
        const info=await fetch("https://www.googleapis.com/oauth2/v3/userinfo",{headers:{Authorization:"Bearer "+tok.access_token}});
        const profile=await info.json();
        const token={...tok,expires_at:Date.now()+(tok.expires_in||3600)*1000,email:profile.email||""};
        await env.GRV_KV.put("token",JSON.stringify(token));
        const sid=randomId(32);
        await env.GRV_KV.put("session:"+sid,JSON.stringify({email:token.email,expires_at:Date.now()+86400000}),{expirationTtl:86400});
        return new Response("",{status:302,headers:{Location:"/", "Set-Cookie":cookie("gm_session",sid,86400)}});
      }

      if (request.method === "GET" && url.pathname === "/auth/logout") {
        const sid=getCookie(request,"gm_session"); if(sid) await env.GRV_KV.delete("session:"+sid);
        return new Response("",{status:302,headers:{Location:"/", "Set-Cookie":cookie("gm_session","",0)}});
      }

      if (url.pathname.startsWith("/api/")) await requireSession(request,env);

      if (request.method === "GET" && url.pathname === "/api/campaigns") {
        const list=await env.GRV_KV.list({prefix:"campaign:"});
        const campaigns=[];
        for(const k of list.keys.slice(0,50)){
          const c=await env.GRV_KV.get(k.name,"json"); if(c) campaigns.push(c);
        }
        campaigns.sort((a,b)=>b.created_at-a.created_at);
        return json({campaigns});
      }

      if (request.method === "POST" && url.pathname === "/api/campaigns") {
        const b=await request.json();
        if(!Array.isArray(b.recipients)||b.recipients.length<1||b.recipients.length>100) return json({error:"1–100 recipients allowed."},400);
        const id="cmp_"+Date.now()+"_"+randomId(6);
        const c={id,total:b.recipients.length,sent:0,failed:0,created_at:Date.now(),subject:String(b.subject||"").slice(0,500),senderName:String(b.senderName||"Grv Mailer").slice(0,120)};
        await env.GRV_KV.put("campaign:"+id,JSON.stringify(c));
        for(const to of b.recipients) await env.GRV_KV.put("job:"+id+":"+to,JSON.stringify({campaignId:id,to,status:"queued",subject:b.subject,body:b.body,senderName:b.senderName,replyTo:b.replyTo}));
        return json({id});
      }

      if (request.method === "POST" && url.pathname === "/api/send") {
        const b=await request.json();
        const c=await env.GRV_KV.get("campaign:"+b.campaignId,"json");
        if(!c)return json({error:"Campaign not found."},404);
        const jobKey="job:"+b.campaignId+":"+b.to;
        const job=await env.GRV_KV.get(jobKey,"json");
        if(!job)return json({error:"Recipient not found in campaign."},404);
        if(job.status==="sent")return json({ok:true,alreadySent:true});
        const token=await getToken(env); if(!token) return json({error:"Gmail is not connected."},401);
        const fresh=await refreshAccessToken(env,token);
        const raw=buildRaw({to:job.to,subject:job.subject,body:job.body,senderName:job.senderName,replyTo:job.replyTo,fromEmail:fresh.email});
        const r=await fetch(GMAIL_SEND,{method:"POST",headers:{Authorization:"Bearer "+fresh.access_token,"Content-Type":"application/json"},body:JSON.stringify({raw:utf8b64url(raw)})});
        if(!r.ok){
          const e=await r.json().catch(()=>({}));
          await env.GRV_KV.put(jobKey,JSON.stringify({...job,status:"failed",error:e.error?.message||"Gmail API error",updated_at:Date.now()}));
          c.failed++; await env.GRV_KV.put("campaign:"+c.id,JSON.stringify(c));
          return json({error:e.error?.message||"Gmail API error"},400);
        }
        await env.GRV_KV.put(jobKey,JSON.stringify({...job,status:"sent",sent_at:Date.now()}));
        c.sent++; await env.GRV_KV.put("campaign:"+c.id,JSON.stringify(c));
        return json({ok:true});
      }

      return new Response("Not found",{status:404});
    } catch (e) {
      return json({error:e?.message||"Server error"},500);
    }
  }
};
