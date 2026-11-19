const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization"
};

function json(data, status=200) {
  return new Response(JSON.stringify(data), {status, headers:{...cors,"Content-Type":"application/json"}});
}
function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt:enc.encode(salt),iterations:180000,hash:"SHA-256"}, key, 256);
  return b64(bits);
}
async function tokenFor(user, secret) {
  const payload = b64(new TextEncoder().encode(JSON.stringify({id:user.id,role:user.role,exp:Date.now()+7*86400000})));
  const key = await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const sig = await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(payload));
  return payload+"."+b64(sig);
}
async function auth(req, env) {
  const t = (req.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
  if (!t || !env.JWT_SECRET) return null;
  const [payload,sig] = t.split(".");
  if (!payload || !sig) return null;
  const key = await crypto.subtle.importKey("raw",new TextEncoder().encode(env.JWT_SECRET),{name:"HMAC",hash:"SHA-256"},false,["verify"]);
  const raw = Uint8Array.from(atob(sig.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));
  const ok = await crypto.subtle.verify("HMAC",key,raw,new TextEncoder().encode(payload));
  if (!ok) return null;
  try {
    const p = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0))));
    if (p.exp < Date.now()) return null;
    return p;
  } catch { return null; }
}
function validUrl(s) {
  try { const u = new URL(s); return ["http:","https:"].includes(u.protocol); } catch { return false; }
}
function code(n=7) {
  const chars="abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
  let s=""; for(let i=0;i<n;i++) s+=chars[Math.floor(Math.random()*chars.length)]; return s;
}

export default {
 async fetch(req, env) {
  if (req.method==="OPTIONS") return new Response(null,{headers:cors});
  const url = new URL(req.url);
  const path = url.pathname;

  if (path.startsWith("/api/")) {
   try {
    if (path==="/api/register" && req.method==="POST") {
      const {name,email,password}=await req.json();
      if (!name || !email || !/^\S+@\S+\.\S+$/.test(email) || !password || password.length<10) return json({error:"Name, valid email and password (10+ characters) required."},400);
      const salt=crypto.randomUUID();
      const ph=salt+":"+await hashPassword(password,salt);
      try {
       const r=await env.DB.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").bind(name.slice(0,70),email.toLowerCase(),ph).run();
       const user={id:r.meta.last_row_id,name,email:email.toLowerCase(),role:"user"};
       return json({token:await tokenFor(user,env.JWT_SECRET),user:{id:user.id,name:user.name,email:user.email,role:user.role}});
      } catch { return json({error:"Email may already be registered."},409); }
    }
    if (path==="/api/login" && req.method==="POST") {
      const {email,password}=await req.json();
      const u=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind((email||"").toLowerCase()).first();
      if (!u || !password || !u.password_hash.includes(":")) return json({error:"Invalid email or password."},401);
      const [salt,stored]=u.password_hash.split(":");
      if (await hashPassword(password,salt)!==stored) return json({error:"Invalid email or password."},401);
      return json({token:await tokenFor(u,env.JWT_SECRET),user:{id:u.id,name:u.name,email:u.email,role:u.role}});
    }
    const user=await auth(req,env);
    if (!user) return json({error:"Please log in."},401);

    if (path==="/api/me") {
      const u=await env.DB.prepare("SELECT id,name,email,role,created_at FROM users WHERE id=?").bind(user.id).first();
      return json({user:u});
    }
    if (path==="/api/links" && req.method==="GET") {
      const rows=await env.DB.prepare("SELECT id,code,destination,title,clicks,created_at,active FROM links WHERE user_id=? ORDER BY id DESC LIMIT 100").bind(user.id).all();
      return json({links:rows.results});
    }
    if (path==="/api/links" && req.method==="POST") {
      const {destination,title}=await req.json();
      if (!validUrl(destination)) return json({error:"Please enter a valid http/https URL."},400);
      let short="";
      for(let i=0;i<5;i++){ short=code(); try { await env.DB.prepare("INSERT INTO links(user_id,code,destination,title) VALUES(?,?,?,?)").bind(user.id,short,destination.slice(0,2048),(title||"").slice(0,100)).run(); break; } catch(e) { if(i===4) throw e; } }
      return json({code:short,shortUrl:new URL("/"+short,req.url).toString()});
    }
    if (path==="/api/analytics") {
      const totals=await env.DB.prepare("SELECT COUNT(*) AS links, COALESCE(SUM(clicks),0) AS clicks FROM links WHERE user_id=?").bind(user.id).first();
      const earnings=await env.DB.prepare("SELECT COALESCE(SUM(amount_usd),0) AS total FROM earnings WHERE user_id=? AND status!='rejected'").bind(user.id).first();
      return json({links:totals.links,clicks:totals.clicks,earnings:earnings.total});
    }
    if (path==="/api/admin/summary") {
      if(user.role!=="admin") return json({error:"Admin only."},403);
      const users=await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
      const links=await env.DB.prepare("SELECT COUNT(*) AS n FROM links").first();
      const clicks=await env.DB.prepare("SELECT COUNT(*) AS n FROM clicks").first();
      return json({users:users.n,links:links.n,clicks:clicks.n});
    }
    if (path==="/api/admin/earnings" && req.method==="POST") {
      if(user.role!=="admin") return json({error:"Admin only."},403);
      const {userId,amount,reason}=await req.json();
      if(!Number.isInteger(userId)||typeof amount!=="number"||amount<=0||amount>1000) return json({error:"Invalid earning entry."},400);
      await env.DB.prepare("INSERT INTO earnings(user_id,amount_usd,reason,status) VALUES(?,?,?,'pending')").bind(userId,amount,(reason||"Manual adjustment").slice(0,160)).run();
      return json({ok:true});
    }
    return json({error:"Not found"},404);
   } catch(e) { return json({error:"Server error",detail:"Check Worker logs and database setup."},500); }
  }

  // Short-code redirect
  if (path.length>1 && !path.startsWith("/assets/")) {
    const c=path.slice(1);
    if (/^[A-Za-z0-9]{4,12}$/.test(c)) {
      const row=await env.DB.prepare("SELECT id,destination,active FROM links WHERE code=?").bind(c).first();
      if(row && row.active) {
        const cf=req.cf||{};
        await env.DB.prepare("UPDATE links SET clicks=clicks+1 WHERE id=?").bind(row.id).run();
        await env.DB.prepare("INSERT INTO clicks(link_id,country,referrer) VALUES(?,?,?)").bind(row.id,cf.country||"",req.headers.get("Referer")||"").run();
        return Response.redirect(row.destination,302);
      }
    }
  }
  return env.ASSETS.fetch(req);
 }
};
