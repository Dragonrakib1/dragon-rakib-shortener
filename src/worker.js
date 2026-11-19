
const encoder = new TextEncoder();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

function randomCode(length = 7) {
  const chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return [...bytes].map(b => chars[b % chars.length]).join("");
}

function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function passwordHash(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    key, 256
  );
  return `${b64(salt)}.${b64(bits)}`;
}

async function verifyPassword(password, stored) {
  const [saltText, hashText] = stored.split(".");
  const salt = Uint8Array.from(atob(saltText.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const result = await passwordHash(password, salt);
  return result.split(".")[1] === hashText;
}

async function makeToken(user, secret) {
  const header = b64(encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const payload = b64(encoder.encode(JSON.stringify({
    id: user.id, exp: Math.floor(Date.now() / 1000) + 86400 * 7
  })));
  const data = `${header}.${payload}`;
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return `${data}.${b64(signature)}`;
}

async function getUser(request, env) {
  const token = request.headers.get("Authorization")?.replace("Bearer ", "");
  if (!token || !env.JWT_SECRET) return null;
  try {
    const [h, p, sig] = token.split(".");
    const key = await crypto.subtle.importKey(
      "raw", encoder.encode(env.JWT_SECRET),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    const valid = await crypto.subtle.verify(
      "HMAC", key,
      Uint8Array.from(atob(sig.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0)),
      encoder.encode(`${h}.${p}`)
    );
    if (!valid) return null;
    const payload = JSON.parse(atob(p.replace(/-/g, "+").replace(/_/g, "/")));
    if (payload.exp < Date.now() / 1000) return null;
    return await env.DB.prepare(
      "SELECT id,name,email,role FROM users WHERE id=?"
    ).bind(payload.id).first();
  } catch {
    return null;
  }
}

async function handleApi(request, env, url) {
  const path = url.pathname.replace(/^\/api/, "");
  const method = request.method;
  let body = {};
  if (method === "POST") {
    try { body = await request.json(); }
    catch { return json({ error: "Invalid JSON" }, 400); }
  }

  if (path === "/register" && method === "POST") {
    const name = String(body.name || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!name || !email.includes("@") || password.length < 10)
      return json({ error: "Enter a name, valid email and password of 10+ characters." }, 400);
    const exists = await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first();
    if (exists) return json({ error: "Email already registered." }, 409);
    const hash = await passwordHash(password);
    const result = await env.DB.prepare(
      "INSERT INTO users (name,email,password_hash) VALUES (?,?,?)"
    ).bind(name, email, hash).run();
    const user = { id: result.meta.last_row_id, name, email, role: "user" };
    return json({ token: await makeToken(user, env.JWT_SECRET), user });
  }

  if (path === "/login" && method === "POST") {
    const email = String(body.email || "").trim().toLowerCase();
    const user = await env.DB.prepare(
      "SELECT * FROM users WHERE email=?"
    ).bind(email).first();
    if (!user || !(await verifyPassword(String(body.password || ""), user.password_hash)))
      return json({ error: "Incorrect email or password." }, 401);
    const safeUser = { id: user.id, name: user.name, email: user.email, role: user.role };
    return json({ token: await makeToken(safeUser, env.JWT_SECRET), user: safeUser });
  }

  const user = await getUser(request, env);

  if (path === "/me" && method === "GET") {
    if (!user) return json({ error: "Please log in." }, 401);
    return json({ user });
  }

  if (path === "/links" && method === "GET") {
    if (!user) return json({ error: "Please log in." }, 401);
    const result = await env.DB.prepare(
      "SELECT code,destination,title,clicks,created_at FROM links WHERE user_id=? ORDER BY id DESC"
    ).bind(user.id).all();
    return json({ links: result.results || [] });
  }

  if (path === "/links" && method === "POST") {
    if (!user) return json({ error: "Please log in." }, 401);
    let destination;
    try {
      const parsed = new URL(String(body.destination || ""));
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error();
      destination = parsed.href;
    } catch {
      return json({ error: "Enter a valid http or https URL." }, 400);
    }

    let code;
    for (let i = 0; i < 5; i++) {
      code = randomCode();
      const exists = await env.DB.prepare("SELECT id FROM links WHERE code=?").bind(code).first();
      if (!exists) break;
    }
    await env.DB.prepare(
      "INSERT INTO links (user_id,code,destination) VALUES (?,?,?)"
    ).bind(user.id, code, destination).run();

    return json({ code, shortUrl: `${url.origin}/${code}` });
  }

  if (path === "/analytics" && method === "GET") {
    if (!user) return json({ error: "Please log in." }, 401);
    const stats = await env.DB.prepare(
      `SELECT COUNT(*) AS links, COALESCE(SUM(clicks),0) AS clicks
       FROM links WHERE user_id=?`
    ).bind(user.id).first();
    const earned = await env.DB.prepare(
      "SELECT COALESCE(SUM(amount_usd),0) AS earnings FROM earnings WHERE user_id=?"
    ).bind(user.id).first();
    return json({
      links: stats.links,
      clicks: stats.clicks,
      earnings: earned.earnings
    });
  }

  if (path === "/admin/summary" && method === "GET") {
    if (!user || user.role !== "admin")
      return json({ error: "Admin access required." }, 403);
    const stats = await env.DB.prepare(
      `SELECT (SELECT COUNT(*) FROM users) AS users,
       (SELECT COUNT(*) FROM links) AS links,
       (SELECT COALESCE(SUM(clicks),0) FROM links) AS clicks`
    ).first();
    return json(stats);
  }

  return json({ error: "API route not found." }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (error) {
        return json({ error: "Server error. Check database setup." }, 500);
      }
    }

    if (url.pathname.length > 1) {
      const code = url.pathname.slice(1);
      if (!code.includes("/")) {
        const link = await env.DB.prepare(
          "SELECT id,destination FROM links WHERE code=? AND active=1"
        ).bind(code).first();

        if (link) {
          const country = request.cf?.country || "";
          const referrer = request.headers.get("Referer") || "";
          await env.DB.batch([
            env.DB.prepare("UPDATE links SET clicks=clicks+1 WHERE id=?").bind(link.id),
            env.DB.prepare(
              "INSERT INTO clicks (link_id,country,referrer) VALUES (?,?,?)"
            ).bind(link.id, country, referrer.slice(0, 500))
          ]);
          return Response.redirect(link.destination, 302);
        }
      }
    }

    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response("DRAGON RAKIB URL Shortener", { status: 200 });
  }
};
