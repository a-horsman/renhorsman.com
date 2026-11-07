const COOKIE = "ren_auth";

async function tokenFor(pw) {
  const data = new TextEncoder().encode("ren-site:" + pw);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function safePath(p) {
  return typeof p === "string" && p.startsWith("/") && !p.startsWith("//") ? p : "/";
}

function loginPage(next, error) {
  const html = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Private</title>
<style>
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f6f4f0;font-family:system-ui,sans-serif;color:#222}
  form{background:#fff;padding:32px 28px;border-radius:14px;box-shadow:0 4px 20px rgba(0,0,0,.08);width:min(320px,90vw);text-align:center}
  h1{font-size:20px;margin:0 0 18px}
  input{width:100%;box-sizing:border-box;padding:12px;font-size:16px;border:1px solid #ccc;border-radius:8px}
  button{margin-top:12px;width:100%;padding:12px;font-size:16px;border:0;border-radius:8px;background:#222;color:#fff;cursor:pointer}
  .err{color:#b00020;font-size:14px;margin:10px 0 0}
</style></head>
<body><form method="POST" action="/__login">
  <h1>Enter password</h1>
  <input type="password" name="password" autofocus autocomplete="current-password" required>
  <input type="hidden" name="next" value="${next.replace(/"/g, "&quot;")}">
  <button type="submit">View</button>
  ${error ? '<p class="err">Wrong password, try again.</p>' : ""}
</form></body></html>`;
  return new Response(html, {
    status: 401,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pw = env.SITE_PASSWORD;
    if (!pw) return loginPage("/", false);
    const expected = await tokenFor(pw);

    if (request.method === "POST" && url.pathname === "/__login") {
      const form = await request.formData();
      const next = safePath(form.get("next"));
      if (form.get("password") === pw) {
        return new Response(null, {
          status: 303,
          headers: {
            Location: next,
            "Set-Cookie": `${COOKIE}=${expected}; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax`,
          },
        });
      }
      return loginPage(next, true);
    }

    const cookies = (request.headers.get("Cookie") || "").split(/;\s*/);
    if (cookies.includes(`${COOKIE}=${expected}`)) {
      const res = await env.ASSETS.fetch(request);
      const out = new Response(res.body, res);
      out.headers.set("X-Robots-Tag", "noindex, nofollow");
      return out;
    }

    return loginPage(url.pathname + url.search, false);
  },
};
