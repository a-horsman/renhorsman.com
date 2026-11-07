export async function onRequest({ request, env, next }) {
  const auth = request.headers.get("Authorization") || "";
  const [scheme, encoded] = auth.split(" ");

  if (scheme === "Basic" && encoded) {
    const decoded = atob(encoded);
    const password = decoded.slice(decoded.indexOf(":") + 1);
    if (password === env.SITE_PASSWORD) {
      const res = await next();
      const out = new Response(res.body, res);
      out.headers.set("X-Robots-Tag", "noindex, nofollow");
      return out;
    }
  }

  return new Response("Password required", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Ren", charset="UTF-8"',
      "Cache-Control": "no-store",
    },
  });
}
