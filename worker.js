export default {
  async fetch(request, env) {
    const auth = request.headers.get("Authorization") || "";
    const [scheme, encoded] = auth.split(" ");

    if (scheme === "Basic" && encoded) {
      const decoded = atob(encoded);
      const password = decoded.slice(decoded.indexOf(":") + 1);
      if (env.SITE_PASSWORD && password === env.SITE_PASSWORD) {
        const res = await env.ASSETS.fetch(request);
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
  },
};
