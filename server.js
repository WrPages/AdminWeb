const express = require("express")
const crypto = require("crypto")
const path = require("path")
const { Redis } = require("@upstash/redis")

const app = express()
app.use(express.json())

const {
  ADMIN_PASSWORD, SESSION_SECRET,
  UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN,
  RAILWAY_TOKEN, RAILWAY_PROJECT_ID, RAILWAY_ENVIRONMENT_ID,
  RAILWAY_SERVICES = "[]",            // [{"name":"Elite","serviceId":"..."}, ...] (los 5)
  UPSTASH_EMAIL, UPSTASH_API_KEY, UPSTASH_DB_ID,
  UPSTASH_LIMIT_COMMANDS = "500000",  // límite mensual del plan free
  PORT = 3000
} = process.env

const redis = new Redis({ url: UPSTASH_REDIS_REST_URL, token: UPSTASH_REDIS_REST_TOKEN })
const GROUPS = ["Elite_Four", "Gym_Leader", "Trainer"]
const isId = id => /^\d{16}$/.test(String(id || "").trim())
const parse = (v, fb) => { try { return !v ? fb : typeof v === "object" ? v : JSON.parse(v) } catch { return fb } }

// ---------- sesión (cookie firmada, sin dependencias) ----------
const sign = s => crypto.createHmac("sha256", SESSION_SECRET).update(s).digest("base64url")
function makeToken() {
  const p = Buffer.from(JSON.stringify({ exp: Date.now() + 12 * 3600e3 })).toString("base64url")
  return `${p}.${sign(p)}`
}
function validToken(t) {
  if (!t) return false
  const [p, sig] = t.split(".")
  if (!p || !sig || sign(p) !== sig) return false
  return parse(Buffer.from(p, "base64url").toString(), {}).exp > Date.now()
}
const getCookie = req => (req.headers.cookie || "").split(";").map(c => c.trim())
  .find(c => c.startsWith("sid="))?.slice(4)
const auth = (req, res, next) => validToken(getCookie(req)) ? next() : res.status(401).json({ error: "No autorizado" })

const fails = {}
app.post("/api/login", (req, res) => {
  const ip = req.headers["x-forwarded-for"] || req.ip
  const f = fails[ip] || { n: 0, until: 0 }
  if (f.until > Date.now()) return res.status(429).json({ error: "Demasiados intentos, espera unos minutos" })
  const a = Buffer.from(String(req.body.password || ""))
  const b = Buffer.from(String(ADMIN_PASSWORD || ""))
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b)
  if (!ok) {
    f.n++; if (f.n >= 5) { f.until = Date.now() + 10 * 60e3; f.n = 0 }
    fails[ip] = f
    return res.status(401).json({ error: "Contraseña incorrecta" })
  }
  fails[ip] = { n: 0, until: 0 }
  res.setHeader("Set-Cookie", `sid=${makeToken()}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`)
  res.json({ ok: true })
})
app.post("/api/logout", (req, res) => {
  res.setHeader("Set-Cookie", "sid=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")
  res.json({ ok: true })
})
app.get("/api/me", auth, (req, res) => res.json({ ok: true }))

// ---------- resumen: online total + PPM de Elite ----------
app.get("/api/summary", auth, async (req, res) => {
  try {
    const counts = await Promise.all(GROUPS.map(g => redis.scard(`online:${g}`)))
    const history = parse(await redis.get("ppm_history"), [])
    // ⚠️ AJUSTAR: no vi cómo guardas ppm_history. Se toma el último registro
    // y se busca un campo numérico común. Cámbialo según tu estructura real.
    const last = Array.isArray(history) ? history[history.length - 1] : null
    const ppm = last == null ? null : typeof last === "number" ? last
      : last.elite ?? last.Elite_Four ?? last.ppm ?? last.value ?? last.total ?? null
    res.json({ online: counts.reduce((a, b) => a + b, 0), byGroup: Object.fromEntries(GROUPS.map((g, i) => [g, counts[i]])), ppm })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// ---------- Railway ----------
async function gql(query, variables) {
  const r = await fetch("https://backboard.railway.com/graphql/v2", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${RAILWAY_TOKEN}` },
    body: JSON.stringify({ query, variables })
  })
  const j = await r.json()
  if (j.errors) throw new Error(j.errors.map(e => e.message).join("; "))
  return j.data
}
const services = () => parse(RAILWAY_SERVICES, [])

app.get("/api/railway/services", auth, async (req, res) => {
  try {
    const out = []
    for (const s of services()) {
      let status = "DESCONOCIDO"
      try {
        const d = await gql(`query($p:String!,$e:String!,$s:String!){deployments(first:1,input:{projectId:$p,environmentId:$e,serviceId:$s}){edges{node{id status}}}}`,
          { p: RAILWAY_PROJECT_ID, e: RAILWAY_ENVIRONMENT_ID, s: s.serviceId })
        status = d.deployments.edges[0]?.node.status || "SIN DEPLOY"
      } catch {}
      out.push({ name: s.name, serviceId: s.serviceId, status })
    }
    res.json(out)
  } catch (e) { res.status(500).json({ error: e.message }) }
})

app.post("/api/railway/:serviceId/:action", auth, async (req, res) => {
  const { serviceId, action } = req.params
  if (!services().some(s => s.serviceId === serviceId)) return res.status(400).json({ error: "Servicio no permitido" })
  try {
    if (action === "redeploy") {
      await gql(`mutation($s:String!,$e:String!){serviceInstanceRedeploy(serviceId:$s,environmentId:$e)}`,
        { s: serviceId, e: RAILWAY_ENVIRONMENT_ID })
    } else if (action === "restart") {
      const d = await gql(`query($p:String!,$e:String!,$s:String!){deployments(first:1,input:{projectId:$p,environmentId:$e,serviceId:$s}){edges{node{id}}}}`,
        { p: RAILWAY_PROJECT_ID, e: RAILWAY_ENVIRONMENT_ID, s: serviceId })
      const id = d.deployments.edges[0]?.node.id
      if (!id) throw new Error("No hay deployment activo")
      await gql(`mutation($id:String!){deploymentRestart(id:$id)}`, { id })
    } else return res.status(400).json({ error: "Acción inválida" })
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// ⚠️ VERIFICAR en el playground de Railway: el campo exacto del crédito restante puede variar.
app.get("/api/railway/usage", auth, async (req, res) => {
  try {
    const d = await gql(`query{me{customer{creditBalance remainingUsageCreditBalance}}}`)
    res.json(d.me.customer)
  } catch (e) { res.json({ error: e.message }) }
})

// ---------- Upstash ----------
app.get("/api/upstash/usage", auth, async (req, res) => {
  try {
    const r = await fetch(`https://api.upstash.com/v2/redis/stats/${UPSTASH_DB_ID}`, {
      headers: { Authorization: "Basic " + Buffer.from(`${UPSTASH_EMAIL}:${UPSTASH_API_KEY}`).toString("base64") }
    })
    const j = await r.json()
    const used = j.total_monthly_requests ?? null
    const limit = Number(UPSTASH_LIMIT_COMMANDS)
    res.json({ used, limit, left: used == null ? null : Math.max(limit - used, 0), raw: j })
  } catch (e) { res.json({ error: e.message }) }
})

// ---------- Panel del server (Redis) ----------
const okGroup = (req, res, next) => GROUPS.includes(req.params.group) ? next() : res.status(400).json({ error: "Grupo inválido" })

app.get("/api/group/:group/online", auth, okGroup, async (req, res) => {
  try {
    const g = req.params.group
    const ids = (await redis.smembers(`online:${g}`)).map(String)
    const raw = (await redis.hgetall(`users:${g}`)) || {}
    const users = Object.values(raw).map(v => parse(v, {}))
    const duos = Object.values((await redis.hgetall("rival_duos")) || {}).map(v => parse(v, null)).filter(Boolean)
    const duoIds = new Map(duos.filter(d => d.status === "online" && d.activeGroup === g && d.activeGameId)
      .map(d => [String(d.activeGameId), Object.values(d.members || {}).map(m => m.name).join(" & ")]))
    res.json(ids.map(id => {
      if (duoIds.has(id)) return { id, label: `Rival Duo: ${duoIds.get(id)}` }
      const u = users.find(u => u.main_id === id || u.sec_id === id)
      return { id, label: u ? `${u.name} (${u.main_id === id ? "Main" : "Sec"})` : "Desconocido" }
    }))
  } catch (e) { res.status(500).json({ error: e.message }) }
})

app.post("/api/group/:group/:action(online|offline|vip)", auth, okGroup, async (req, res) => {
  const { group, action } = req.params
  const id = String(req.body.id || "").trim()
  if (!isId(id)) return res.status(400).json({ error: "El ID debe tener 16 dígitos" })
  try {
    if (action === "online") await redis.sadd(`online:${group}`, id)
    if (action === "offline") await redis.srem(`online:${group}`, id)
    if (action === "vip") await redis.sadd(`vip:${group}`, id)
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

app.use(express.static(path.join(__dirname, "public")))
app.listen(PORT, () => console.log("Panel Zenith en puerto", PORT))
