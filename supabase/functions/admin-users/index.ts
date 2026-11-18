// Edge Function "admin-users" – Nutzerverwaltung nur für Admins (Tabelle app_admins).
// Passwörter sind NIE lesbar (Supabase speichert nur bcrypt-Hashes). Möglich: Reset-Mail, neues Passwort setzen.
import { createClient } from "npm:@supabase/supabase-js@2";

const URL_ = Deno.env.get("SUPABASE_URL")!;
const ANON = Deno.env.get("SUPABASE_ANON_KEY")!;
const SERVICE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

const pwOk = (p: string) =>
  typeof p === "string" && p.length >= 8 && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Methode nicht erlaubt" }, 405);

  // 1) Aufrufer prüfen
  const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) return json({ error: "Nicht angemeldet" }, 401);
  const userClient = createClient(URL_, ANON, { global: { headers: { Authorization: `Bearer ${token}` } } });
  const { data: u, error: uErr } = await userClient.auth.getUser(token);
  if (uErr || !u?.user) return json({ error: "Ungültige Sitzung" }, 401);
  const me = u.user;

  const admin = createClient(URL_, SERVICE, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: isAdmin } = await admin.from("app_admins").select("user_id").eq("user_id", me.id).maybeSingle();
  if (!isAdmin) return json({ error: "Kein Admin" }, 403);

  let body: any;
  try { body = await req.json(); } catch { return json({ error: "Ungültiges JSON" }, 400); }
  const action = String(body.action || "");

  const audit = (a: string, id?: string, email?: string) =>
    admin.from("admin_audit").insert({ admin_id: me.id, action: a, target_id: id ?? null, target_email: email ?? null });

  const getTarget = async () => {
    const id = String(body.user_id || "");
    if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
    const { data } = await admin.auth.admin.getUserById(id);
    return data?.user ?? null;
  };

  try {
    // 2) Aktionen
    if (action === "list") {
      const out: any[] = [];
      for (let page = 1; page <= 20; page++) {
        const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 200 });
        if (error) throw error;
        for (const x of data.users) {
          out.push({ id: x.id, email: x.email, created_at: x.created_at, last_sign_in_at: x.last_sign_in_at,
            confirmed: !!x.email_confirmed_at });
        }
        if (data.users.length < 200) break;
      }
      const { data: admins } = await admin.from("app_admins").select("user_id");
      const set = new Set((admins || []).map((a: any) => a.user_id));
      await audit("list");
      return json({ users: out.map((x) => ({ ...x, is_admin: set.has(x.id) })), me: me.id });
    }

    const t = await getTarget();
    if (!t) return json({ error: "Nutzer nicht gefunden" }, 404);

    if (action === "send_reset") {
      const redirectTo = typeof body.redirect_to === "string" ? body.redirect_to : undefined;
      const { error } = await userClient.auth.resetPasswordForEmail(t.email!, { redirectTo });
      if (error) throw error;
      await audit("send_reset", t.id, t.email!);
      return json({ ok: true });
    }

    if (action === "set_password") {
      if (!pwOk(body.password)) return json({ error: "Passwort: mind. 8 Zeichen, Groß-/Kleinbuchstaben, Zahl, Sonderzeichen" }, 400);
      const { error } = await admin.auth.admin.updateUserById(t.id, { password: body.password });
      if (error) throw error;
      await audit("set_password", t.id, t.email!);
      return json({ ok: true });
    }

    if (action === "delete_user") {
      if (t.id === me.id) return json({ error: "Du kannst dich nicht selbst löschen" }, 400);
      const { error } = await admin.auth.admin.deleteUser(t.id); // Daten löschen per ON DELETE CASCADE
      if (error) throw error;
      // Tabellen ohne FK-Kaskade sicherheitshalber leeren
      for (const tb of ["learning_attempts", "user_state", "flashcard_progress", "feedback"]) {
        await admin.from(tb).delete().eq("user_id", t.id);
      }
      await audit("delete_user", t.id, t.email!);
      return json({ ok: true });
    }

    if (action === "export_user") { // Auskunft Art. 15 / Übertragbarkeit Art. 20
      const tables = ["learning_attempts", "user_state", "flashcard_progress", "feedback"];
      const data: Record<string, unknown> = {
        konto: { id: t.id, email: t.email, erstellt: t.created_at, letzter_login: t.last_sign_in_at },
      };
      for (const tb of tables) {
        const { data: rows } = await admin.from(tb).select("*").eq("user_id", t.id);
        data[tb] = rows ?? [];
      }
      await audit("export_user", t.id, t.email!);
      return json({ export: data });
    }

    return json({ error: "Unbekannte Aktion" }, 400);
  } catch (e) {
    console.error(e);
    return json({ error: "Serverfehler" }, 500);
  }
});
