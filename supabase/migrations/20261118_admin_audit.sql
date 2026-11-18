-- Protokoll aller Admin-Aktionen (DSGVO Art. 5 Abs. 2 / Art. 32: Rechenschaft)
-- Nur die Edge Function (service_role) darf schreiben/lesen. Keine Policies = kein Zugriff für Clients.
create table if not exists public.admin_audit (
  id uuid primary key default gen_random_uuid(),
  admin_id uuid not null,
  action text not null check (action in ('list','send_reset','set_password','delete_user','export_user')),
  target_id uuid,
  target_email text,
  created_at timestamptz not null default now()
);
alter table public.admin_audit enable row level security;
revoke all on public.admin_audit from anon, authenticated;
