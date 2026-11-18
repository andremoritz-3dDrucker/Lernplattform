# Lernplattform
Eine Lernplattform für die IHK Prüfung Teil 2

## Seiten
- `index.html` – Lernapp
- `admin.html` – Nutzerverwaltung (nur Admins)
- `passwort.html` – neues Passwort nach Reset-Mail

Backend: `supabase/functions/admin-users` (Deploy per GitHub Actions, Secret `SUPABASE_ACCESS_TOKEN`).
Passwörter sind nie lesbar (Hash, DSGVO Art. 32) – nur Reset-Mail oder neues Passwort setzen.
