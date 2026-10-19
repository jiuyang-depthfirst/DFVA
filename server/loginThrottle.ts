import { createHash } from "crypto";
import { pool } from "./db";

// PostgreSQL keeps counters shared across workers/instances; the upsert is atomic
// so parallel login attempts cannot bypass the limit.
export async function initLoginThrottle(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_login_attempts (
      key text PRIMARY KEY,
      attempts integer NOT NULL,
      window_start timestamptz NOT NULL
    )
  `);
  const cleanup = setInterval(() => {
    pool.query("DELETE FROM auth_login_attempts WHERE window_start < now() - interval '1 day'")
      .catch((error) => console.error("Login throttle cleanup failed:", error));
  }, 60 * 60 * 1000);
  cleanup.unref();
}

async function attempt(scope: string, value: string): Promise<number> {
  const key = `${scope}:${createHash("sha256").update(value).digest("hex")}`;
  const { rows } = await pool.query<{ attempts: number }>(`
    INSERT INTO auth_login_attempts (key, attempts, window_start)
    VALUES ($1, 1, now())
    ON CONFLICT (key) DO UPDATE SET
      attempts = CASE WHEN auth_login_attempts.window_start <= now() - interval '15 minutes'
        THEN 1 ELSE auth_login_attempts.attempts + 1 END,
      window_start = CASE WHEN auth_login_attempts.window_start <= now() - interval '15 minutes'
        THEN now() ELSE auth_login_attempts.window_start END
    RETURNING attempts
  `, [key]);
  return rows[0].attempts;
}

export async function allowLoginAttempt(ip: string, username: string): Promise<boolean> {
  // Check the IP first so a flood from one address cannot create unlimited
  // username counters. The per-username limit still blocks distributed spraying.
  if (await attempt("ip", ip) > 30) return false;
  return await attempt("user", username) <= 8;
}
