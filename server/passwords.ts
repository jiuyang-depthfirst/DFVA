import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "crypto";
import { promisify } from "util";

const scrypt = promisify(scryptCallback);
const HASH_FORMAT = /^scrypt\$[0-9a-f]{32}\$[0-9a-f]{128}$/;

export function isPasswordHash(value: string): boolean {
  return HASH_FORMAT.test(value);
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = (await scrypt(password, salt, 64)) as Buffer;
  return `scrypt$${salt.toString("hex")}$${key.toString("hex")}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  if (!isPasswordHash(stored)) return false;
  const [, salt, expected] = stored.split("$");
  const key = (await scrypt(password, Buffer.from(salt, "hex"), 64)) as Buffer;
  return timingSafeEqual(key, Buffer.from(expected, "hex"));
}
