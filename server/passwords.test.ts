import { test } from "node:test";
import assert from "node:assert/strict";
import { hashPassword, isPasswordHash, verifyPassword } from "./passwords";

test("password hashes use independent salts and verify without plaintext comparison", async () => {
  const first = await hashPassword("secret123");
  const second = await hashPassword("secret123");
  assert.ok(isPasswordHash(first));
  assert.notEqual(first, second);
  assert.notEqual(first, "secret123");
  assert.equal(await verifyPassword("secret123", first), true);
  assert.equal(await verifyPassword("wrong", first), false);
  assert.equal(await verifyPassword("secret123", second), true);
  assert.equal(await verifyPassword("secret123", "secret123"), false);
  assert.equal(await verifyPassword("secret123", "scrypt$invalid$hash"), false);
});
