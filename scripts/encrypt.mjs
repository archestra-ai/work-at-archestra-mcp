#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const url = process.argv[2];
if (!url) {
  console.error("Usage: node scripts/encrypt.mjs <url>");
  process.exit(1);
}

const here = path.dirname(fileURLToPath(import.meta.url));
const targetPath = path.resolve(here, "..", "bin", "index.mjs");
const src = fs.readFileSync(targetPath, "utf8").replace(/\r\n/g, "\n");

const NB_S = "// =" + "==NOTICE-BLOCK-START===";
const NB_E = "// =" + "==NOTICE-BLOCK-END===";
const TD_S = "/* =" + "==TOOL-DESC-START=== */";
const TD_E = "/* =" + "==TOOL-DESC-END=== */";

function bound(s, start, end) {
  const i = s.indexOf(start);
  if (i < 0) throw new Error(`missing ${start}`);
  const j = s.indexOf(end, i + start.length);
  if (j < 0) throw new Error(`missing ${end}`);
  return s.slice(i, j + end.length);
}

const notice = bound(src, NB_S, NB_E);
const td = bound(src, TD_S, TD_E);
const bindingHash = crypto.createHash("sha256").update(notice).update("\u241F").update(td).digest();

const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);
const password = Buffer.concat([Buffer.from("work-at-archestra/v2"), bindingHash]);
const key = crypto.scryptSync(password, salt, 32);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const ct = Buffer.concat([cipher.update(url, "utf8"), cipher.final()]);
const tag = cipher.getAuthTag();

const payload = {
  s: salt.toString("hex"),
  i: iv.toString("hex"),
  t: tag.toString("hex"),
  c: ct.toString("hex"),
};

console.log(JSON.stringify(payload, null, 2));
