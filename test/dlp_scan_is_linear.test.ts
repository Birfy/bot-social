/**
 * DLP: the scan cost grows linearly with the text, on every door that runs it.
 *
 * Two rules in `src/policy.ts` `dlpScan` backtrack over the remainder of a run from every start position:
 *
 * - email `/[\w.+-]+@[\w-]+\.[\w.-]+/` — a long `\w` run with no `@` re-walks it again from each start.
 * - amount `/(¥|￥|\$|USD|RMB|元)\s*\d|\d+\s*(元|块钱|美元)/` — `\d+\s*(…)` re-walks a digit run whenever
 *   the unit sits just out of reach; a trailing `x元` is enough.
 *
 * On the base of this change, with that base's own rules, `dlpScan` took 1.85 s / 6.02 s / 23.7 s on the
 * email shape at 32 / 64 / 128 KiB and 11.4 s / 32.7 s / 130.3 s on the digit-run shape, and the three
 * 256 KiB timing tests below took 95.6 s / 96.5 s / 423.1 s.
 *
 * Both run for a drafted line (`text` plus `JSON.stringify(structured)`), for a message draft, and for an
 * action's `justification` and `params.title` — that last one scans twice. A message draft is now bounded
 * by `text` (4,000 characters) and `structured` (32 KiB serialized); an action's `justification` and
 * `params.title` have no length gate, so the only cap in front of that scan is the 256 KiB request body
 * and one bot key is enough to hold the event loop for minutes per request.
 *
 * The fixes keep both detected sets, because each rule only ever needed one character:
 *
 * - an email local part can begin anywhere, so only the character just before `@` decides the verdict;
 * - only the last digit of a run can be followed by whitespace and a unit.
 *
 * Each match now begins at that character instead of at the head of the run, so the reported interval
 * moves — a long local part starts at its last character, a trailing run after the dot ends at its first,
 * and a long digit run starts at its last digit. That is intentional: `dlpScan` only asks whether the
 * pattern matches, never where. A length cap such as `{1,64}` would shrink the set instead, so long
 * addresses and long digit runs that do carry a unit are pinned below.
 *
 * Out of scope: byte caps for `structured`, `justification` or `params.title`.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { dlpScan } from "../src/policy.js";

/** Wide enough for a slow machine, far below a single quadratic pass over 256 KiB. */
const CEILING_MS = 2000;

/** The pre-change patterns, kept here as the reference answer for the equivalence checks. */
const LEGACY_EMAIL = /[\w.+-]+@[\w-]+\.[\w.-]+/;
const LEGACY_AMOUNT = /(¥|￥|\$|USD|RMB|元)\s*\d|\d+\s*(元|块钱|美元)/;

const emailHit = (text: string) => dlpScan(text).some((h) => h.category === "pii.email");
const moneyHit = (text: string) => dlpScan(text).some((h) => h.category === "money");

/**
 * The normalization `dlpScan` applies before any rule runs, so the reference patterns read the same text the
 * live ones do (full-width forms folded, format characters dropped, digit groups joined).
 */
const normalized = (text: string) =>
  text.normalize("NFKC").replace(/\p{Cf}/gu, "").replace(/(?<=\d)[\s.\-/]+(?=\d)/g, "");

function timed<T>(f: () => T): { value: T; ms: number } {
  const t0 = process.hrtime.bigint();
  const value = f();
  return { value, ms: Number(process.hrtime.bigint() - t0) / 1e6 };
}

test("a 256 KiB token with no '@' is scanned in milliseconds", () => {
  const probe = "user" + "a".repeat(256 * 1024 - 4);
  const { value: hits, ms } = timed(() => dlpScan(probe));
  assert.ok(ms < CEILING_MS, `dlpScan took ${ms.toFixed(0)} ms on a 256 KiB token; the ceiling is ${CEILING_MS} ms`);
  assert.ok(!hits.some((h) => h.category === "pii.email"), "a token with no '@' is not an address");
});

test("a 256 KiB token with an '@' and no dotted domain is scanned under the same ceiling", () => {
  const probe = "a@" + "b".repeat(256 * 1024 - 3) + "!";
  const { value: hits, ms } = timed(() => dlpScan(probe));
  assert.ok(ms < CEILING_MS, `dlpScan took ${ms.toFixed(0)} ms on a 256 KiB token; the ceiling is ${CEILING_MS} ms`);
  assert.ok(!hits.some((h) => h.category === "pii.email"), "an '@' without a dotted domain is not an address");
});

test("a 256 KiB digit run whose unit is out of reach is scanned in milliseconds", () => {
  const probe = "1".repeat(256 * 1024 - 2) + "x元";
  const { value: hits, ms } = timed(() => dlpScan(probe));
  assert.ok(ms < CEILING_MS, `dlpScan took ${ms.toFixed(0)} ms on a 256 KiB digit run; the ceiling is ${CEILING_MS} ms`);
  assert.ok(!hits.some((h) => h.category === "money"), "a unit behind a letter does not make an amount");
});

test("a 1 MiB token is scanned in linear time", () => {
  const probe = "user" + "a".repeat(1024 * 1024 - 4);
  const small = timed(() => dlpScan("user" + "a".repeat(256 * 1024 - 4)));
  const { value: hits, ms } = timed(() => dlpScan(probe));
  assert.ok(ms < CEILING_MS, `dlpScan took ${ms.toFixed(0)} ms on a 1 MiB token (256 KiB: ${small.ms.toFixed(1)} ms); the ceiling is ${CEILING_MS} ms`);
  assert.ok(!hits.some((h) => h.category === "pii.email"), "a token with no '@' is not an address");
});

test("every address shape the old pattern found is still found", () => {
  const shapes = [
    "a@b.co",
    "x@y.z",
    "first.last+tag@sub.example.com",
    "A_B@x-y.z",
    "a.b@c.d",
    "write to first.last@example.com today",
    "a@b.co.",
    "FIRST@EXAMPLE.COM",
    "a@b..c",
    ".@b.co",
    "a@b.c-",
    "two: a@b.co and c@d.ef",
    "tab\tx@y.z",
  ];
  for (const s of shapes) {
    assert.ok(LEGACY_EMAIL.test(s), `${JSON.stringify(s)} must be an address for the reference pattern`);
    assert.ok(emailHit(s), `${JSON.stringify(s)} must still be flagged`);
  }
});

test("an address with a 100-character local part or domain label is still found", () => {
  const long = [
    "a".repeat(100) + "@b.co",
    "x@" + "d".repeat(100) + ".co",
    "x@d." + "t".repeat(100),
  ];
  for (const s of long) {
    assert.ok(LEGACY_EMAIL.test(s), "the reference pattern finds it");
    assert.ok(emailHit(s), `a ${s.length}-character address must still be flagged`);
  }
});

test("text that was never an address stays unflagged", () => {
  // Compare on the text the scan reads: the digit-gap normalization folds `x@1.2` to `x@12` before any rule
  // sees it, so the raw string is not the right reference for that verdict.
  for (const s of ["a@b", "@b.co", "a@.b", "a@@b.c", "a b", "at home", "", "x@1.2", "1@2.3"]) {
    assert.equal(emailHit(s), LEGACY_EMAIL.test(normalized(s)), `${JSON.stringify(s)} changed its verdict`);
    assert.equal(emailHit(s), false, `${JSON.stringify(s)} is not an address`);
  }
});

test("every amount shape the old pattern found is still found", () => {
  const shapes = ["¥ 100", "￥100", "$5", "USD 20", "RMB 30", "元100", "100 元", "20块钱", "5美元", "3\n元", "价格 12 元"];
  for (const s of shapes) {
    assert.ok(LEGACY_AMOUNT.test(s), `${JSON.stringify(s)} must be an amount for the reference pattern`);
    assert.ok(moneyHit(s), `${JSON.stringify(s)} must still be flagged`);
  }
});

test("a long digit run that ends in a unit is still an amount", () => {
  for (const s of ["1".repeat(100000) + "元", "1".repeat(100000) + " 块钱"]) {
    assert.ok(LEGACY_AMOUNT.test(s), "the reference pattern finds it");
    assert.ok(moneyHit(s), `a ${s.length}-character amount must still be flagged`);
  }
});

test("text that was never an amount stays unflagged", () => {
  for (const s of ["1 x元", "100", "元", "块钱", "12块", "abc元", "$", "usd 5", ""]) {
    assert.equal(moneyHit(s), LEGACY_AMOUNT.test(s), `${JSON.stringify(s)} changed its verdict`);
    assert.equal(moneyHit(s), false, `${JSON.stringify(s)} is not an amount`);
  }
});

test("the scan agrees with the old patterns on a seeded fuzz corpus", () => {
  let seed = 0x2f6e2b1;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const emailAlphabet = "abZ09_.+-@ @.:-/!\u00e9\n".split("");
  const amountAlphabet = "0123456789 ab元块钱美元¥$.,\n-".split("");
  const draw = (alphabet: string[], max: number) => {
    let s = "";
    const len = Math.floor(rnd() * (max + 1));
    for (let j = 0; j < len; j++) s += alphabet[Math.floor(rnd() * alphabet.length)];
    return s;
  };
  for (let i = 0; i < 4000; i++) {
    const s = draw(emailAlphabet, 24);
    assert.equal(emailHit(s), LEGACY_EMAIL.test(normalized(s)), `${JSON.stringify(s)} changed its email verdict`);
  }
  for (let i = 0; i < 4000; i++) {
    const s = draw(amountAlphabet, 24);
    assert.equal(moneyHit(s), LEGACY_AMOUNT.test(normalized(s)), `${JSON.stringify(s)} changed its amount verdict`);
  }
});
