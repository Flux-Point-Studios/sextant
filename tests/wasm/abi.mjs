// The wasm32 ABI smoke: drive the built `sextant.wasm` (argv[2]) through its exports on
// committed vectors and check what crosses the 32-bit boundary - status codes, the
// SextantCreatedOutput layout (usize fields are 4 bytes here), the caller-sizing
// protocol, and sentinel bytes surviving every refusal. Run by scripts/harness.sh after
// the wasm32 build; exits nonzero on the first failed check.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const vectors = join(dirname(fileURLToPath(import.meta.url)), "..", "vectors");
const hexFile = (name) => Buffer.from(readFileSync(join(vectors, name), "utf8").trim(), "hex");
const hex = (text) => Buffer.from(text, "hex");

const { instance } = await WebAssembly.instantiate(readFileSync(process.argv[2]), {});
const sx = instance.exports;

const Ok = 0;
const ErrNullPointer = -1;
const ErrEmptyInput = -2;
const ErrBufferTooSmall = -3;
const DecodeUnsupportedEra = 101;
const UtxoInclusionNotIncluded = 400;
const UtxoValidityNotEstablished = 412;
const CreatedDecode = 420;
const CreatedHeaderHashMismatch = 421;
const CreatedNotCreated = 427;
const CREATED_SIZE = 72;
const VERIFIED_SIZE = 32;
const STRUCT_SENTINEL = 0x5a;
const BUFFER_SENTINEL = 0xaa;

// A bump arena in pages grown past the module's own heap, which its allocator never
// hands out: each region is filled with `fill` or the given bytes.
let next = sx.memory.grow(64) * 65536;
const bytes = () => new Uint8Array(sx.memory.buffer);
function region(content, fill = 0) {
    const size = typeof content === "number" ? content : content.length;
    const at = next;
    next += (size + 15) & ~15;
    if (typeof content === "number") bytes().fill(fill, at, at + size);
    else bytes().set(content, at);
    return at;
}
const view = (at, size) => Buffer.from(bytes().slice(at, at + size));
const allAre = (at, size, value) => view(at, size).every((b) => b === value);
const u64 = (at) => new DataView(sx.memory.buffer).getBigUint64(at, true);
const i64 = (at) => new DataView(sx.memory.buffer).getBigInt64(at, true);
const u32 = (at) => new DataView(sx.memory.buffer).getUint32(at, true);

assert.equal(sx.sextant_abi_version(), 6);

const block = region(hexFile("invalid-mainnet-13591743.block"));
const blockLen = hexFile("invalid-mainnet-13591743.block").length;
const blockHash = region(hex("f258395bec389a78f685862811adafe031122566df38fa2895d6c256a0c2c7e1"));
const tx = (id) => region(hex(id));
const TX0 = tx("1ae09b7f678f8053665727c23a6d0ebb232c40f699e56dcc40de261f72c2bde9");
const TX7 = tx("6532eb693c0a1170a07061a38e6dbaac8a3acfa57e43d497a33e0d072d40379a");
const INLINE = tx("b19d40d830f21e680d75617fd33802a651935f25f756e499e3894fdec2cf5986");
const HASHED = tx("a9654c5a5f4f9d07314ea027f96f76b5536c7ec092bd5d907fb7aaa0efa4b552");

// One call into sentinel-filled outputs: the struct region runs 8 bytes past the struct
// so an overrun shows; `caps` null passes NULL/0 for both buffers.
function created(blockAt, blockSize, hashAt, txAt, index, caps = [128, 128]) {
    const out = region(CREATED_SIZE + 8, STRUCT_SENTINEL);
    const [addressCap, datumCap] = caps ?? [0, 0];
    const address = region(Math.max(addressCap, 1), BUFFER_SENTINEL);
    const datum = region(Math.max(datumCap, 1), BUFFER_SENTINEL);
    const detail = region(16, 0x77);
    const rc = sx.sextant_verify_created_output(
        blockAt, blockSize, hashAt, txAt, index, out,
        caps ? address : 0, addressCap, caps ? datum : 0, datumCap, detail,
    );
    return { rc, out, address, addressCap, datum, datumCap, detail };
}
const untouched = (c) =>
    allAre(c.out, CREATED_SIZE + 8, STRUCT_SENTINEL) &&
    allAre(c.address, Math.max(c.addressCap, 1), BUFFER_SENTINEL) &&
    allAre(c.datum, Math.max(c.datumCap, 1), BUFFER_SENTINEL);
const detail = (c) => [i64(c.detail), u64(c.detail + 8)];

function expectCreated(c, { lovelace, address, kind, datum, valid }) {
    assert.equal(c.rc, Ok);
    assert.equal(u64(c.out), lovelace);
    assert.equal(u64(c.out + 8), 13591743n);
    assert.equal(u64(c.out + 16), 190746649n);
    assert.equal(u32(c.out + 24), address.length);
    assert.equal(u32(c.out + 28), datum.length);
    assert.deepEqual(view(c.out + 32, 32), view(blockHash, 32));
    assert.deepEqual([...view(c.out + 64, 8)], [kind, valid, 0, 0, 0, 0, 0, 0]);
    assert.ok(allAre(c.out + CREATED_SIZE, 8, STRUCT_SENTINEL), "no write past the struct");
    assert.deepEqual(view(c.address, address.length), address);
    assert.deepEqual(view(c.datum, datum.length), datum);
    assert.deepEqual(detail(c), [-1n, 0n]);
}

expectCreated(created(block, blockLen, blockHash, TX0, 0), {
    lovelace: 285000000n,
    address: hex("0126fff975e02f6bbc3c6fc541eacee020e74006d3f9b4cba061da6ae51052e7078f15c995e31e4085f4adb1c03f0dc0aba3de57bffb4c12c7"),
    kind: 0, datum: hex(""), valid: 1,
});
expectCreated(created(block, blockLen, blockHash, TX7, 3), {
    lovelace: 520548445n,
    address: hex("018a6550ab2f014123c8cd0d021e23dfbbc5b6279bfa2c5e130910f3c21af7b97baf428cba146425910b7ac5d1ef155cabd71662644b44abdf"),
    kind: 0, datum: hex(""), valid: 0,
});
const inline = created(block, blockLen, blockHash, INLINE, 0);
assert.equal(inline.rc, Ok);
assert.equal(view(inline.out + 64, 1)[0], 2);
assert.deepEqual(view(inline.datum, u32(inline.out + 28)), hex("9f9f00003a057905903a000a8e4b00ff3a080c9afcff"));
const hashed = created(block, blockLen, blockHash, HASHED, 0);
assert.equal(hashed.rc, Ok);
assert.equal(view(hashed.out + 64, 1)[0], 1);
assert.deepEqual(view(hashed.datum, u32(hashed.out + 28)), hex("07e4460f9f681534c4671bc2569966e6b7809af60d5a71320d41032ea8eaafee"));

// The sizing protocol: a NULL/0 probe and an address buffer one byte short answer -3
// with the true lengths in a fully written struct and copy no variable byte.
const probe = created(block, blockLen, blockHash, TX7, 3, null);
assert.equal(probe.rc, ErrBufferTooSmall);
assert.equal(u32(probe.out + 24), 57);
assert.deepEqual([...view(probe.out + 64, 8)], [0, 0, 0, 0, 0, 0, 0, 0]);
const short = created(block, blockLen, blockHash, TX7, 3, [56, 128]);
assert.equal(short.rc, ErrBufferTooSmall);
assert.ok(allAre(short.address, 56, BUFFER_SENTINEL) && allAre(short.datum, 128, BUFFER_SENTINEL));

// Refusals: each code, the detail written, nothing else - with and without buffers.
const otherHash = region(view(blockHash, 32).map((b, i) => (i === 0 ? b ^ 1 : b)));
const garbage = region(hex("82000102"));
for (const caps of [[128, 128], null]) {
    const notCreated = created(block, blockLen, blockHash, TX7, 0, caps);
    assert.equal(notCreated.rc, CreatedNotCreated);
    assert.ok(untouched(notCreated));
    assert.deepEqual(detail(notCreated), [-1n, 0n]);
    const mismatch = created(block, blockLen, otherHash, TX0, 0, caps);
    assert.equal(mismatch.rc, CreatedHeaderHashMismatch);
    assert.ok(untouched(mismatch));
    const decode = created(garbage, 4, blockHash, TX0, 0, caps);
    assert.equal(decode.rc, CreatedDecode);
    assert.ok(untouched(decode));
    assert.deepEqual(detail(decode), [-1n, BigInt(DecodeUnsupportedEra)]);
}

// Caller errors come first and write nothing, the detail included: a null pointer is
// reported ahead of an empty block.
const nullBlock = created(0, 0, blockHash, TX0, 0);
assert.equal(nullBlock.rc, ErrNullPointer);
assert.ok(untouched(nullBlock) && allAre(nullBlock.detail, 16, 0x77));
assert.equal(created(block, blockLen, 0, TX0, 0).rc, ErrNullPointer);
const empty = created(block, 0, blockHash, TX0, 0);
assert.equal(empty.rc, ErrEmptyInput);
assert.ok(untouched(empty) && allAre(empty.detail, 16, 0x77));

// The body-only UTxO read: the certified golden order is included and refused (412),
// the struct and both buffers as they were; a spoofed body is not included (400).
const body = hexFile("mithril-tx-body.cbor");
const proof = Buffer.from(
    JSON.parse(readFileSync(join(vectors, "mithril-txproof.json"), "utf8")).certified_transactions[0].proof,
);
const root = region(hex("83c012fdc3e756fb5230d1a6554fbf743ccea171b37d536a64350c4f5d774129"));
const proofAt = region(proof);
const spoof = Buffer.from(body);
spoof[116] ^= 1;
for (const [bodyBytes, expected] of [[body, UtxoValidityNotEstablished], [spoof, UtxoInclusionNotIncluded]]) {
    for (const caps of [[256, 256], [0, 0]]) {
        const bodyAt = region(bodyBytes);
        const out = region(VERIFIED_SIZE + 8, STRUCT_SENTINEL);
        const address = region(Math.max(caps[0], 1), BUFFER_SENTINEL);
        const datum = region(Math.max(caps[1], 1), BUFFER_SENTINEL);
        const detailAt = region(16, 0x77);
        const rc = sx.sextant_verify_utxo_read(
            bodyAt, bodyBytes.length, 0, proofAt, proof.length, root, 4927469n, out,
            caps[0] ? address : 0, caps[0], caps[1] ? datum : 0, caps[1], detailAt,
        );
        assert.equal(rc, expected);
        assert.ok(allAre(out, VERIFIED_SIZE + 8, STRUCT_SENTINEL));
        assert.ok(allAre(address, Math.max(caps[0], 1), BUFFER_SENTINEL));
        assert.ok(allAre(datum, Math.max(caps[1], 1), BUFFER_SENTINEL));
        assert.deepEqual([i64(detailAt), u64(detailAt + 8)], [-1n, 0n]);
    }
}

// Every new status is named by the message table.
for (const status of [412, 420, 421, 422, 423, 424, 425, 426, 427]) {
    const need = sx.sextant_status_message(status, 0, 0);
    const at = region(need);
    sx.sextant_status_message(status, at, need);
    assert.notEqual(view(at, need).toString("utf8"), "unknown status", String(status));
}

console.log("wasm abi smoke: ok (abi 6, created output 72-byte layout, sizing, refusals, 412)");
