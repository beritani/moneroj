import { describe, test } from "@std/testing/bdd";
import { expect } from "@std/expect";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  decodeAddress,
  encodeAddress,
  getPrivateViewKey,
  mnemonicToSeed,
  PrivateKey,
  PublicKey,
  seedToMnemonic,
  validateAddress,
} from "../src/wallet.ts";

describe("mnemonic and seed", () => {
  test("mnemonic to seed", () => {
    const mnemonic =
      "inbound gather dads maze rising enough irritate gels dizzy novelty deity flippant ladder jigsaw anchor bawled nodes recipe inline diet perfect identity bakery bobsled diet";
    const expected =
      "490767dabdd62f88c09d63e0e2b5c61cea0dbf9a9bb56120e62b6c74342dba06";
    const actual = mnemonicToSeed(mnemonic);
    expect(bytesToHex(actual)).toEqual(expected);
  });

  test("seed to mnemonic", () => {
    const seed =
      "78fdb9c9710ef2144c483c2bce405707f712fe0ec56ccbc92f1c18c6a86f0c05";
    const expected =
      "paddles rogue macro urgent system upload ocean waxing buckets himself weird yields ruthless tuition video godfather toyed piloted skater sword obtains rage roster saved skater";
    const actual = seedToMnemonic(hexToBytes(seed));
    expect(actual.join(" ")).toEqual(expected);
  });
});

describe("public keys", () => {
  const seed =
    "78fdb9c9710ef2144c483c2bce405707f712fe0ec56ccbc92f1c18c6a86f0c05";

  test("public spend key", () => {
    const ks = PrivateKey.fromHex(seed); // Private Spend Key
    const Ks = PublicKey.fromPrivateKey(ks); // Public Spend Key
    const expected =
      "6523f094e6ddd1db9fa77702188ff7b34c87eeb0c79c94d25b642b7813ee686c";
    const actual = bytesToHex(Ks);
    expect(actual).toEqual(expected);
  });

  test("private view key", () => {
    const ks = PrivateKey.fromHex(seed); // Private Spend Key
    const kv = getPrivateViewKey(ks); // Private View Key
    const expected =
      "ec215a86562d63d349e9ef21e0ed2d56252122b823433dae8d36b2ad8083c904";
    const actual = bytesToHex(kv);
    expect(actual).toEqual(expected);
  });

  test("public view key", () => {
    const ks = PrivateKey.fromHex(seed); // Private Spend Key
    const kv = getPrivateViewKey(ks); // Private View Key
    const Kv = PublicKey.fromPrivateKey(kv); // Public View Key
    const expected =
      "642310ab76a2f94f50ebfb134a01b2e8310a2acf674bb526ee636905fc1b673f";
    const actual = bytesToHex(Kv);
    expect(actual).toEqual(expected);
  });
});

describe("address", () => {
  test("encode address", () => {
    const seed =
      "78fdb9c9710ef2144c483c2bce405707f712fe0ec56ccbc92f1c18c6a86f0c05";
    const addr = encodeAddress(PrivateKey.fromHex(seed));
    const expected =
      "45TQgTZMeP2djdDqwNg2CnWzRchgQ8K8FcBj8XrSPBBVK8Xk1yaJYQpEGU144rGuQdfqYqqaMVtZA7WgXQ1jigmk8BGWKAx";
    expect(addr).toEqual(expected);
  });

  test("decode address", () => {
    const addr =
      "45TQgTZMeP2djdDqwNg2CnWzRchgQ8K8FcBj8XrSPBBVK8Xk1yaJYQpEGU144rGuQdfqYqqaMVtZA7WgXQ1jigmk8BGWKAx";
    const expected = {
      pubSpend:
        "6523f094e6ddd1db9fa77702188ff7b34c87eeb0c79c94d25b642b7813ee686c",
      pubView:
        "642310ab76a2f94f50ebfb134a01b2e8310a2acf674bb526ee636905fc1b673f",
      checksum: "9d2c8d41",
    };

    const decoded = decodeAddress(addr);
    expect(bytesToHex(decoded.pubSpend)).toEqual(expected.pubSpend);
    expect(bytesToHex(decoded.pubView)).toEqual(expected.pubView);
    expect(bytesToHex(decoded.checksum)).toEqual(expected.checksum);
  });

  test("validate address", () => {
    const valid =
      "45TQgTZMeP2djdDqwNg2CnWzRchgQ8K8FcBj8XrSPBBVK8Xk1yaJYQpEGU144rGuQdfqYqqaMVtZA7WgXQ1jigmk8BGWKAx";
    const invalid =
      "45TQgTZMeP2djdDqwNg2CnWzRchgQ8K8FcBj8XrSPBBVK8Xk1yaJZQpEGU144rGuQdfqYqqaMVtZA7WgXQ1jigmk8BGWKAx";

    expect(validateAddress(valid)).toBeTruthy();
    expect(validateAddress(invalid)).toBeFalsy();
  });
});
