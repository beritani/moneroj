import { ed25519 as ed } from "@noble/curves/ed25519";
import {
  bytesToNumberLE,
  hexToBytes,
  numberToBytesLE,
} from "@noble/curves/abstract/utils";
import { type Bytes, crc32, keccak, modN } from "./utils.ts";
import wordlist from "./wordlists/english.ts";
import { bytesToHex, concatBytes } from "@noble/hashes/utils";
import { base58xmr } from "@scure/base";

const G = ed.ExtendedPoint.BASE;

interface PrivateKey {
  fromScalar(scalar: bigint): Bytes;
  fromHex(hex: string): Bytes;
}

export const PrivateKey: PrivateKey = {
  fromScalar(scalar: bigint) {
    return numberToBytesLE(scalar, 32);
  },
  fromHex(hex: string) {
    return hexToBytes(hex);
  },
};

interface PublicKey {
  fromScalar(scalar: bigint): Bytes;
  fromPrivateKey(privateKey: Bytes): Bytes;
}

export const PublicKey: PublicKey = {
  fromScalar(scalar: bigint) {
    return G.multiply(scalar).toRawBytes();
  },
  fromPrivateKey(privateKey: Bytes) {
    return PublicKey.fromScalar(modN(privateKey));
  },
};

export const seedToMnemonic = (seed: Bytes): string[] => {
  const mnemonic: string[] = [];

  const n = BigInt(wordlist.length);
  for (let i = 0; i < seed.length / 4; i++) {
    const x = bytesToNumberLE(seed.slice(i * 4, i * 4 + 4));
    const w1 = x % n;
    const w2 = (x / n + w1) % n;
    const w3 = (x / n / n + w2) % n;
    mnemonic.push(
      wordlist[Number(w1)],
      wordlist[Number(w2)],
      wordlist[Number(w3)],
    );
  }

  const trimmed = mnemonic.map((w) => w.slice(0, 3)).join("");
  const checksum = crc32(trimmed);
  mnemonic.push(mnemonic[checksum % mnemonic.length]);
  return mnemonic;
};

export const mnemonicToSeed = (mnemonic: string): Bytes => {
  const n = wordlist.length;
  const words = mnemonic.split(" ");
  const seed = new Uint8Array(32);
  for (let i = 0; i < words.length / 3; i++) {
    const [word1, word2, word3] = words.slice(3 * i, 3 * i + 3);
    const w1 = wordlist.indexOf(word1);
    const w2 = wordlist.indexOf(word2);
    const w3 = wordlist.indexOf(word3);
    const x = w1 + n * ((n + w2 - w1) % n) + n * n * ((n + w3 - w2) % n);
    const b = numberToBytesLE(x, 4);
    seed[i * 4] = b[0];
    seed[i * 4 + 1] = b[1];
    seed[i * 4 + 2] = b[2];
    seed[i * 4 + 3] = b[3];
  }
  return seed;
};

export const getPrivateViewKey = (privateKey: Bytes): Bytes => {
  return PrivateKey.fromScalar(modN(keccak(privateKey)));
};

export const encodeAddress = (privateSpendKey: Bytes): string => {
  const privateViewKey = getPrivateViewKey(privateSpendKey);
  const addr = new Uint8Array(65);
  addr[0] = 0x12;
  addr.set(PublicKey.fromPrivateKey(privateSpendKey), 1);
  addr.set(PublicKey.fromPrivateKey(privateViewKey), 33);
  const hash = keccak(addr);
  return base58xmr.encode(concatBytes(addr, hash.slice(0, 4)));
};

interface DecodedAddress {
  network: Bytes;
  pubSpend: Bytes;
  pubView: Bytes;
  checksum: Bytes;
}

export const decodeAddress = (address: string): DecodedAddress => {
  const decoded = base58xmr.decode(address);
  const network = decoded.slice(0, 1);
  const pubSpend = decoded.slice(1, 33);
  const pubView = decoded.slice(33, 65);
  const checksum = decoded.slice(65);

  return {
    network,
    pubSpend,
    pubView,
    checksum,
  };
};

export const validateAddress = (address: string): boolean => {
  const { network, pubSpend, pubView, checksum } = decodeAddress(address);
  const hash = keccak(network, pubSpend, pubView);
  return bytesToHex(checksum) === bytesToHex(hash.slice(0, 4));
};
