# monero-js

This is a pure javascript implementation monero.

> **N.B**: See disclaimer. This library is a work in progress!

## Functionality

- Generate Seed
- Convert seed to mnemonic
- Convert mnemonic to seed
- Generate Public Spend Key, Private View Key and Public View Key

## Usage

### Mnemonic to Seed

```ts
import { mnemonicToSeed } from "monero-js/wallet";

const mnemonic =
  "inbound gather dads maze rising enough irritate gels dizzy novelty deity flippant ladder jigsaw anchor bawled nodes recipe inline diet perfect identity bakery bobsled diet";

const seed = mnemonicToSeed(mnemonic);
// 490767dabdd62f88c09d63e0e2b5c61cea0dbf9a9bb56120e62b6c74342dba06
```

## Attribution

This library uses the [noble](https://paulmillr.com/noble/) cryptographic libraries by [@paulmillr](https://github.com/paulmillr). Huge thanks!

- [@noble/curves](https://github.com/paulmillr/noble-curves)
- [@noble/hashes](https://github.com/paulmillr/noble-hashes)

## Disclaimer

This library is a work in progress and has not been audited or verified by anyone qualified.

## License

MIT License (MIT). Copyright (C) 2023 Sean N. (https://seann.co.uk)

See [LICENSE](/LICENSE).
