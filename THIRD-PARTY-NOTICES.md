# Third-party notices

Klav's own code is licensed under Apache-2.0 ([`LICENSE-APACHE`](LICENSE-APACHE)), except `crates/klav-server`, which is AGPL-3.0-only ([`crates/klav-server/LICENSE`](crates/klav-server/LICENSE)); see [ADR 0003](docs/decisiones/0003-licencias.md).

This file lists the third-party material that Klav **bundles**: data files, fonts, icons and code that are copied into this repository or into what Klav distributes, and that come with their own license. It follows [ADR 0031](docs/decisiones/0031-repositorio-en-ingles-y-open-source.md) §5. Each entry says what the material is, where it lives, its license, its copyright line, where it ends up, and the notice its license asks for. The full license texts are at the end.

## Dependencies

Rust crates and npm packages are not listed one by one here, and Klav's binaries, apps and sites do not carry their notices yet. [`deny.toml`](deny.toml) limits the licenses Rust crates may use, and the `cargo-deny` CI task checks it on every PR; it checks which licenses are used, not that their notices ship. Besides MIT and Apache-2.0, the crates compiled into Klav's binaries include BSD-3-Clause (`curve25519-dalek`, `ed25519-dalek`, `x25519-dalek`, `subtle`, `aws-lc-sys`; `matchit` in `klav-server` and `klav-proxy`), ISC (`rustls-webpki`, `untrusted`, `aws-lc-sys`), Unicode-3.0 (the ICU4X crates and their data) and MPL-2.0 (UniFFI, below), whose notices must go with a binary. The extension and the SDK have no npm runtime dependencies. The docs site ships code from Astro, Pagefind and `@cloudflare/nimbus-docs` (MIT). No npm license is checked yet: the `docs` task runs `pnpm audit`, which checks advisories, not licenses.

A dependency can still carry bundled data under a license that its own package metadata doesn't show. Known cases: the Public Suffix List, listed below, and the dictionaries in the `zxcvbn` crate (MIT), which Dropbox's zxcvbn built from Wikipedia and Wiktionary frequency lists, US census names and leaked-password lists; `zxcvbn` comes in through `klav-client`'s `health` feature, which `klav-cli`, `klav-daemon` and `klav-ffi` turn on, so it ships in the `klav` CLI, `klavd`, `klav-native-host`, `klav-proxy` (through `klav-sdk` and `klav-daemon`) and the iOS and Mac apps, but not in the extension.

## Summary

| Material | License | In the repository | Ends up in |
|---|---|---|---|
| [Apple password rules](#apple-password-manager-resources) | MIT | `crates/klav-core/src/generator/password-rules.json` | Every binary built on `klav-core`'s generator (see the entry) |
| [Apple change-password pages](#apple-password-manager-resources) | MIT | `crates/klav-core/src/generator/change-password-urls.json` | Same as above |
| [EFF Large Wordlist](#eff-large-wordlist-for-passphrases) | CC BY 3.0 US | `crates/klav-core/src/generator/eff_large_wordlist.txt` | Same as above |
| [Public Suffix List](#public-suffix-list) | MPL-2.0 | Not in the repository: compiled in from the `psl` crate | Binaries built with `klav-core`'s `rp-id` feature |
| [UniFFI](#uniffi) | MPL-2.0 | Not in the repository: crates `uniffi` and `uniffi_core` 0.32.2 | iOS app, Mac app |
| [Geist and Geist Mono](#fonts) | SIL OFL 1.1 | `apps/ios/Shared/Fonts/`, `apps/extension/static/fonts/`, `apps/web/public/fonts/` | iOS app, Mac app, browser extension, website |
| [Departure Mono](#fonts) | SIL OFL 1.1 | Same three folders | Same as above |
| [Inter and JetBrains Mono](#fonts) | SIL OFL 1.1 | Not in the repository: npm packages `@fontsource-variable/inter` and `@fontsource-variable/jetbrains-mono` 5.3.0 | Docs site |
| [Simple Icons](#simple-icons) | CC0 1.0 (project license; each bundled logo has CC0 1.0 or no license data, see the entry) | `assets/site-icons/site-icons.json` | iOS app, Mac app, browser extension |
| [Phosphor Icons](#phosphor-icons) | MIT | Not in the repository: npm package `@iconify-json/ph` 1.2.2 | Docs site |
| [Sparkle](#sparkle) | MIT, plus the licenses of the code it includes | Not in the repository: Swift package pinned in `apps/ios/Package.resolved` | Mac app |
| [Nimbus docs starter](#nimbus-docs-starter) | MIT | `apps/docs/` (scaffolded source) | Docs site |

"Ends up in" was worked out by reading the code and the build scripts in this repository. No built artifact was opened to confirm it.

## What ships today

The notices are in this file and next to the material in the source tree. The distributed artifacts carry less: the font license files ship with the fonts in the iOS and Mac apps, the extension and the website, but the `klav` CLI, `klavd`, `klav-native-host`, `klav-proxy`, `klav-forward` and `klav-server` (and the images that `Dockerfile`, `deploy/railway/Dockerfile` and `deploy/proxy/Dockerfile` build) carry no notices, the iOS and Mac apps have no acknowledgements screen, the extension shows none, and the docs site ships Inter and JetBrains Mono without their license files. Carrying the notices into each artifact is separate work (ADR 0031 §5).

## Apple password-manager-resources

- **What:** two data files from [apple/password-manager-resources](https://github.com/apple/password-manager-resources), unchanged, at commit `e6a7cf40fe91aa8897b1be07b0ab416332c31488`:
  - `quirks/password-rules.json`, kept as `crates/klav-core/src/generator/password-rules.json`: each site's password rules, which the generator follows.
  - `quirks/change-password-URLs.json`, kept as `crates/klav-core/src/generator/change-password-urls.json`: each site's change-password page, for the assisted password change.
- **Provenance:** [`PASSWORD-RULES-NOTICE.md`](crates/klav-core/src/generator/PASSWORD-RULES-NOTICE.md) and [`CHANGE-PASSWORD-URLS-NOTICE.md`](crates/klav-core/src/generator/CHANGE-PASSWORD-URLS-NOTICE.md) give the SHA-256 of each file and the date it was downloaded. `scripts/generator/update-password-rules.sh` updates both.
- **License:** MIT.
- **Copyright:** Copyright 2020 - 2026 Apple Inc.
- **Ends up in:** `include_str!` compiles both files into `klav-core` (`generator/rules.rs:25` and `generator/change_password.rs:20`). The crates that call the generator are `klav-cli`, `klav-client`, `klav-daemon`, `klav-ffi`, `klav-sdk` and `klav-wasm`. So the files are in:
  - the `klav` CLI, `klavd` and `klav-native-host`;
  - the iOS app and the Mac app, through `klav-ffi`; the Mac app also carries the three binaries above as helpers;
  - the browser extension, through `klav-wasm`;
  - `klav-proxy` (and the image `deploy/proxy/Dockerfile` builds), which depends on `klav-client` and shows a pairing code from the EFF list.
- **Notice:** MIT asks for the copyright line and the permission notice "in all copies or substantial portions of the Software". The full text is under [MIT (Apple Inc.)](#mit-apple-inc).

`generator/rules.rs` also implements Apple's `passwordrules` grammar. It follows the behavior of Apple's reference parser, `tools/PasswordRulesParser/PasswordRulesParser.js`, but it is Klav's own Rust code, not a copy of it.

## EFF Large Wordlist for Passphrases

- **What:** the *EFF Large Wordlist for Passphrases* (7776 words) from the Electronic Frontier Foundation, unchanged: `crates/klav-core/src/generator/eff_large_wordlist.txt`. It is used for passphrases and for the six pairing words of an agent.
- **Provenance:** [`WORDLIST-NOTICE.md`](crates/klav-core/src/generator/WORDLIST-NOTICE.md), with the source URL and the SHA-256.
- **License:** [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/), the license the [EFF copyright policy](https://web.archive.org/web/20160728232614/https://www.eff.org/copyright) linked when the list was published in July 2016. The [policy today](https://www.eff.org/copyright) names CC BY 4.0 International; the attribution below meets both.
- **Copyright:** © Electronic Frontier Foundation.
- **Ends up in:** `include_str!` compiles it into `klav-core` (`generator/mod.rs:52`), and it ships in the same places as the Apple files above.
- **Notice:** CC BY 3.0 asks for credit to the author, the title, the license's URI and the source's URL wherever the work is distributed:

  > *EFF Large Wordlist for Passphrases*, by the Electronic Frontier Foundation (<https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases>), licensed under CC BY 3.0 US (<https://creativecommons.org/licenses/by/3.0/us/>). Klav uses it without modifications.

## Public Suffix List

- **What:** Mozilla's [Public Suffix List](https://publicsuffix.org/). Klav doesn't keep a copy: the `psl` crate (2.1.247 in `Cargo.lock`) compiles the list into its code. `klav-core` uses it only to validate a passkey's rpId, behind the optional `rp-id` feature ([ADR 0020](docs/decisiones/0020-passkeys.md)).
- **License:** the list is under the [Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/), as the header of the upstream `public_suffix_list.dat` says (the copy inside `psl` drops it). The `psl` crate's own code is MIT/Apache-2.0, and that is what its metadata declares, so `cargo-deny` sees only MIT/Apache-2.0.
- **Ends up in:** `klav-client`, `klav-daemon` and `klav-import` turn the `rp-id` feature on; `klav-wasm` doesn't. So the list is in the `klav` CLI, `klavd`, `klav-native-host`, `klav-proxy` and the iOS and Mac apps, but not in the extension.
- **Notice:** MPL-2.0 §3.2 asks that whoever distributes the work in executable form tell recipients where to get its source code. For the list:

  > This product includes the Public Suffix List, licensed under the Mozilla Public License 2.0 (<https://mozilla.org/MPL/2.0/>). Its source is in the `psl` crate 2.1.247 (<https://docs.rs/crate/psl/2.1.247/source/data/rules.txt>); the current list is at <https://publicsuffix.org/list/public_suffix_list.dat>.

## UniFFI

- **What:** the runtime of [UniFFI](https://github.com/mozilla/uniffi-rs) 0.32.2 (`uniffi`, `uniffi_core`), from Mozilla, compiled into `KlavFFI` through `klav-ffi`; `uniffi_bindgen` generates the Swift bindings at build time. Klav uses the crates unmodified.
- **License:** [Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/). `deny.toml` allows MPL-2.0 only for the uniffi crates.
- **Ends up in:** the iOS app and the Mac app.
- **Notice:** MPL-2.0 §3.2 asks that whoever distributes the work in executable form tell recipients where to get its source code:

  > This product includes UniFFI 0.32.2, licensed under the Mozilla Public License 2.0 (<https://mozilla.org/MPL/2.0/>). Its source is at <https://github.com/mozilla/uniffi-rs/tree/v0.32.2>.

## Fonts

All four families are under the SIL Open Font License 1.1. None of them declares a Reserved Font Name. The license text is under [SIL Open Font License 1.1](#sil-open-font-license-11).

| Family | Files | Copyright | Ends up in |
|---|---|---|---|
| Geist and Geist Mono | `geist.ttf`, `geist-mono-400.ttf` in `apps/ios/Shared/Fonts/`; `geist.woff2`, `geist-mono-400.woff2` in `apps/extension/static/fonts/` and `apps/web/public/fonts/` | Copyright 2024 The Geist Project Authors (https://github.com/vercel/geist-font) | iOS app and Mac app (`apps/ios/Shared`), the extension (the build copies every file in `static/fonts`), and the website (the Dockerfile copies `public`) |
| Departure Mono | `departure-mono-400.ttf` and `departure-mono-400.woff2`, in the same three folders | Copyright 2022–2024 Helena Zhang (helenazhang.com). | Same as Geist |
| Inter | npm package `@fontsource-variable/inter` 5.3.0, imported in `apps/docs/src/layouts/BaseLayout.astro` | Copyright 2016 The Inter Project Authors (https://github.com/rsms/inter) | Docs site |
| JetBrains Mono | npm package `@fontsource-variable/jetbrains-mono` 5.3.0, imported in the same file | Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono) | Docs site |

Each of the three font folders in the repository already holds the license next to the fonts: `LICENSE-geist.txt` and `LICENSE-departure-mono.txt`. The OFL lets the fonts be bundled with software, as long as the copyright line and the license go with them.

## Simple Icons

- **What:** the monochrome logos of about 300 common sites, from [Simple Icons](https://simpleicons.org) 16.36.0. `scripts/site-icons.mjs` downloads the pinned `simple-icons` npm package, checks its integrity and rewrites each path into `assets/site-icons/site-icons.json`; `assets/site-icons/sites.txt` lists which logos.
- **License:** the Simple Icons project is [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/), but not every icon in it is ([disclaimer](https://github.com/simple-icons/simple-icons/blob/16.36.0/DISCLAIMER.md)). Klav ships only logos whose entry in `data/simple-icons.json` has no `license` field or says `CC0-1.0`, and `scripts/site-icons.mjs` stops if `sites.txt` names any other. In 16.36.0 that is 313 logos: 2 marked CC0-1.0 (`codeberg`, `sourcehut`) and 311 with no license data, for which the project's CC0 1.0 is the only license on record. Simple Icons warns that "the absence of license data for a particular icon does not imply that the icon is not released under a license", and that its license data may be out of date. Three logos that 16.36.0 licenses otherwise were removed from `sites.txt`: `gnuprivacyguard` (GPL-3.0-or-later), `letsencrypt` (CC BY-NC 4.0) and `vivaldi` (CC BY 4.0). The script rewrites each path with absolute commands, turns arcs into cubic curves and rounds to two decimals. CC0 1.0 asks for no notice; `site-icons.json` records its source in its `source` field.
- **Trademarks:** the logos are trademarks of their owners. Klav shows them only so that people recognize their own items. That implies no relationship with those brands and no endorsement by them. CC0 1.0 does not cover trademark rights (CC0 §4(a)); Simple Icons asks users to follow each brand's guidelines, linked in the `guidelines` field of its data where it has them.
- **Ends up in:** the browser extension (the build copies `site-icons.json`), and the iOS app and the Mac app (`apps/ios/project.yml` adds it as a resource).

## Phosphor Icons

- **What:** icons from [Phosphor Icons](https://phosphoricons.com), through the npm package `@iconify-json/ph` 1.2.2. Nimbus's `Icon` component inlines each glyph as SVG when the docs site is built.
- **License:** MIT.
- **Copyright:** Copyright (c) 2023 Phosphor Icons. The copyright line comes from [phosphor-icons/core](https://github.com/phosphor-icons/core/blob/main/LICENSE), which the package's `info.json` names as its license.
- **Ends up in:** the docs site.
- **Notice:** the MIT text under [MIT (Phosphor Icons)](#mit-phosphor-icons).

## Sparkle

- **What:** [Sparkle](https://sparkle-project.org) 2.10.0 (revision `eef1a539a373c1f1a320624b1130fc5de7b2e100`), the update framework of the Mac app ([ADR 0027](docs/decisiones/0027-app-de-mac.md) §7). Swift Package Manager fetches it from the pin in `apps/ios/Package.resolved`; only the `KlavMac` target in `apps/ios/project.yml` uses it.
- **License:** MIT for Sparkle. Sparkle includes code under other licenses: bsdiff (BSD-2-Clause style), sais-lite (MIT), orlp/ed25519 (zlib) and `SUSignatureVerifier.m` (BSD-2-Clause style).
- **Copyright:** Copyright (c) 2006-2013 Andy Matuschak, and the others listed in its license.
- **Ends up in:** the Mac app, as `Contents/Frameworks/Sparkle.framework` (`scripts/macos/build-app.sh`).
- **Notice:** the BSD-style terms ask that binary redistributions reproduce the copyright notice, the conditions and the disclaimer "in the documentation and/or other materials provided with the distribution". The full text, copied from Sparkle's `LICENSE` at the pinned revision, is under [Sparkle](#sparkle-1).

## Nimbus docs starter

- **What:** the docs site in `apps/docs` began as the Nimbus starter (`@cloudflare/create-nimbus-docs`; the scaffold is described in `apps/docs/AGENT.md` and [ADR 0039](docs/decisiones/0039-public-docs-site.md)). Its layouts, components and styles were copied into `apps/docs/src` and have since been edited. The site also depends on the `@cloudflare/nimbus-docs` npm package (0.19.3).
- **License:** MIT, according to the npm metadata of both packages.
- **Copyright:** Copyright (c) 2025 Cloudflare, Inc., in the `LICENSE` of both `@cloudflare/nimbus-docs` 0.19.3 and `@cloudflare/create-nimbus-docs` 0.8.3, the starter version `apps/docs` was scaffolded from.
- **Ends up in:** the docs site.
- **Notice:** the MIT text under [MIT (Cloudflare, Inc.)](#mit-cloudflare-inc).

## In the repository, but not distributed

These files are copied from public specifications. Only the tests read them, and no binary, app or site includes them:

- `docs/vectores/hpke-rfc9180.json`: test vector A.2.1 of [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180).
- `docs/vectores/totp.json`: the test vectors of [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) (appendix B) and [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226) (appendix D).
- `docs/vectores/webauthn-l3.json`: a test vector from [W3C Web Authentication Level 3](https://w3c.github.io/webauthn/#sctn-test-vectors-none-es256), §16.

`CODE_OF_CONDUCT.md` is adapted from the Contributor Covenant 3.0 and carries its attribution. As an adaptation of a CC BY-SA 4.0 work, it is under CC BY-SA 4.0, not Apache-2.0.

## License texts

### MIT (Apple Inc.)

For `password-rules.json` and `change-password-urls.json`, copied from the two `*-NOTICE.md` files:

> Copyright 2020 - 2026 Apple Inc.
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### MIT (Phosphor Icons)

> Copyright (c) 2023 Phosphor Icons
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### MIT (Cloudflare, Inc.)

> Copyright (c) 2025 Cloudflare, Inc.
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### SIL Open Font License 1.1

For Geist and Geist Mono, Departure Mono, Inter and JetBrains Mono, with these copyright lines:

- Copyright 2024 The Geist Project Authors (https://github.com/vercel/geist-font)
- Copyright 2022–2024 Helena Zhang (helenazhang.com).
- Copyright 2016 The Inter Project Authors (https://github.com/rsms/inter)
- Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono)

This Font Software is licensed under the SIL Open Font License, Version 1.1. The text below is copied from `apps/ios/Shared/Fonts/LICENSE-geist.txt`; the same text is in `LICENSE-departure-mono.txt` and in the `LICENSE` of both Fontsource packages.

```text
-----------------------------------------------------------
SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
-----------------------------------------------------------

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded, 
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply
to any document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may
include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software components as
distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting,
or substituting -- in part or in whole -- any of the components of the
Original Version, by changing formats or by porting the Font Software to a
new environment.

"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,
in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to
remain under this license does not apply to any document created
using the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
OTHER DEALINGS IN THE FONT SOFTWARE.
```

### Sparkle

Copied from `LICENSE` in Sparkle at revision `eef1a539a373c1f1a320624b1130fc5de7b2e100` (2.10.0):

```text
Copyright (c) 2006-2013 Andy Matuschak.
Copyright (c) 2009-2013 Elgato Systems GmbH.
Copyright (c) 2011-2014 Kornel Lesiński.
Copyright (c) 2015-2017 Mayur Pawashe.
Copyright (c) 2014 C.W. Betts.
Copyright (c) 2014 Petroules Corporation.
Copyright (c) 2014 Big Nerd Ranch.
All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

=================
EXTERNAL LICENSES
=================

bspatch.c and bsdiff.c, from bsdiff 4.3 <http://www.daemonology.net/bsdiff/>:

Copyright 2003-2005 Colin Percival
All rights reserved

Redistribution and use in source and binary forms, with or without
modification, are permitted providing that the following conditions 
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

--

sais.c and sais.h, from sais-lite (2010/08/07) <https://sites.google.com/site/yuta256/sais>:

The sais-lite copyright is as follows:

Copyright (c) 2008-2010 Yuta Mori All Rights Reserved.

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

--

Portable C implementation of Ed25519, from https://github.com/orlp/ed25519

Copyright (c) 2015 Orson Peters <orsonpeters@gmail.com>

This software is provided 'as-is', without any express or implied warranty. In no event will the
authors be held liable for any damages arising from the use of this software.

Permission is granted to anyone to use this software for any purpose, including commercial
applications, and to alter it and redistribute it freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not claim that you wrote the
   original software. If you use this software in a product, an acknowledgment in the product
   documentation would be appreciated but is not required.

2. Altered source versions must be plainly marked as such, and must not be misrepresented as
   being the original software.

3. This notice may not be removed or altered from any source distribution.

--

SUSignatureVerifier.m:

Copyright (c) 2011 Mark Hamlin.

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted providing that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

## Keeping this file current

A PR that adds, removes or updates bundled material (a vendored data file, a font, an icon, a Swift package, an npm package that ships in the docs site) updates this file in the same PR. After `scripts/generator/update-password-rules.sh` or `scripts/site-icons.mjs` runs, check its entry here. `cargo-deny` rejects a Rust license outside `deny.toml`; nothing yet catches new vendored material or a new npm license.
