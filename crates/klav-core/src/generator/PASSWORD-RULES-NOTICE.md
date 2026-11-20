# Per-site password rules

`password-rules.json` is `quirks/password-rules.json` from [apple/password-manager-resources](https://github.com/apple/password-manager-resources), unchanged, at commit [`e6a7cf40fe91aa8897b1be07b0ab416332c31488`](https://github.com/apple/password-manager-resources/tree/e6a7cf40fe91aa8897b1be07b0ab416332c31488) (SHA-256 `94e4f19a781edb7f5306a06eacd0d48e0195a2295972e4629341c3d046ac188f`, downloaded on 2026-11-04 with `scripts/generator/update-password-rules.sh`).

Each entry gives, for a domain, the site's password rules in the `passwordrules` grammar. The smart generator in `klav-core` reads them without network (ADR 0022 §1.3).

MIT license:

> Copyright 2020 - 2026 Apple Inc.
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
