# Change-password pages per site

`change-password-urls.json` is `quirks/change-password-URLs.json` from [apple/password-manager-resources](https://github.com/apple/password-manager-resources), unchanged, at commit [`e6a7cf40fe91aa8897b1be07b0ab416332c31488`](https://github.com/apple/password-manager-resources/tree/e6a7cf40fe91aa8897b1be07b0ab416332c31488) (SHA-256 `62838bb54084663e5dad60396c0008b78d13584955e1e9df0c5b93a0237cf2b0`, downloaded on 2026-11-05 with `scripts/generator/update-password-rules.sh`).

Each entry gives, for a domain, the page where the password is changed. Assisted password change offers it to the agent with `change_password_url`, without network; if the site isn't listed, Klav uses `https://<host>/.well-known/change-password`, with the item's port if its URL carries a different one (ADR 0022 §1.3 and §5).

MIT license:

> Copyright 2020 - 2026 Apple Inc.
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
