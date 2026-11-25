# Template for Formula/klav-cli.rb in OmarAlex24/homebrew-tap
# (deploy/homebrew/README.md; ADR 0048 §5.3). Each release bumps the tag in
# the URL and `sha256`; a 0000… placeholder makes the download fail.
#
# Linux only. On a Mac the CLI comes with the app (`brew install --cask
# omaralex24/tap/klav`, then "Set up this Mac"), so it isn't called `klav`:
# `brew install klav` never has to choose between this and the cask.
class KlavCli < Formula
  desc "Klav's command-line client, local daemon and browser native-messaging host"
  homepage "https://klav.dev/"
  url "https://github.com/OmarAlex24/klav/releases/download/v0.10.0/klav-linux-x86_64.tar.gz"
  # sha256 of klav-linux-x86_64.tar.gz, from the release's SHA256SUMS.
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0"

  livecheck do
    url :stable
    strategy :github_latest
  end

  # The release binary: x86_64, glibc 2.36 or later (Debian 12, Ubuntu 23.04).
  depends_on arch: :x86_64
  depends_on :linux

  def install
    bin.install "klav", "klavd", "klav-native-host"
  end

  def caveats
    <<~EOS
      `klav unlock` starts klavd when it's needed. To connect a browser:
        klav extension install-host
      The browser's host manifest names this version's klav-native-host,
      so run it again after every `brew upgrade klav-cli`.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/klav --version")
    assert_match version.to_s, shell_output("#{bin}/klavd --version")
  end
end
