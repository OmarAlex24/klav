# Template for Casks/klav.rb in OmarAlex24/homebrew-tap
# (deploy/homebrew/README.md; ADR 0048 §5.3). Each release bumps `version`
# and `sha256`; a 0000… placeholder makes the download fail.
cask "klav" do
  version "0.10.0"
  # sha256 of Klav.dmg, from the release's SHA256SUMS.
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  url "https://github.com/OmarAlex24/klav/releases/download/v#{version}/Klav.dmg"
  name "Klav"
  desc "End-to-end encrypted password manager for people and AI agents"
  homepage "https://klav.dev/"

  livecheck do
    url :url
    strategy :github_latest
  end

  # Sparkle updates the app itself; `brew upgrade` leaves it alone.
  auto_updates true
  depends_on arch: :arm64
  depends_on macos: :sequoia

  app "Klav.app"

  # klavd runs as a LaunchAgent the app registers ("Set up this Mac").
  uninstall launchctl: "dev.klav.klavd",
            quit:      "dev.klav.mac"

  # Only what can be rebuilt. ~/Library/Application Support/klav holds the
  # account and its encrypted copy of the vault, and is never removed here:
  # without the emergency kit, the Secret Key in it is the only copy.
  zap trash: [
    "~/Library/Caches/dev.klav.mac",
    "~/Library/HTTPStorages/dev.klav.mac",
    "~/Library/Preferences/dev.klav.mac.plist",
  ]

  caveats <<~EOS
    Open Klav and choose "Set up this Mac": it installs `klav` in
    /usr/local/bin, starts klavd and connects your browsers.
  EOS
end
