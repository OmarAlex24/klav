# Template for Formula/klav-server.rb in OmarAlex24/homebrew-tap
# (deploy/homebrew/README.md; ADR 0048 §5.3). Each release bumps the tag in
# both URLs and both `sha256` lines; a 0000… placeholder makes the download
# fail.
class KlavServer < Formula
  desc "Sync server for Klav, the end-to-end encrypted password manager"
  homepage "https://klav.dev/"
  # The tag's source: what macOS builds, since a prebuilt binary would be
  # unsigned and quarantined there (docs/releasing.md §1).
  url "https://github.com/OmarAlex24/klav/archive/refs/tags/v0.10.0.tar.gz"
  # sha256 of that archive (README.md, "Each release").
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "AGPL-3.0-only"

  livecheck do
    url :stable
    strategy :github_latest
  end

  on_macos do
    depends_on "rust" => :build
  end

  # Linux: the release's prebuilt binary (x86_64, glibc 2.36 or later)
  # instead of a Rust build.
  on_linux do
    depends_on arch: :x86_64

    resource "prebuilt" do
      url "https://github.com/OmarAlex24/klav/releases/download/v0.10.0/klav-server-linux-x86_64.tar.gz"
      # sha256 of klav-server-linux-x86_64.tar.gz, from the release's SHA256SUMS.
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    if OS.linux?
      resource("prebuilt").stage do
        bin.install "klav-server"
        # For a system install without Homebrew; here `brew services` runs
        # the server. Kept for reference.
        pkgshare.install "klav-server.service", "server.toml.example"
      end
    else
      system "cargo", "install", *std_cargo_args(path: "crates/klav-server")
    end
  end

  # The configuration is written once and never overwritten on upgrade: the
  # server starts closed to strangers, in invite mode, on 127.0.0.1 only.
  post_install_steps do
    mkdir_p "klav", base: :var
    mkdir_p "klav", base: :etc
    unless_path_exists "klav/server.toml", base: :etc do
      write_file "klav/server.toml", <<~TOML, base: :etc
        # klav-server's configuration (https://docs.klav.dev/self-hosting/configuration/).
        listen = "127.0.0.1:8080"
        database_url = "sqlite://{{var}}/klav/klav.db"
        data_dir = "{{var}}/klav"
        trust_forwarded_for = false
        allow_registration = false
        registration_mode = "invite"
      TOML
    end
  end

  service do
    run [opt_bin/"klav-server", "--config", etc/"klav/server.toml"]
    keep_alive true
    working_dir var/"klav"
    log_path var/"log/klav-server.log"
    error_log_path var/"log/klav-server.log"
  end

  def caveats
    <<~EOS
      klav-server listens on 127.0.0.1:8080. Its configuration is
        #{etc}/klav/server.toml
      and its database and attachments are in #{var}/klav.
      Start it, now and at login:
        brew services start klav-server

      Put TLS in front before another device connects
      (https://docs.klav.dev/self-hosting/tls-and-reverse-proxy/):
        tailscale serve --bg 8080       # private: only your tailnet
        caddy reverse-proxy --from klav.example.com --to 127.0.0.1:8080

      Nobody can sign up without an invite. Create yours:
        KLAV_CONFIG=#{etc}/klav/server.toml klav-server invite create --email you@example.com
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/klav-server --version")

    port = free_port
    (testpath/"server.toml").write <<~TOML
      listen = "127.0.0.1:#{port}"
      database_url = "sqlite://#{testpath}/klav.db"
      data_dir = "#{testpath}/data"
    TOML
    pid = spawn bin/"klav-server", "--config", testpath/"server.toml"
    begin
      healthy = 20.times.any? do
        sleep 0.5
        system bin/"klav-server", "healthcheck", "--config", testpath/"server.toml"
      end
      assert healthy, "klav-server didn't answer on /v1/health"
    ensure
      Process.kill("TERM", pid)
      Process.wait(pid)
    end
  end
end
