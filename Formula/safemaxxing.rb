# Homebrew formula for a custom tap:
#
#   brew tap carlobaratta/tap
#   brew install safemaxxing
#   sudo brew services start safemaxxing   # runs `safemaxxing watch` as root
#
# It installs the signed, notarized onedir bundle from the GitHub release (one per arch). The
# url/sha256 pairs below are placeholders until the first tagged release; the release workflow
# prints each tarball's SHA-256 so the tap can be updated. Keep this file in the tap repo
# (carlobaratta/homebrew-tap) as Formula/safemaxxing.rb; it lives here as the source of truth.
class Safemaxxing < Formula
  desc "Headless privacy supervisor and egress firewall for macOS"
  homepage "https://github.com/carlobaratta/safemaxxing"
  version "0.1.1"
  license "MIT"

  on_arm do
    url "https://github.com/carlobaratta/safemaxxing/releases/download/v0.1.1/safemaxxing-0.1.1-arm64.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  on_intel do
    url "https://github.com/carlobaratta/safemaxxing/releases/download/v0.1.1/safemaxxing-0.1.1-x86_64.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  depends_on :macos

  def install
    # The tarball holds the PyInstaller onedir bundle under safemaxxing/.
    libexec.install "safemaxxing"
    bin.install_symlink libexec/"safemaxxing/safemaxxing"
  end

  service do
    # Detection only by default (no automatic blocking); needs root for log, pf and pktap.
    run [opt_bin/"safemaxxing", "watch", "--json"]
    keep_alive true
    require_root true
    log_path var/"log/safemaxxing.log"
    error_log_path var/"log/safemaxxing.log"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/safemaxxing version")
  end
end
