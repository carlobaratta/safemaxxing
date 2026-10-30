# Homebrew formula for a custom tap:
#
#   brew tap carlobaratta/tap
#   brew install safemaxxing
#
# There is deliberately no `service` block: the Homebrew prefix is owned by the user, so a root
# daemon run from it (`sudo brew services`) would let any code running as that user replace the
# bundle and gain root at the next start (see SECURITY.md). Root use goes through the .pkg,
# which installs a root-owned copy under /usr/local/libexec. It installs the signed, notarized onedir bundle from the GitHub release (one per arch). The
# url/sha256 pairs below are placeholders until the first tagged release; the release workflow
# prints each tarball's SHA-256 so the tap can be updated. Keep this file in the tap repo
# (carlobaratta/homebrew-tap) as Formula/safemaxxing.rb; it lives here as the source of truth.
class Safemaxxing < Formula
  desc "Headless privacy supervisor and egress firewall for macOS"
  homepage "https://github.com/carlobaratta/safemaxxing"
  version "0.2.0"
  license "MIT"

  on_arm do
    url "https://github.com/carlobaratta/safemaxxing/releases/download/v0.2.0/safemaxxing-0.2.0-arm64.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  on_intel do
    url "https://github.com/carlobaratta/safemaxxing/releases/download/v0.2.0/safemaxxing-0.2.0-x86_64.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  depends_on :macos

  def install
    # The tarball holds the onedir bundle under a single safemaxxing/ directory, and Homebrew
    # stages into that directory, so the working directory is the bundle itself: the binary
    # plus _internal/.
    libexec.install Dir["*"]
    bin.install_symlink libexec/"safemaxxing"
  end

  def caveats
    <<~EOS
      safemaxxing needs root for `watch`, `tui`, `menubar` and the firewall commands. This
      Homebrew install lives in a user-writable prefix, so do not run it as root (no
      `sudo safemaxxing`, no `sudo brew services`): install the signed .pkg from the GitHub
      release for a root-owned copy in /usr/local/libexec instead. `doctor`, `version` and
      `permissions` (with Full Disk Access) work without root.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/safemaxxing version")
  end
end
