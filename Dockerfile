# Untrusted-code analysis sandbox.
# A locked-down Claude Code environment for reading repos/sites you don't trust.
# Built for rootless Podman; works with gVisor (runsc) via the --hardened flag.
FROM node:22-slim

# --- system + static-analysis tooling -------------------------------------
# ripgrep  : fast read-only search
# python3+pip : for semgrep
# iptables/ipset/dnsutils/aggregate : egress firewall (init-firewall.sh)
# git      : clone/inspect history (never runs repo hooks on clone)
# curl/ca-certificates : firewall verification + gitleaks download
RUN apt-get update && apt-get install -y --no-install-recommends \
        ripgrep git curl ca-certificates \
        python3 python3-pip python3-venv \
        iptables ipset dnsutils aggregate \
        sudo jq \
    && rm -rf /var/lib/apt/lists/*

# semgrep (static analysis) in an isolated venv
RUN python3 -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-cache-dir semgrep \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

# gitleaks (secret scanner) — pinned release, checksum-verified
ARG GITLEAKS_VERSION=8.21.2
RUN curl -sSL -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && gitleaks version

# Claude Code (the sandboxed, untrusted-facing agent)
RUN npm install -g @anthropic-ai/claude-code

# --- non-root user --------------------------------------------------------
# Rootless Podman already maps us to an unprivileged host user; this adds the
# in-container non-root layer. analyst owns /workspace; firewall init uses sudo.
RUN useradd -m -s /bin/bash analyst \
    && echo 'analyst ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh' > /etc/sudoers.d/firewall \
    && chmod 0440 /etc/sudoers.d/firewall

COPY init-firewall.sh /usr/local/bin/init-firewall.sh
RUN chmod 0755 /usr/local/bin/init-firewall.sh

USER analyst
WORKDIR /workspace
