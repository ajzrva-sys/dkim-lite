#!/bin/sh
set -eu

# Build a deliberately narrow Rspamd configuration for comparative benchmarks.
# The image's shipped module list is used so newly added modules are disabled too.
mkdir -p /etc/rspamd/local.d /etc/rspamd/override.d
for module_path in /usr/share/rspamd/config/modules.d/*.conf; do
    module=$(basename "$module_path" .conf)
    # dkim_signing calls the signing API exposed by Rspamd's dkim plugin, so
    # that one dependency must remain loaded as well.
    if [ "$module" != "dkim_signing" ] && [ "$module" != "dkim" ]; then
        printf 'enabled = false;\n' > "/etc/rspamd/local.d/$module.conf"
    fi
done

cat > /etc/rspamd/override.d/dkim_signing.conf <<'EOF'
enabled = true;
path = "/run/dkim-benchmark/benchmark.pem";
selector = "benchmark";
sign_authenticated = true;
sign_local = true;
allow_username_mismatch = true;
use_domain = "header";
use_esld = false;
EOF

cat > /etc/rspamd/override.d/options.inc <<'EOF'
filters = "dkim";
check_all_filters = false;
EOF

cat > /etc/rspamd/override.d/worker-controller.inc <<'EOF'
count = -1;
EOF

# Rspamd's documented signing-only route.  The authenticated macro supplied by
# the benchmark selects this rule, preventing core Bayes/MIME scanning while
# leaving DKIM_SIGNED available.
cat > /etc/rspamd/rspamd.conf.local <<'EOF'
settings {
  sign_only {
    authenticated = true;
    apply {
      symbols_enabled = ["DKIM_SIGNED"];
      flags = ["skip_process"];
    }
  }
}
EOF

if [ "$#" -gt 0 ]; then
    exec "$@"
fi
exec /usr/bin/rspamd -f
