%global debug_package %{nil}

Name:           dkim-lite
Version:        0.2.0
Release:        1%{?dist}
Summary:        Small outgoing-only DKIM milter
License:        ASL 2.0
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc
BuildRequires:  openssl-devel
BuildRequires:  pkgconfig
BuildRequires:  selinux-policy-devel
Requires:       openssl-libs
Requires:       postfix
Requires:       policycoreutils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
dkim-lite is a small Postfix milter that adds RSA-SHA256 DKIM signatures to
authorized outgoing mail using the RHEL system OpenSSL implementation.

%prep
%autosetup

%build
export CARGO_NET_OFFLINE=true
cargo build --release --locked --offline
make -C packaging/selinux \
    -f %{_datadir}/selinux/devel/Makefile dkim_lite.pp

%check
export CARGO_NET_OFFLINE=true
cargo test --release --locked --offline

%install
install -Dpm0755 target/release/dkim-lite %{buildroot}%{_sbindir}/dkim-lite
install -Dpm0644 dkim-lite.conf.example %{buildroot}%{_sysconfdir}/dkim-lite/dkim-lite.conf
install -Dpm0644 packaging/dkim-lite.service %{buildroot}%{_unitdir}/dkim-lite.service
install -Dpm0644 README.md %{buildroot}%{_docdir}/dkim-lite/README.md
install -Dpm0644 packaging/selinux/dkim_lite.pp \
    %{buildroot}%{_datadir}/selinux/packages/dkim-lite/dkim_lite.pp

%pre
getent group dkim-lite >/dev/null || groupadd --system dkim-lite
getent passwd dkim-lite >/dev/null || \
    useradd --system --gid dkim-lite --home-dir / --shell /sbin/nologin \
    --comment "Lite DKIM signer" dkim-lite

%post
semodule -i %{_datadir}/selinux/packages/dkim-lite/dkim_lite.pp || :
restorecon -R /run/dkim-lite 2>/dev/null || :
%systemd_post dkim-lite.service

%preun
%systemd_preun dkim-lite.service

%postun
%systemd_postun_with_restart dkim-lite.service
if [ "$1" -eq 0 ]; then
    semodule -r dkim_lite 2>/dev/null || :
fi

%files
%license LICENSE
%doc %{_docdir}/dkim-lite/README.md
%{_sbindir}/dkim-lite
%dir %{_sysconfdir}/dkim-lite
%config(noreplace) %{_sysconfdir}/dkim-lite/dkim-lite.conf
%{_unitdir}/dkim-lite.service
%{_datadir}/selinux/packages/dkim-lite/dkim_lite.pp

%changelog
* Fri Jul 31 2026 DKIM Lite Maintainers - 0.2.0-1
- Add system-OpenSSL RSA key generation and DNS record output

* Fri Jul 31 2026 DKIM Lite Maintainers - 0.1.0-1
- Initial package
