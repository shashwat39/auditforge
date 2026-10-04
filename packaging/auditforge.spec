%global debug_package %{nil}

Name:           auditforge
Version:        0.1.0
Release:        1%{?dist}
Summary:        Userspace Linux audit log collector

License:        MIT
Source0:        %{name}-%{version}.tar.gz

# cargo and rustc must already be on PATH (rustup or the distro packages).
# They are not BuildRequires so the spec can build where Rust is installed
# outside the RPM database.
Requires:       systemd
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%define _unitdir /usr/lib/systemd/system

%description
AuditForge reads Linux auditd log files from userspace and writes one
normalized JSON object per record. It does not consume kernel audit
events through netlink.

%prep
%setup -q

%build
cargo build --release --locked

%install
rm -rf %{buildroot}
install -D -m 0755 target/release/%{name} %{buildroot}%{_bindir}/%{name}
install -D -m 0644 packaging/%{name}.service %{buildroot}%{_unitdir}/%{name}.service
mkdir -p %{buildroot}/var/lib/%{name}
install -D -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -D -m 0644 SECURITY.md %{buildroot}%{_docdir}/%{name}/SECURITY.md
install -D -m 0644 CHANGELOG.md %{buildroot}%{_docdir}/%{name}/CHANGELOG.md

%pre
getent group auditforge >/dev/null || groupadd -r auditforge
getent passwd auditforge >/dev/null || \
    useradd -r -g auditforge -d /var/lib/auditforge -s /sbin/nologin \
    -c "AuditForge service account" auditforge

%post
if [ -d /var/lib/auditforge ]; then
    chown auditforge:auditforge /var/lib/auditforge
    chmod 0750 /var/lib/auditforge
fi
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
fi

%preun
if [ "$1" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop auditforge.service >/dev/null 2>&1 || :
    systemctl disable auditforge.service >/dev/null 2>&1 || :
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
    if [ "$1" -ge 1 ]; then
        systemctl try-restart auditforge.service >/dev/null 2>&1 || :
    fi
fi

%files
%license LICENSE
%dir %{_docdir}/%{name}
%{_docdir}/%{name}/README.md
%{_docdir}/%{name}/SECURITY.md
%{_docdir}/%{name}/CHANGELOG.md
%{_bindir}/%{name}
%{_unitdir}/%{name}.service
# Directory only. Files created later are not owned by the package, so
# uninstall removes this directory only when it is empty.
%dir %attr(0750, root, root) %verify(not user group) /var/lib/auditforge

%changelog
* Sat Oct 04 2026 AuditForge <auditforge@localhost> - 0.1.0-1
- Initial package.
