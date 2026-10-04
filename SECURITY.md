# Security policy

## Supported use

AuditForge 0.1 reads audit records that auditd has already written to a log file. It prints JSON to standard output. It does not open an audit netlink socket, load eBPF, or change kernel audit rules.

## Reporting a vulnerability

Open a private security advisory on the project repository, or email the maintainers if the repository has no advisory feature. Please include a proof of concept, the AuditForge version, and the operating system. Give the project time to fix the issue before publishing details.

## What the program trusts

- The audit log is data, not code. Record contents are copied into JSON strings and are not passed to a shell, a dynamic loader, or a format string.
- A line longer than 1 MiB is discarded with an error on stderr so one corrupt record cannot grow memory without a limit.
- Malformed lines produce a JSON object with null fields and the original text in `raw`. They do not stop the process.
- Paths passed to `--input` are opened only for reading.

## Service account

The systemd unit runs as the unprivileged `auditforge` user with `NoNewPrivileges`, `PrivateTmp`, `ProtectHome`, and `ProtectSystem=strict`.

On Oracle Linux and Fedora, `/var/log/audit/audit.log` is typically mode `0600` and owned by root. The service user cannot read it until an administrator grants access, for example with `setfacl`. The unit does not run as root to paper over that restriction. See the comments in `packaging/auditforge.service`.

`/var/lib/auditforge` is created mode `0750` for that user. Version 0.1 does not write state there. Uninstall does not delete files found in that directory.

## Out of scope for this version

- Kernel audit netlink and eBPF
- Authentication, a network API, or multi-tenant collection
- Redaction of secrets that may appear inside audit records (`execve` arguments, file paths, account names)

Treat the JSON output as sensitive. It is a copy of the audit log.
