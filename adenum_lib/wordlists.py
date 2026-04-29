from __future__ import annotations

COMMON_AD_USERS = [
    "administrator", "admin", "guest", "krbtgt", "default", "operator",
    "backup", "test", "user", "svc", "service", "helpdesk", "support",
    "manager", "supervisor", "intern", "owner", "office",
    "exchange", "exch", "mail", "smtp", "imap", "pop3",
    "sql", "mssql", "mysql", "postgres", "oracle",
    "web", "www", "iis", "apache", "ftp", "tftp", "git",
    "sccm", "sharepoint", "wsus", "veeam", "vmware", "esxi",
    "svc_sql", "svc_web", "svc_backup", "svc_iis", "svc_exchange",
    "svc_sccm", "svc_sharepoint", "svc_veeam", "svc_vmware",
    "svc-sql", "svc-web", "svc-backup", "svc-iis",
    "service.sql", "service.web", "service.backup",
    "scanner", "printer", "scanaccount", "ldap", "ldapsync",
    "ad_sync", "azure_sync", "mso_sync", "aad_sync",
    "domainadmin", "enterprise_admin", "enterprise.admin",
    "john", "jane", "alice", "bob", "charlie", "david", "mike",
    "robert", "mary", "linda", "barbara", "susan", "jessica",
]


COMMON_PASSWORDS = [
    "Password1", "Password123", "Password123!", "P@ssw0rd",
    "Welcome1", "Welcome123", "Summer2024", "Summer2025", "Spring2024",
    "Winter2024", "Autumn2024", "January2024", "Changeme1",
    "Company123", "Letmein123", "Admin@123", "Admin123!",
]


def merge_userlists(*lists) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for source in lists:
        for entry in source:
            cleaned = entry.strip().lower()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                out.append(entry.strip())
    return out
