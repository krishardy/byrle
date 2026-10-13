//! Roles, and the permissions each grants. Permissions are a closed set in code; a role is
//! a named set of them, held by an account by name. See docs/admin-plan.md §4.2.

/// What a console request needs. Every API handler declares one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    /// R3, R5, R6 and R9: dependencies, refusals, failures and the request log.
    RequestsRead,
    /// R4: versions served before a malware advisory was loaded.
    AlertsRead,
    /// R7: the configuration, with secrets removed.
    ConfigRead,
    /// R10: each component's status.
    StatusRead,
    /// R8: the account event log.
    EventsRead,
    /// Accounts, their roles and tokens, read.
    AccountsRead,
    /// Accounts, their roles and tokens, changed.
    AccountsWrite,
}

impl Permission {
    /// Every permission.
    pub const ALL: [Permission; 7] = [
        Self::RequestsRead,
        Self::AlertsRead,
        Self::ConfigRead,
        Self::StatusRead,
        Self::EventsRead,
        Self::AccountsRead,
        Self::AccountsWrite,
    ];

    /// Its name, such as `requests.read`.
    pub fn name(self) -> &'static str {
        match self {
            Self::RequestsRead => "requests.read",
            Self::AlertsRead => "alerts.read",
            Self::ConfigRead => "config.read",
            Self::StatusRead => "status.read",
            Self::EventsRead => "events.read",
            Self::AccountsRead => "accounts.read",
            Self::AccountsWrite => "accounts.write",
        }
    }
}

/// A named set of permissions an account holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Every permission.
    Admin,
}

impl Role {
    /// Every role.
    pub const ALL: [Role; 1] = [Self::Admin];

    /// Its name, as stored and as `--role` takes it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Admin => "admin",
        }
    }

    /// The role called `name`. The error lists the roles there are.
    pub fn parse(name: &str) -> Result<Role, String> {
        Self::ALL
            .into_iter()
            .find(|role| role.name() == name)
            .ok_or_else(|| {
                let known: Vec<&str> = Self::ALL.iter().map(|role| role.name()).collect();
                format!("`{name}` is not a role: {}", known.join(", "))
            })
    }

    /// The permissions it grants.
    pub fn permissions(self) -> &'static [Permission] {
        match self {
            Self::Admin => &Permission::ALL,
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Whether any of `roles` grants `permission`.
pub fn permits(roles: &[Role], permission: Permission) -> bool {
    roles
        .iter()
        .any(|role| role.permissions().contains(&permission))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn admin_holds_every_permission_and_no_role_holds_none() {
        for permission in Permission::ALL {
            assert!(permits(&[Role::Admin], permission), "{}", permission.name());
            assert!(!permits(&[], permission), "{}", permission.name());
        }
    }

    #[test]
    fn each_name_is_distinct() {
        let names: std::collections::BTreeSet<&str> =
            Permission::ALL.iter().map(|p| p.name()).collect();
        assert_eq!(names.len(), Permission::ALL.len());
        assert!(names.contains("requests.read") && names.contains("accounts.write"));
    }

    #[test]
    fn a_role_is_read_by_its_name() {
        assert_eq!(Role::parse("admin"), Ok(Role::Admin));
        assert_eq!(Role::Admin.to_string(), "admin");
        let refused = Role::parse("root").unwrap_err();
        assert!(
            refused.contains("`root`") && refused.contains("admin"),
            "{refused}"
        );
    }
}
