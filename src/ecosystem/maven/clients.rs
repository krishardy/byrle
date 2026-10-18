//! mvn, as `byrle doctor` checks it, from the `settings.xml` files it reads, merged as
//! mvn 3.10.0 merged them in docs/maven-plan.md, step 7. mvn prints its merged settings only
//! through `help:effective-settings`, a plugin it would download through the mirror being
//! checked.

use std::path::{Path, PathBuf};

use quick_xml::events::Event;

use crate::doctor::{
    CacheBypass, CacheLocation, Client, Finding, Indexes, Machine, RegistrySource, Severity,
};
use crate::env::EnvError;

pub const MVN: Client = Client {
    name: "mvn",
    version_args: &["--version"],
    registry: Some(RegistrySource::Read {
        read: mvn_indexes,
        set_index: super::setup_line,
        drop_extra: || "add `*` to the `<mirrorOf>` of the proxy's mirror".to_owned(),
    }),
    set_registry: "",
    cache: CacheLocation::Read(local_repository),
    bypass: CacheBypass::Complete,
    clear_cache: "use a mirror id no `_remote.repositories` in the local repository records, \
                  or remove the local repository",
    settings: Some(mvn_settings),
    found: None,
};

pub const CLIENTS: &[Client] = &[MVN, super::gradle::GRADLE];

/// Where mvn asks for Central with no mirror.
const CENTRAL_URL: &str = "https://repo.maven.apache.org/maven2";

/// The id mvn gives Central, which no pom declares.
const CENTRAL_ID: &str = "central";

/// An id no settings file names, as XML text holds no NUL: any repository a pom declares.
const UNNAMED: &str = "\0";

/// Where mvn asks for a repository no mirror takes.
const OWN_URL: &str = "each repository a pom declares, at its own URL";

/// A `<mirror>`: requests for the repositories `mirror_of` matches go to `url`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Mirror {
    pub id: String,
    pub mirror_of: String,
    pub url: String,
}

/// A `<server>`: the credentials mvn sends to the repository or mirror of its id.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Server {
    pub id: String,
    pub username: String,
    pub password: String,
    /// Whether `<configuration><httpHeaders>` sets a non-empty `Authorization`.
    pub authorization: bool,
}

impl Server {
    /// Whether mvn sends a token from it, as Basic or in a header.
    fn has_credentials(&self) -> bool {
        self.authorization || !(self.username.is_empty() || self.password.is_empty())
    }
}

/// What doctor reads from a `settings.xml`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Settings {
    pub local_repository: Option<String>,
    pub mirrors: Vec<Mirror>,
    pub servers: Vec<Server>,
}

/// Where values in a `settings.xml` come from: `${user.home}` and `${env.NAME}`.
pub struct Values<'a> {
    pub home: Option<&'a str>,
    pub variable: &'a dyn Fn(&str) -> Option<String>,
}

/// `text` with each `${user.home}` and set `${env.NAME}` replaced. Any other is left as
/// written.
pub fn interpolate(text: &str, values: &Values) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            rest = &rest[start..];
            break;
        };
        let name = &after[..end];
        let value = match name.strip_prefix("env.") {
            Some(variable) => (values.variable)(variable),
            None if name == "user.home" => values.home.map(str::to_owned),
            None => None,
        };
        out.push_str(&value.unwrap_or_else(|| format!("${{{name}}}")));
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Read `text` as a `settings.xml`. Errors when it is not well-formed XML.
pub fn parse(text: &str, values: &Values) -> Result<Settings, String> {
    let mut reader = quick_xml::Reader::from_str(text);
    let mut settings = Settings::default();
    let mut path: Vec<String> = Vec::new();
    let mut read = String::new();
    let mut header = (String::new(), String::new());
    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(start) => {
                path.push(start.local_name().as_ref().to_owned());
                read.clear();
                match path_of(&path).as_slice() {
                    ["settings", "mirrors", "mirror"] => settings.mirrors.push(Mirror::default()),
                    ["settings", "servers", "server"] => settings.servers.push(Server::default()),
                    _ => {}
                }
            }
            Event::Text(t) => read.push_str(&t.xml10_content()),
            Event::CData(c) => read.push_str(&c.into_inner()),
            Event::GeneralRef(r) => {
                let resolved = match r.resolve_char_ref().map_err(|e| e.to_string())? {
                    Some(c) => c,
                    None => super::wire::predefined(&r.into_inner())?,
                };
                read.push(resolved);
            }
            Event::End(_) => {
                let value = interpolate(read.trim(), values);
                place(&mut settings, &path_of(&path), value, &mut header);
                read.clear();
                path.pop();
            }
            Event::Eof => return Ok(settings),
            _ => {}
        }
    }
}

fn path_of(path: &[String]) -> Vec<&str> {
    path.iter().map(String::as_str).collect()
}

/// Keep `value`, the text of the element at `path`. `header` is the `<property>` being
/// read under `<httpHeaders>`.
fn place(settings: &mut Settings, path: &[&str], value: String, header: &mut (String, String)) {
    let mirror = settings.mirrors.last_mut();
    let server = settings.servers.last_mut();
    match (path, mirror, server) {
        (["settings", "localRepository"], _, _) => settings.local_repository = Some(value),
        (["settings", "mirrors", "mirror", field], Some(mirror), _) => match *field {
            "id" => mirror.id = value,
            "mirrorOf" => mirror.mirror_of = value,
            "url" => mirror.url = value,
            _ => {}
        },
        (["settings", "servers", "server", field], _, Some(server)) => match *field {
            "id" => server.id = value,
            "username" => server.username = value,
            "password" => server.password = value,
            _ => {}
        },
        (
            [
                "settings",
                "servers",
                "server",
                "configuration",
                "httpHeaders",
                "property",
                field,
            ],
            _,
            _,
        ) => match *field {
            "name" => header.0 = value,
            "value" => header.1 = value,
            _ => {}
        },
        (
            [
                "settings",
                "servers",
                "server",
                "configuration",
                "httpHeaders",
                "property",
            ],
            _,
            Some(server),
        ) => {
            let (name, value) = std::mem::take(header);
            server.authorization |= name.eq_ignore_ascii_case("authorization") && !value.is_empty();
        }
        _ => {}
    }
}

/// `user`'s settings, then `global`'s mirrors and servers whose ids `user` does not name.
pub fn merged(user: Settings, global: Settings) -> Settings {
    let mut settings = user;
    for mirror in global.mirrors {
        if settings.mirrors.iter().all(|m| m.id != mirror.id) {
            settings.mirrors.push(mirror);
        }
    }
    for server in global.servers {
        if settings.servers.iter().all(|s| s.id != server.id) {
            settings.servers.push(server);
        }
    }
    settings.local_repository = settings.local_repository.or(global.local_repository);
    settings
}

/// The mirror mvn sends repository `id`'s requests to: the first whose `<mirrorOf>` is
/// `id`, else the first whose pattern matches it.
pub fn mirror_for<'a>(mirrors: &'a [Mirror], id: &str) -> Option<&'a Mirror> {
    mirrors
        .iter()
        .find(|mirror| mirror.mirror_of == id)
        .or_else(|| mirrors.iter().find(|mirror| matches(&mirror.mirror_of, id)))
}

/// Whether `pattern` takes repository `id` at an https URL off this host, as Central is
/// and as one a pom declares is assumed to be. A `!id` in the list excludes it.
fn matches(pattern: &str, id: &str) -> bool {
    let mut result = false;
    for part in pattern.split(',').map(str::trim) {
        if let Some(excluded) = part.strip_prefix('!').filter(|e| !e.is_empty()) {
            if excluded == id {
                return false;
            }
        } else if part == id {
            return true;
        } else if part == "*" || part == "external:*" {
            result = true;
        }
    }
    result
}

/// What doctor reads of mvn's configuration on this machine.
pub struct Read {
    /// The files read, each with its settings or why it was not read.
    pub files: Vec<(PathBuf, Result<Settings, String>)>,
    pub settings: Settings,
    /// `-Dmaven.repo.local` from the arguments.
    pub repo_local: Option<PathBuf>,
}

/// Arguments mvn adds to the command line: [`crate::env::MVN_ADDED`], then those in
/// `.mvn/maven.config` of the nearest directory above `dir` holding `.mvn/`.
fn added_arguments(machine: &Machine) -> Result<Vec<String>, EnvError> {
    let mut args: Vec<String> = machine
        .environment
        .maven_args()?
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let config = machine
        .dir
        .ancestors()
        .map(|dir| dir.join(".mvn"))
        .find(|dir| dir.is_dir())
        .and_then(|dir| std::fs::read_to_string(dir.join("maven.config")).ok());
    args.extend(
        config
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned),
    );
    Ok(args)
}

/// The first value `args` gives an option of `names`, as `-s path`, or as `--settings=path`
/// for a long name.
fn option(args: &[String], names: &[&str]) -> Option<String> {
    args.iter().enumerate().find_map(|(at, arg)| {
        if names.contains(&arg.as_str()) {
            return args.get(at + 1).cloned();
        }
        names
            .iter()
            .filter(|name| name.starts_with("--"))
            .find_map(|name| arg.strip_prefix(&format!("{name}=")).map(str::to_owned))
    })
}

/// The directory `mvn --version` prints after `Maven home: `.
fn maven_home(machine: &Machine) -> Option<PathBuf> {
    let printed = machine.ask("mvn", MVN.version_args)?;
    printed
        .lines()
        .find_map(|line| line.strip_prefix("Maven home: "))
        .map(|home| PathBuf::from(home.trim()))
}

/// mvn's settings files and what they set. `None` when mvn is not installed.
fn read(machine: &Machine) -> Result<Option<Read>, EnvError> {
    let Some(maven_home) = maven_home(machine) else {
        return Ok(None);
    };
    let home = machine.environment.home()?;
    let args = added_arguments(machine)?;
    let from_args = |names: &[&str]| option(&args, names).map(|path| machine.dir.join(path));
    let user = from_args(&["-s", "--settings"])
        .or_else(|| home.as_ref().map(|home| home.join(".m2/settings.xml")));
    let global = from_args(&["-gs", "--global-settings"])
        .unwrap_or_else(|| maven_home.join("conf/settings.xml"));
    let shown_home = home.as_ref().map(|home| home.display().to_string());
    let variable = |name: &str| machine.environment.referenced(name);
    let values = Values {
        home: shown_home.as_deref(),
        variable: &variable,
    };
    let mut files = Vec::new();
    let mut found = Vec::new();
    for path in user.into_iter().chain([global]) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            found.push(Settings::default());
            continue;
        };
        let parsed = parse(&text, &values);
        found.push(parsed.clone().unwrap_or_default());
        files.push((path, parsed));
    }
    let global = found.pop().unwrap_or_default();
    let user = found.pop().unwrap_or_default();
    let repo_local = args
        .iter()
        .find_map(|arg| arg.strip_prefix("-Dmaven.repo.local="))
        .map(|path| machine.dir.join(path));
    Ok(Some(Read {
        files,
        settings: merged(user, global),
        repo_local,
    }))
}

/// Central's mirror, and where a repository a pom declares is asked.
fn mvn_indexes(machine: &Machine) -> Result<Option<Indexes>, EnvError> {
    Ok(read(machine)?.map(|read| indexes(&read.settings)))
}

pub fn indexes(settings: &Settings) -> Indexes {
    let url = |id: &str| mirror_for(&settings.mirrors, id).map(|mirror| mirror.url.clone());
    Indexes {
        index: url(CENTRAL_ID).unwrap_or_else(|| CENTRAL_URL.to_owned()),
        extra: vec![url(UNNAMED).unwrap_or_else(|| OWN_URL.to_owned())],
    }
}

/// `-Dmaven.repo.local`, else `<localRepository>`, else `~/.m2/repository`.
fn local_repository(machine: &Machine) -> Result<Option<PathBuf>, EnvError> {
    let home = machine.environment.home()?;
    let Some(read) = read(machine)? else {
        return Ok(None);
    };
    Ok(read
        .repo_local
        .or_else(|| read.settings.local_repository.map(PathBuf::from))
        .or_else(|| home.map(|home| home.join(".m2/repository"))))
}

fn mvn_settings(machine: &Machine, tokens: Option<bool>) -> Vec<Finding> {
    match read(machine) {
        Ok(Some(read)) => settings(&read, tokens),
        _ => Vec::new(),
    }
}

/// Which files were read, and when the proxy requires tokens, whether a `<server>` holds
/// them for Central's mirror.
pub fn settings(read: &Read, tokens: Option<bool>) -> Vec<Finding> {
    let mut findings: Vec<Finding> = read
        .files
        .iter()
        .map(|(path, parsed)| file_finding(path, parsed.as_ref().err()))
        .collect();
    if read.files.is_empty() {
        findings.push(Finding::new(
            Severity::Ok,
            "mvn settings",
            "no settings.xml, so mvn asks Central at its own URL",
        ));
    }
    let mirror = mirror_for(&read.settings.mirrors, CENTRAL_ID);
    if let (Some(true), Some(mirror)) = (tokens, mirror) {
        findings.push(server_finding(&read.settings.servers, &mirror.id));
    }
    findings
}

fn file_finding(path: &Path, error: Option<&String>) -> Finding {
    match error {
        None => Finding::new(
            Severity::Ok,
            "mvn settings",
            format!("read {}", path.display()),
        ),
        Some(error) => Finding::new(
            Severity::Problem,
            "mvn settings",
            format!("{} is not well-formed XML: {error}", path.display()),
        ),
    }
}

/// Whether a `<server>` of the mirror's id holds a token for mvn to send.
fn server_finding(servers: &[Server], id: &str) -> Finding {
    if servers
        .iter()
        .any(|server| server.id == id && server.has_credentials())
    {
        return Finding::new(
            Severity::Ok,
            "mvn server",
            format!("<server> `{id}` holds the credentials mvn sends to the mirror"),
        );
    }
    Finding::new(
        Severity::Problem,
        "mvn server",
        format!(
            "no <server> `{id}` holds a username and password or an Authorization header, so \
             the proxy answers mvn 401"
        ),
    )
    .with_fix(format!(
        "add <server><id>{id}</id><username>ACCOUNT</username><password>TOKEN</password>\
         </server> to ~/.m2/settings.xml"
    ))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::env::{HOME_DIR, MVN_ADDED};

    fn unset(_: &str) -> Option<String> {
        None
    }

    const NONE: Values = Values {
        home: None,
        variable: &unset,
    };

    fn mirror(id: &str, mirror_of: &str, url: &str) -> Mirror {
        Mirror {
            id: id.to_owned(),
            mirror_of: mirror_of.to_owned(),
            url: url.to_owned(),
        }
    }

    fn mirrors(listed: &[(&str, &str)]) -> Vec<Mirror> {
        listed
            .iter()
            .map(|(id, mirror_of)| mirror(id, mirror_of, &format!("https://{id}.example/")))
            .collect()
    }

    fn chosen<'a>(mirrors: &'a [Mirror], id: &str) -> Option<&'a str> {
        mirror_for(mirrors, id).map(|mirror| mirror.id.as_str())
    }

    /// The file mvn 3.10.0 ships blocks http repositories, and Central is https.
    #[test]
    fn the_shipped_global_file_sends_central_to_its_own_url() {
        let text = String::from_utf8(super::super::fixture("global-settings.xml")).unwrap();
        let settings = parse(&text, &NONE).expect("reads");
        assert_eq!(
            settings.mirrors,
            [mirror(
                "maven-default-http-blocker",
                "external:http:*",
                "http://0.0.0.0/"
            )]
        );
        assert_eq!(settings.local_repository, None, "commented out");
        assert!(settings.servers.is_empty());
        assert_eq!(
            indexes(&settings),
            Indexes {
                index: CENTRAL_URL.to_owned(),
                extra: vec![OWN_URL.to_owned()],
            }
        );
    }

    /// Each row was a run of `dependency:resolve` against the stub on 2026-10-17 or 18.
    #[test]
    fn a_mirror_named_by_id_is_chosen_before_any_pattern() {
        let both = mirrors(&[("star", "*"), ("exact", "central")]);
        assert_eq!(chosen(&both, "central"), Some("exact"));
        assert_eq!(chosen(&both, UNNAMED), Some("star"));
        let excluding = mirrors(&[("star", "*,!central")]);
        assert_eq!(chosen(&excluding, "central"), None);
        assert_eq!(chosen(&excluding, UNNAMED), Some("star"));
        let listed = mirrors(&[("star", "*"), ("list", "central,foo")]);
        assert_eq!(
            chosen(&listed, "central"),
            Some("star"),
            "a list is a pattern"
        );
        let user = Settings {
            mirrors: mirrors(&[("ustar", "*")]),
            ..Settings::default()
        };
        let global = Settings {
            mirrors: mirrors(&[("gexact", "central")]),
            ..Settings::default()
        };
        assert_eq!(
            chosen(&merged(user, global).mirrors, "central"),
            Some("gexact")
        );
    }

    #[test]
    fn a_pattern_takes_wildcards_lists_and_exclusions() {
        for (pattern, id, expected) in [
            ("*", "central", true),
            ("central", "central", true),
            ("external:*", "central", true),
            ("external:http:*", "central", false),
            ("foo, central", "central", true),
            ("external:*,!central", "central", false),
            ("!central,*", "central", false),
            ("!,*", "central", true),
            ("foo", "central", false),
            ("!foo", "central", false),
        ] {
            assert_eq!(matches(pattern, id), expected, "{pattern}");
        }
    }

    /// The user file's mirror, server and repository win over the global file's.
    #[test]
    fn the_user_file_wins_over_the_global_file_by_id() {
        let server = |id: &str, username: &str| Server {
            id: id.to_owned(),
            username: username.to_owned(),
            ..Server::default()
        };
        let user = Settings {
            local_repository: None,
            mirrors: vec![mirror("m", "*", "https://user.example/")],
            servers: vec![server("s", "user")],
        };
        let global = Settings {
            local_repository: Some("/global/repo".to_owned()),
            mirrors: vec![
                mirror("m", "*", "https://global.example/"),
                mirror("g", "central", "https://g.example/"),
            ],
            servers: vec![server("s", "global"), server("t", "global")],
        };
        let settings = merged(user, global);
        assert_eq!(
            settings.mirrors,
            [
                mirror("m", "*", "https://user.example/"),
                mirror("g", "central", "https://g.example/"),
            ]
        );
        assert_eq!(
            settings.servers,
            [server("s", "user"), server("t", "global")]
        );
        assert_eq!(settings.local_repository.as_deref(), Some("/global/repo"));
        let mine = Settings {
            local_repository: Some("/mine".to_owned()),
            ..Settings::default()
        };
        assert_eq!(
            merged(mine, Settings::default())
                .local_repository
                .as_deref(),
            Some("/mine")
        );
    }

    #[test]
    fn user_home_and_set_variables_are_replaced() {
        let variable = |name: &str| (name == "TOKEN").then(|| "t0k".to_owned());
        let values = Values {
            home: Some("/home/u"),
            variable: &variable,
        };
        for (text, expected) in [
            ("${user.home}/.m2/repo", "/home/u/.m2/repo"),
            ("a${env.TOKEN}b${env.TOKEN}", "at0kbt0k"),
            ("${env.UNSET}", "${env.UNSET}"),
            ("${maven.home}", "${maven.home}"),
            ("x${env.TOKEN", "x${env.TOKEN"),
            ("plain", "plain"),
        ] {
            assert_eq!(interpolate(text, &values), expected, "{text}");
        }
        assert_eq!(interpolate("${user.home}", &NONE), "${user.home}");
    }

    const USER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <localRepository>${user.home}/repo</localRepository>
  <mirrors>
    <mirror>
      <id>byrle</id>
      <name>byrle</name>
      <mirrorOf>*</mirrorOf>
      <url>https://byrle.example/maven/?a=1&amp;b=&#50;</url>
    </mirror>
  </mirrors>
  <servers>
    <server>
      <id>byrle</id>
      <username>alice</username>
      <password><![CDATA[${env.TOKEN}]]></password>
    </server>
    <server>
      <id>bearer</id>
      <configuration>
        <httpHeaders>
          <property><name>X-Other</name><value>1</value><note>2</note></property>
          <property><name>Authorization</name><value>Bearer t0k</value></property>
        </httpHeaders>
        <timeout>5</timeout>
      </configuration>
    </server>
    <server><id>empty</id><configuration><httpHeaders>
      <property><name>Authorization</name><value></value></property>
    </httpHeaders></configuration></server>
    <server><id>nameless</id><username>alice</username></server>
  </servers>
</settings>
"#;

    #[test]
    fn mirrors_servers_and_the_local_repository_are_read() {
        let variable = |name: &str| (name == "TOKEN").then(|| "t0k".to_owned());
        let values = Values {
            home: Some("/home/u"),
            variable: &variable,
        };
        let settings = parse(USER, &values).expect("reads");
        assert_eq!(settings.local_repository.as_deref(), Some("/home/u/repo"));
        assert_eq!(
            settings.mirrors,
            [mirror("byrle", "*", "https://byrle.example/maven/?a=1&b=2")]
        );
        let credentials: Vec<(&str, bool)> = settings
            .servers
            .iter()
            .map(|server| (server.id.as_str(), server.has_credentials()))
            .collect();
        assert_eq!(
            credentials,
            [
                ("byrle", true),
                ("bearer", true),
                ("empty", false),
                ("nameless", false)
            ]
        );
        assert_eq!(settings.servers[0].password, "t0k");
    }

    #[test]
    fn a_file_that_is_not_xml_is_an_error() {
        for text in [
            "<settings><mirrors></settings>",
            "<settings>&nope;</settings>",
            "<settings>&#xFFFFFFFF;</settings>",
        ] {
            assert!(parse(text, &NONE).is_err(), "{text}");
        }
        assert_eq!(parse("<settings/>", &NONE), Ok(Settings::default()));
    }

    #[test]
    fn an_option_is_read_as_two_arguments_or_with_an_equals_sign() {
        let args =
            |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_owned).collect() };
        let names = ["-s", "--settings"];
        for (text, expected) in [
            ("-B -s a.xml", Some("a.xml")),
            ("--settings=b.xml -s a.xml", Some("b.xml")),
            ("--settings c.xml", Some("c.xml")),
            ("-s", None),
            ("-sa.xml -gs g.xml", None),
        ] {
            assert_eq!(option(&args(text), &names).as_deref(), expected, "{text}");
        }
        assert_eq!(option(&args("-s=a.xml"), &names), None, "only a long name");
    }

    /// mvn's home at `root/maven`, the user's at `root/home`, the project `root/work/project`.
    struct Layout {
        root: PathBuf,
        project: PathBuf,
        version: String,
    }

    impl Layout {
        fn new(label: &str) -> Self {
            let root = crate::util::test_support::tempdir(label);
            let project = root.join("work/project");
            for dir in [
                project.clone(),
                root.join("home/.m2"),
                root.join("maven/conf"),
            ] {
                std::fs::create_dir_all(dir).unwrap();
            }
            let version = format!(
                "Apache Maven 3.10.0 (c43a36b8)\nMaven home: {}\nJava version: 21",
                root.join("maven").display()
            );
            Self {
                root,
                project,
                version,
            }
        }

        fn write(&self, path: &str, text: &str) {
            let path = self.root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }

        fn home(&self) -> String {
            self.root.join("home").display().to_string()
        }

        fn read(&self, environment: &crate::env::Process) -> Option<Read> {
            let run = |program: &str, args: &[&str]| {
                (program == "mvn" && args == ["--version"]).then(|| self.version.clone())
            };
            let machine = Machine {
                environment,
                dir: &self.project,
                run: &run,
            };
            read(&machine).expect("the environment reads")
        }
    }

    fn star(url: &str) -> String {
        format!(
            "<settings><mirrors><mirror><id>byrle</id><mirrorOf>*</mirrorOf><url>{url}</url>\
             </mirror></mirrors></settings>"
        )
    }

    #[test]
    fn the_user_s_and_maven_home_s_files_are_read() {
        let layout = Layout::new("mvn-files");
        layout.write(
            "home/.m2/settings.xml",
            &star("https://user.example/maven/"),
        );
        layout.write(
            "maven/conf/settings.xml",
            "<settings><localRepository>/global/repo</localRepository></settings>",
        );
        let environment = crate::env::testing::with(&[(HOME_DIR, &layout.home())]);
        let read = layout.read(&environment).expect("mvn runs");
        let files: Vec<&Path> = read.files.iter().map(|(path, _)| path.as_path()).collect();
        assert_eq!(
            files,
            [
                layout.root.join("home/.m2/settings.xml"),
                layout.root.join("maven/conf/settings.xml"),
            ]
        );
        assert_eq!(indexes(&read.settings).index, "https://user.example/maven/");
        assert_eq!(
            read.settings.local_repository.as_deref(),
            Some("/global/repo")
        );
        assert_eq!(read.repo_local, None);
    }

    /// `-s` and `-gs` replace the files, from `MVN_ADDED` first, then the nearest
    /// `.mvn/maven.config`, relative to the working directory.
    #[test]
    fn the_arguments_mvn_adds_name_the_files() {
        let layout = Layout::new("mvn-arguments");
        layout.write("home/.m2/settings.xml", &star("https://home.example/"));
        layout.write("work/project/a.xml", &star("https://a.example/"));
        layout.write("work/project/b.xml", &star("https://b.example/"));
        layout.write("work/.mvn/maven.config", "-s b.xml\n-Dmaven.repo.local=r\n");
        let home = layout.home();
        let environment = crate::env::testing::with(&[(HOME_DIR, &home)]);
        let read = layout.read(&environment).unwrap();
        assert_eq!(indexes(&read.settings).index, "https://b.example/");
        assert_eq!(read.repo_local, Some(layout.project.join("r")));
        let environment =
            crate::env::testing::with(&[(HOME_DIR, &home), (MVN_ADDED, "-s a.xml -gs b.xml")]);
        let read = layout.read(&environment).unwrap();
        let files: Vec<&Path> = read.files.iter().map(|(path, _)| path.as_path()).collect();
        assert_eq!(
            files,
            [layout.project.join("a.xml"), layout.project.join("b.xml")]
        );
        assert_eq!(indexes(&read.settings).index, "https://a.example/");
    }

    #[test]
    fn mvn_is_read_only_when_it_runs() {
        let layout = Layout::new("mvn-absent");
        let environment = crate::env::testing::empty();
        let machine = Machine {
            environment: &environment,
            dir: &layout.project,
            run: &|_, _| None,
        };
        assert!(read(&machine).unwrap().is_none());
        assert_eq!(mvn_indexes(&machine), Ok(None));
        assert_eq!(local_repository(&machine), Ok(None));
        assert!(mvn_settings(&machine, Some(true)).is_empty());
        let version = Machine {
            run: &|_, _| Some("Apache Maven 3.10.0".to_owned()),
            ..machine
        };
        assert!(read(&version).unwrap().is_none(), "no Maven home printed");
    }

    /// Nothing set and nothing written: Central at its own URL, nothing read.
    #[test]
    fn with_no_home_and_no_files_mvn_asks_central() {
        let layout = Layout::new("mvn-bare");
        let environment = crate::env::testing::empty();
        let read = layout.read(&environment).unwrap();
        assert!(read.files.is_empty());
        assert_eq!(indexes(&read.settings).index, CENTRAL_URL);
        let findings = settings(&read, Some(true));
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].detail,
            "no settings.xml, so mvn asks Central at its own URL"
        );
    }

    /// The findings doctor prints come from the files read on this machine.
    #[test]
    fn mvn_s_findings_are_of_the_files_it_reads() {
        let layout = Layout::new("mvn-findings");
        layout.write(
            "home/.m2/settings.xml",
            &star("https://byrle.example/maven/"),
        );
        let environment = crate::env::testing::with(&[(HOME_DIR, &layout.home())]);
        let run = |_: &str, _: &[&str]| Some(layout.version.clone());
        let machine = Machine {
            environment: &environment,
            dir: &layout.project,
            run: &run,
        };
        let details: Vec<String> = mvn_settings(&machine, Some(true))
            .into_iter()
            .map(|finding| finding.detail)
            .collect();
        assert_eq!(
            details,
            [
                format!(
                    "read {}",
                    layout.root.join("home/.m2/settings.xml").display()
                ),
                "no <server> `byrle` holds a username and password or an Authorization header, \
                 so the proxy answers mvn 401"
                    .to_owned(),
            ]
        );
    }

    #[test]
    fn an_unreadable_environment_is_an_error() {
        let layout = Layout::new("mvn-unreadable");
        let run = |_: &str, _: &[&str]| Some(layout.version.clone());
        for unreadable in [HOME_DIR, MVN_ADDED] {
            let environment = crate::env::testing::with_unreadable(&[], unreadable);
            let machine = Machine {
                environment: &environment,
                dir: &layout.project,
                run: &run,
            };
            assert!(mvn_indexes(&machine).is_err(), "{}", unreadable.name);
            assert!(local_repository(&machine).is_err(), "{}", unreadable.name);
            assert!(mvn_settings(&machine, Some(true)).is_empty());
        }
    }

    #[test]
    fn the_local_repository_is_the_argument_then_the_settings_then_home() {
        let layout = Layout::new("mvn-repository");
        let home = layout.home();
        let run = |_: &str, _: &[&str]| Some(layout.version.clone());
        let at = |environment: &crate::env::Process| {
            let machine = Machine {
                environment,
                dir: &layout.project,
                run: &run,
            };
            local_repository(&machine).unwrap()
        };
        let environment = crate::env::testing::with(&[(HOME_DIR, &home)]);
        assert_eq!(
            at(&environment),
            Some(layout.root.join("home/.m2/repository"))
        );
        assert_eq!(at(&crate::env::testing::empty()), None);
        layout.write(
            "home/.m2/settings.xml",
            "<settings><localRepository>${user.home}/r</localRepository></settings>",
        );
        assert_eq!(at(&environment), Some(layout.root.join("home/r")));
        let argued =
            crate::env::testing::with(&[(HOME_DIR, &home), (MVN_ADDED, "-Dmaven.repo.local=/a")]);
        assert_eq!(at(&argued), Some(PathBuf::from("/a")));
    }

    /// A token in `${env.NAME}` is read from the environment doctor runs in.
    #[test]
    fn a_variable_the_file_names_is_read_from_the_environment() {
        let layout = Layout::new("mvn-variable");
        layout.write(
            "home/.m2/settings.xml",
            "<settings><servers><server><id>byrle</id><username>a</username>\
             <password>${env.MVN_TOKEN}</password></server></servers></settings>",
        );
        let home = layout.home();
        let environment = crate::env::Env::from_lookup(Box::new(move |name: &str| match name {
            name if name == HOME_DIR.name => Some(home.clone().into()),
            "MVN_TOKEN" => Some("t0k".into()),
            "EMPTY" => Some("".into()),
            _ => None,
        })
            as Box<dyn Fn(&str) -> Option<std::ffi::OsString> + Send + Sync>);
        let read = layout.read(&environment).unwrap();
        assert_eq!(read.settings.servers[0].password, "t0k");
        assert_eq!(environment.referenced("EMPTY"), None);
        let bytes = crate::env::testing::with_unreadable(&[], HOME_DIR);
        assert_eq!(bytes.referenced(HOME_DIR.name), None, "not UTF-8");
    }

    fn read_of(mirrors: Vec<Mirror>, servers: Vec<Server>) -> Read {
        Read {
            files: vec![(PathBuf::from("/s.xml"), Ok(Settings::default()))],
            settings: Settings {
                local_repository: None,
                mirrors,
                servers,
            },
            repo_local: None,
        }
    }

    #[test]
    fn a_server_is_asked_for_only_when_the_proxy_requires_tokens() {
        let central = vec![mirror("byrle", "*", "https://byrle.example/maven/")];
        let holding = vec![Server {
            id: "byrle".to_owned(),
            username: "alice".to_owned(),
            password: "t0k".to_owned(),
            authorization: false,
        }];
        let details = |read: &Read, tokens: Option<bool>| -> Vec<(Severity, String)> {
            settings(read, tokens)
                .into_iter()
                .map(|finding| (finding.severity, finding.detail))
                .collect()
        };
        let read = read_of(central.clone(), Vec::new());
        assert_eq!(details(&read, None).len(), 1);
        assert_eq!(details(&read, Some(false)).len(), 1);
        let missing = settings(&read, Some(true));
        assert_eq!(missing[0].detail, "read /s.xml");
        assert_eq!(missing[1].severity, Severity::Problem);
        assert_eq!(
            missing[1].detail,
            "no <server> `byrle` holds a username and password or an Authorization header, so \
             the proxy answers mvn 401"
        );
        assert_eq!(
            missing[1].fix.as_deref(),
            Some(
                "add <server><id>byrle</id><username>ACCOUNT</username><password>TOKEN\
                 </password></server> to ~/.m2/settings.xml"
            )
        );
        let elsewhere = vec![Server {
            id: "other".to_owned(),
            ..holding[0].clone()
        }];
        let empty = vec![Server {
            password: String::new(),
            ..holding[0].clone()
        }];
        for servers in [elsewhere, empty] {
            let read = read_of(central.clone(), servers);
            assert_eq!(details(&read, Some(true))[1].0, Severity::Problem);
        }
        let held = read_of(central, holding);
        assert_eq!(
            details(&held, Some(true))[1],
            (
                Severity::Ok,
                "<server> `byrle` holds the credentials mvn sends to the mirror".to_owned()
            )
        );
        let unmirrored = read_of(Vec::new(), Vec::new());
        assert_eq!(
            details(&unmirrored, Some(true)).len(),
            1,
            "no mirror to name"
        );
    }

    #[test]
    fn a_file_that_is_not_read_is_a_problem() {
        let read = Read {
            files: vec![(PathBuf::from("/s.xml"), Err("bad".to_owned()))],
            settings: Settings::default(),
            repo_local: None,
        };
        let findings = settings(&read, None);
        assert_eq!(findings[0].severity, Severity::Problem);
        assert_eq!(findings[0].detail, "/s.xml is not well-formed XML: bad");
    }

    /// What doctor prints for mvn pointed at Central with no mirror.
    #[test]
    fn mvn_without_a_mirror_is_reported_off_the_proxy() {
        let proxy = "http://127.0.0.1:8080";
        let found = indexes(&Settings::default());
        let registry = crate::doctor::check_registry(&MVN, Some(&found.index), proxy);
        assert_eq!(registry.severity, Severity::Problem);
        assert_eq!(
            registry.detail,
            "points at https://repo.maven.apache.org/maven2, not the proxy at \
             http://127.0.0.1:8080/maven"
        );
        let extra = crate::doctor::check_extra_indexes(&MVN, &found.extra, "fix", proxy);
        assert_eq!(
            extra.detail,
            "also asks each repository a pom declares, at its own URL, whose files never \
             reach the proxy"
        );
        let pointed = indexes(&Settings {
            mirrors: vec![mirror("byrle", "*", "http://127.0.0.1:8080/maven/")],
            ..Settings::default()
        });
        assert_eq!(
            crate::doctor::check_registry(&MVN, Some(&pointed.index), proxy).severity,
            Severity::Ok
        );
        assert_eq!(
            crate::doctor::check_extra_indexes(&MVN, &pointed.extra, "fix", proxy).severity,
            Severity::Ok
        );
        let RegistrySource::Read { drop_extra, .. } = MVN.registry.as_ref().unwrap() else {
            panic!("read from files");
        };
        assert_eq!(
            drop_extra(),
            "add `*` to the `<mirrorOf>` of the proxy's mirror"
        );
    }
}
