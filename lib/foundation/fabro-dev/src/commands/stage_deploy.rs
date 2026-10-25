//! `cargo dev stage-deploy` moves the `fabro-stage` Coolify app to a new
//! `stage-<12 hex char sha>` image tag and verifies it comes up healthy on the
//! built commit, without ever touching prod. See F002 in `.harness/features.json`.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as FmtWrite;
use std::fs;
#[expect(
    clippy::disallowed_types,
    reason = "writing curl's own config to its own stdin pipe is the one place stage-deploy touches std::io::Write; nothing here is network I/O needing an async facade"
)]
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Args;
use fabro_util::path as fabro_path;
use serde_json::{Value, json};
#[expect(
    clippy::disallowed_types,
    reason = "stage-deploy parses Coolify/stage URLs only to extract and compare hostnames for the prod-refusal guard; the parsed URL is never logged, so DisplaySafeUrl's redaction is not needed here"
)]
use url::Url;

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const MAX_ERROR_BODY_LEN: usize = 2000;
const CURL_MAX_TIME_SECS: u64 = 20;
const STATUS_MARKER: &str = "__FABRO_STAGE_DEPLOY_HTTP_STATUS__:";

/// Prod's known Coolify application UUID, fqdn host, and image prefix. The
/// guard refuses these unconditionally, regardless of what `stage.env` says,
/// so a misconfigured staging settings file can never make prod a target.
const PROD_APP_UUID: &str = "auamnukef5qyu1lveh7vpkf3";
const PROD_FQDN_HOST: &str = "factory.eovidiu.dev";
const FABRO_SH_IMAGE_PREFIX: &str = "ghcr.io/fabro-sh/";

#[derive(Debug, Args)]
pub(crate) struct StageDeployArgs {
    /// Staging image tag to deploy (`stage-<12 lowercase hex commit chars>`).
    #[arg(long)]
    tag:                 String,
    /// Settings file, overriding the default `~/.config/fabro/stage.env`.
    #[arg(long, value_name = "PATH")]
    settings:            Option<PathBuf>,
    /// Application UUID, overriding the settings file's `STAGE_APP_UUID` (to prove the prod refusal).
    #[arg(long, value_name = "UUID", value_parser = validate_app_uuid)]
    app_uuid:            Option<String>,
    /// Print the planned requests without sending them.
    #[arg(long)]
    dry_run:             bool,
    /// Seconds to wait for the app to report `exited` after stopping it.
    #[arg(long, default_value_t = 180)]
    stop_timeout_secs:   u64,
    /// Seconds to wait for the app to report `running:healthy` after starting it.
    #[arg(long, default_value_t = 600)]
    start_timeout_secs:  u64,
    /// Seconds to wait for `/api/v1/system/info` to report the deployed commit.
    #[arg(long, default_value_t = 120)]
    verify_timeout_secs: u64,
}

fn validate_app_uuid(raw: &str) -> std::result::Result<String, String> {
    if !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
        Ok(raw.to_string())
    } else {
        Err("must match [a-z0-9]+".to_string())
    }
}

pub(crate) fn stage_deploy(args: &StageDeployArgs) -> Result<()> {
    let tag = StageTag::parse(&args.tag)?;
    let settings_path = args.settings.clone().unwrap_or_else(default_settings_path);
    let settings = StageSettings::load(&settings_path)?;
    let app_uuid = args
        .app_uuid
        .clone()
        .unwrap_or_else(|| settings.stage_app_uuid.clone());
    let plan = StageDeployPlan {
        tag,
        settings,
        app_uuid,
        timeouts: timeouts_from_args(args),
    };

    // The transport and clock are always built, dry-run or not: the dry-run
    // decision lives in `execute`, generic over `Transport`, so a reordering
    // that sends a request before checking `dry_run` fails a test instead of
    // shipping (see `dry_run_sends_zero_requests_through_the_execute_path`).
    let mut transport = CurlTransport::new(plan.secrets().iter().map(ToString::to_string).collect());
    let mut clock = SystemClock::new();
    execute(&plan, args.dry_run, &mut transport, &mut clock)
}

fn timeouts_from_args(args: &StageDeployArgs) -> Timeouts {
    Timeouts {
        stop:   Duration::from_secs(args.stop_timeout_secs),
        start:  Duration::from_secs(args.start_timeout_secs),
        verify: Duration::from_secs(args.verify_timeout_secs),
    }
}

#[expect(
    clippy::print_stdout,
    reason = "dev stage-deploy command reports dry-run requests directly"
)]
fn execute<T, C>(plan: &StageDeployPlan, dry_run: bool, transport: &mut T, clock: &mut C) -> Result<()>
where
    T: Transport,
    C: Clock,
{
    if dry_run {
        for line in plan.dry_run_lines() {
            println!("{line}");
        }
        return Ok(());
    }
    plan.run(transport, clock)
}

fn default_settings_path() -> PathBuf {
    fabro_path::expand_tilde(Path::new("~/.config/fabro/stage.env"))
}

// --- stage tag ---------------------------------------------------------

/// A validated `stage-<12 hex chars>` image tag.
struct StageTag {
    raw:   String,
    sha12: String,
}

impl StageTag {
    fn parse(raw: &str) -> Result<Self> {
        let sha12 = raw
            .strip_prefix("stage-")
            .filter(|sha| sha.len() == 12 && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .with_context(|| format!("invalid --tag {raw:?}: expected stage-<12 lowercase hex chars>"))?;
        Ok(Self {
            raw:   raw.to_string(),
            sha12: sha12.to_string(),
        })
    }

    fn raw(&self) -> &str {
        &self.raw
    }

    fn short_sha(&self) -> &str {
        &self.sha12[..7]
    }
}

// --- settings ------------------------------------------------------------

const SETTINGS_KEYS: [&str; 8] = [
    "COOLIFY_API_URL",
    "COOLIFY_TOKEN_FILE",
    "STAGE_APP_UUID",
    "STAGE_URL",
    "STAGE_IMAGE_REPO",
    "CF_ACCESS_CLIENT_ID_FILE",
    "CF_ACCESS_CLIENT_SECRET_FILE",
    "FABRO_DEV_TOKEN_FILE",
];

/// Settings read from the stage settings file (default `~/.config/fabro/stage.env`)
/// and the secret files it points at. `Debug` redacts the four secret fields.
struct StageSettings {
    coolify_api_url:         String,
    coolify_token:           String,
    stage_app_uuid:          String,
    stage_url:               String,
    stage_image_repo:        String,
    cf_access_client_id:     String,
    cf_access_client_secret: String,
    fabro_dev_token:         String,
}

impl fmt::Debug for StageSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StageSettings")
            .field("coolify_api_url", &self.coolify_api_url)
            .field("coolify_token", &"[REDACTED]")
            .field("stage_app_uuid", &self.stage_app_uuid)
            .field("stage_url", &self.stage_url)
            .field("stage_image_repo", &self.stage_image_repo)
            .field("cf_access_client_id", &"[REDACTED]")
            .field("cf_access_client_secret", &"[REDACTED]")
            .field("fabro_dev_token", &"[REDACTED]")
            .finish()
    }
}

impl StageSettings {
    #[expect(
        clippy::disallowed_methods,
        reason = "fabro-dev stage-deploy reads its settings file synchronously; it is a CLI tool, not a Tokio runtime"
    )]
    fn load(path: &Path) -> Result<Self> {
        let expanded = fabro_path::expand_tilde(path);
        let contents = fs::read_to_string(&expanded)
            .with_context(|| format!("reading stage settings file {}", expanded.display()))?;
        Self::parse(&contents, &expanded)
    }

    fn parse(contents: &str, path: &Path) -> Result<Self> {
        let map = parse_settings_map(contents, path)?;
        let coolify_api_url = required(&map, "COOLIFY_API_URL", path)?
            .trim_end_matches('/')
            .to_string();
        let coolify_token_file =
            fabro_path::expand_tilde(Path::new(&required(&map, "COOLIFY_TOKEN_FILE", path)?));
        let stage_app_uuid = required(&map, "STAGE_APP_UUID", path)?;
        let stage_url = required(&map, "STAGE_URL", path)?;
        let stage_image_repo = required(&map, "STAGE_IMAGE_REPO", path)?;
        let cf_access_client_id_file =
            fabro_path::expand_tilde(Path::new(&required(&map, "CF_ACCESS_CLIENT_ID_FILE", path)?));
        let cf_access_client_secret_file =
            fabro_path::expand_tilde(Path::new(&required(&map, "CF_ACCESS_CLIENT_SECRET_FILE", path)?));
        let fabro_dev_token_file =
            fabro_path::expand_tilde(Path::new(&required(&map, "FABRO_DEV_TOKEN_FILE", path)?));

        reject_control_chars(&coolify_api_url, "COOLIFY_API_URL", path)?;
        reject_control_chars(&stage_app_uuid, "STAGE_APP_UUID", path)?;
        reject_control_chars(&stage_url, "STAGE_URL", path)?;
        reject_control_chars(&stage_image_repo, "STAGE_IMAGE_REPO", path)?;

        if let Err(reason) = validate_app_uuid(&stage_app_uuid) {
            bail!("{}: STAGE_APP_UUID {reason}", path.display());
        }
        if !stage_url.to_ascii_lowercase().starts_with("https://") {
            bail!("{}: STAGE_URL must use https", path.display());
        }
        if stage_image_repo.to_ascii_lowercase().starts_with(FABRO_SH_IMAGE_PREFIX) {
            bail!("{}: STAGE_IMAGE_REPO must not be under {FABRO_SH_IMAGE_PREFIX}", path.display());
        }

        Ok(Self {
            coolify_api_url,
            coolify_token: read_secret_file(&coolify_token_file)?,
            stage_app_uuid,
            stage_url,
            stage_image_repo,
            cf_access_client_id: read_secret_file(&cf_access_client_id_file)?,
            cf_access_client_secret: read_secret_file(&cf_access_client_secret_file)?,
            fabro_dev_token: read_secret_file(&fabro_dev_token_file)?,
        })
    }
}

fn reject_control_chars(value: &str, field: &str, path: &Path) -> Result<()> {
    if value.chars().any(char::is_control) {
        bail!("{}: {field} contains control characters", path.display());
    }
    Ok(())
}

fn parse_settings_map(contents: &str, path: &Path) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for (index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            // Never echo `line` here: an operator who pastes a bare secret on
            // its own line (no `=`) must not see it reflected in the error.
            bail!("{}: line {} is not KEY=VALUE", path.display(), index + 1);
        };
        let key = key.trim();
        if !SETTINGS_KEYS.contains(&key) {
            bail!("{}: line {} has an unknown key {key:?}", path.display(), index + 1);
        }
        map.insert(key.to_string(), unquote(value.trim()));
    }
    Ok(map)
}

fn required(map: &HashMap<String, String>, key: &str, path: &Path) -> Result<String> {
    map.get(key)
        .cloned()
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{}: missing required setting {key}", path.display()))
}

fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

#[expect(
    clippy::disallowed_methods,
    reason = "fabro-dev stage-deploy reads secret files synchronously; it is a CLI tool, not a Tokio runtime"
)]
fn read_secret_file(path: &Path) -> Result<String> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading secret file {}", path.display()))?;
    let value =
        parse_secret_contents(&contents).with_context(|| format!("secret file {}", path.display()))?;
    if value.is_empty() {
        bail!("secret file {} is empty", path.display());
    }
    Ok(value)
}

/// A secret file is either a raw value on its own, or one `NAME="value"` /
/// `NAME=value` line. Any control character (newline, carriage return, NUL)
/// in the resulting value is refused: it would otherwise reach curl's `-K`
/// config as a raw line break and be read as extra directives.
fn parse_secret_contents(contents: &str) -> Result<String> {
    let trimmed = contents.trim();
    let value = if let Some((name, value)) = trimmed.split_once('=') {
        if is_env_identifier(name.trim()) {
            unquote(value.trim())
        } else {
            trimmed.to_string()
        }
    } else {
        trimmed.to_string()
    };
    if value.chars().any(char::is_control) {
        bail!("must be a single value or one NAME=\"value\" line, with no control characters");
    }
    Ok(value)
}

fn is_env_identifier(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

// --- transport -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Patch,
    Post,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Patch => "PATCH",
            Self::Post => "POST",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone)]
struct PlannedRequest {
    method:  Method,
    url:     String,
    headers: Vec<(String, String)>,
    body:    Option<Value>,
}

impl fmt::Debug for PlannedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_headers: Vec<String> = self
            .headers
            .iter()
            .map(|(name, _)| format!("{name}: [REDACTED]"))
            .collect();
        formatter
            .debug_struct("PlannedRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &redacted_headers)
            .field("body", &self.body)
            .finish()
    }
}

#[derive(Debug, Clone)]
struct TransportResponse {
    status: u16,
    body:   String,
}

trait Transport {
    fn send(&mut self, request: &PlannedRequest) -> Result<TransportResponse>;
}

trait Clock {
    fn elapsed(&self) -> Duration;
    fn sleep(&mut self, duration: Duration);
}

struct SystemClock {
    start: Instant,
}

impl SystemClock {
    fn new() -> Self {
        Self { start: Instant::now() }
    }
}

impl Clock for SystemClock {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "stage-deploy polls Coolify synchronously between retries; it is a CLI tool, not a Tokio runtime"
    )]
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Sends requests over a `curl` subprocess, config fed over `curl`'s stdin
/// (`-K -`) so headers, the URL, and the body never appear on the command
/// line or in the environment. `-q` ignores the operator's `~/.curlrc` (which
/// could otherwise add `-v`, `trace`, a proxy, or `-L`); curl's default user
/// agent is kept (Cloudflare bans others).
struct CurlTransport {
    max_time: Duration,
    secrets:  Vec<String>,
}

impl CurlTransport {
    fn new(secrets: Vec<String>) -> Self {
        Self { max_time: Duration::from_secs(CURL_MAX_TIME_SECS), secrets }
    }

    fn secrets_as_str(&self) -> Vec<&str> {
        self.secrets.iter().map(String::as_str).collect()
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "stage-deploy's real transport intentionally builds a curl invocation; the request never contributes to these static args, so no secret can reach argv"
    )]
    fn curl_command(_request: &PlannedRequest) -> Command {
        let mut command = Command::new("curl");
        command.arg("-q").arg("-sS").arg("-K").arg("-");
        command
    }

    /// The exact `Command` `send()` spawns: argv plus piped stdio. Kept as
    /// one function so a test exercising it (rather than `curl_command`
    /// alone) cannot be fooled by a future `.arg(...)` added only in `send`.
    fn configured_command(request: &PlannedRequest) -> Command {
        let mut command = Self::curl_command(request);
        command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        command
    }

    fn curl_config(request: &PlannedRequest, max_time: Duration) -> String {
        let mut config = String::new();
        let _ = writeln!(config, "silent");
        let _ = writeln!(config, "show-error");
        let _ = writeln!(config, "max-time = \"{}\"", max_time.as_secs());
        let _ = writeln!(config, "request = \"{}\"", request.method.as_str());
        let _ = writeln!(config, "url = \"{}\"", curl_escape(&request.url));
        let _ = writeln!(config, "header = \"Accept: application/json\"");
        for (name, value) in &request.headers {
            let _ = writeln!(config, "header = \"{name}: {}\"", curl_escape(value));
        }
        if let Some(body) = &request.body {
            let _ = writeln!(config, "header = \"Content-Type: application/json\"");
            let _ = writeln!(config, "data-raw = \"{}\"", curl_escape(&body.to_string()));
        }
        let _ = writeln!(config, "write-out = \"\\n{STATUS_MARKER}%{{http_code}}\"");
        config
    }
}

impl Transport for CurlTransport {
    fn send(&mut self, request: &PlannedRequest) -> Result<TransportResponse> {
        let config = Self::curl_config(request, self.max_time);
        let mut child = Self::configured_command(request).spawn().context("spawning curl")?;
        child
            .stdin
            .take()
            .context("curl stdin unavailable")?
            .write_all(config.as_bytes())
            .context("writing curl config to curl's stdin")?;
        let output = child.wait_with_output().context("waiting for curl")?;
        if !output.status.success() {
            bail!(format_curl_failure(
                output.status.code(),
                &String::from_utf8_lossy(&output.stderr),
                &self.secrets_as_str()
            ));
        }
        split_status_marker(&String::from_utf8_lossy(&output.stdout))
    }
}

fn format_curl_failure(code: Option<i32>, stderr: &str, secrets: &[&str]) -> String {
    let code_text = code.map_or_else(|| "signal".to_string(), |code| code.to_string());
    format!("curl exited with status {code_text}: {}", scrub_and_truncate(stderr, secrets))
}

fn split_status_marker(stdout: &str) -> Result<TransportResponse> {
    let (body, marker_line) = stdout
        .rsplit_once('\n')
        .context("curl output is missing the status marker line")?;
    let status_text = marker_line
        .strip_prefix(STATUS_MARKER)
        .with_context(|| format!("curl output is missing {STATUS_MARKER}: {marker_line:?}"))?;
    let status: u16 = status_text
        .trim()
        .parse()
        .with_context(|| format!("curl reported a non-numeric status: {status_text:?}"))?;
    Ok(TransportResponse { status, body: body.to_string() })
}

fn curl_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

// --- deploy plan -------------------------------------------------------

struct Timeouts {
    stop:   Duration,
    start:  Duration,
    verify: Duration,
}

struct StageDeployPlan {
    tag:      StageTag,
    settings: StageSettings,
    app_uuid: String,
    timeouts: Timeouts,
}

impl StageDeployPlan {
    fn app_url(&self) -> String {
        format!("{}/applications/{}", self.settings.coolify_api_url, self.app_uuid)
    }

    fn coolify_headers(&self) -> Vec<(String, String)> {
        vec![(
            "Authorization".to_string(),
            format!("Bearer {}", self.settings.coolify_token),
        )]
    }

    fn system_info_url(&self) -> String {
        format!("{}/api/v1/system/info", self.settings.stage_url.trim_end_matches('/'))
    }

    fn system_info_headers(&self) -> Vec<(String, String)> {
        vec![
            ("CF-Access-Client-Id".to_string(), self.settings.cf_access_client_id.clone()),
            (
                "CF-Access-Client-Secret".to_string(),
                self.settings.cf_access_client_secret.clone(),
            ),
            ("Authorization".to_string(), format!("Bearer {}", self.settings.fabro_dev_token)),
        ]
    }

    fn secrets(&self) -> [&str; 4] {
        [
            self.settings.coolify_token.as_str(),
            self.settings.cf_access_client_id.as_str(),
            self.settings.cf_access_client_secret.as_str(),
            self.settings.fabro_dev_token.as_str(),
        ]
    }

    /// Refuses unconditionally for prod's known UUID, fqdn host, or
    /// `ghcr.io/fabro-sh/` image, whatever `stage.env` says. Otherwise
    /// refuses unless the app's `fqdn` is exactly one host matching
    /// `STAGE_URL` and its `docker_registry_image_name` matches
    /// `STAGE_IMAGE_REPO` exactly.
    fn guard(&self, app: &Value) -> Result<()> {
        if self.app_uuid.eq_ignore_ascii_case(PROD_APP_UUID) {
            bail!("refusing to deploy: {} is prod's known application UUID", self.app_uuid);
        }

        let fqdn = app.get("fqdn").and_then(Value::as_str).unwrap_or_default();
        let image = app
            .get("docker_registry_image_name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let raw_hosts: Vec<&str> = fqdn.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        let app_host = (raw_hosts.len() == 1).then(|| url_host(raw_hosts[0])).and_then(Result::ok);

        if let Some(host) = &app_host {
            if host.eq_ignore_ascii_case(PROD_FQDN_HOST) {
                bail!(
                    "refusing to deploy to application {}: fqdn host {host:?} is prod's known host {PROD_FQDN_HOST}",
                    self.app_uuid
                );
            }
        }
        if image.to_ascii_lowercase().starts_with(FABRO_SH_IMAGE_PREFIX) {
            bail!(
                "refusing to deploy to application {}: image {image:?} is under {FABRO_SH_IMAGE_PREFIX}",
                self.app_uuid
            );
        }

        let stage_host = url_host(&self.settings.stage_url)?;
        let host_ok = app_host.as_deref().is_some_and(|host| host.eq_ignore_ascii_case(&stage_host));
        let image_ok = image == self.settings.stage_image_repo;

        if host_ok && image_ok {
            return Ok(());
        }

        bail!(
            "refusing to deploy to application {}: fqdn={fqdn:?} (want host {stage_host:?}), image={image:?} (want {:?})",
            self.app_uuid,
            self.settings.stage_image_repo
        );
    }

    fn ensure_success(&self, request: &PlannedRequest, response: &TransportResponse) -> Result<()> {
        if (200..300).contains(&response.status) {
            return Ok(());
        }
        bail!(
            "{} {} failed with status {}: {}",
            request.method,
            request.url,
            response.status,
            scrub_and_truncate(&response.body, &self.secrets())
        );
    }

    /// One-shot GET, used for the initial guard check: propagates any
    /// failure immediately rather than retrying (unlike `poll_application`).
    fn get_application<T: Transport>(&self, transport: &mut T) -> Result<Value> {
        let request = PlannedRequest {
            method:  Method::Get,
            url:     self.app_url(),
            headers: self.coolify_headers(),
            body:    None,
        };
        let response = transport.send(&request)?;
        self.ensure_success(&request, &response)?;
        serde_json::from_str(&response.body).with_context(|| format!("parsing JSON from GET {}", request.url))
    }

    /// GET used inside the stop/start poll loops: a transport error or a
    /// non-2xx is "not yet", not a hard failure, so a transient Coolify
    /// hiccup between stop and start does not abort the deploy early.
    fn poll_application<T: Transport>(&self, transport: &mut T) -> std::result::Result<Value, String> {
        let request = PlannedRequest {
            method:  Method::Get,
            url:     self.app_url(),
            headers: self.coolify_headers(),
            body:    None,
        };
        let response = match transport.send(&request) {
            Ok(response) => response,
            Err(error) => return Err(scrub_and_truncate(&error.to_string(), &self.secrets())),
        };
        if !(200..300).contains(&response.status) {
            return Err(format!(
                "GET {} returned {}: {}",
                request.url,
                response.status,
                scrub_and_truncate(&response.body, &self.secrets())
            ));
        }
        serde_json::from_str(&response.body).map_err(|error| format!("parsing JSON from GET {}: {error}", request.url))
    }

    fn patch_tag<T: Transport>(&self, transport: &mut T) -> Result<()> {
        let request = PlannedRequest {
            method:  Method::Patch,
            url:     self.app_url(),
            headers: self.coolify_headers(),
            body:    Some(json!({
                "docker_registry_image_tag": self.tag.raw(),
                "instant_deploy": false,
            })),
        };
        let response = transport.send(&request)?;
        self.ensure_success(&request, &response)
    }

    fn stop<T: Transport>(&self, transport: &mut T) -> Result<()> {
        let request = PlannedRequest {
            method:  Method::Post,
            url:     format!("{}/stop", self.app_url()),
            headers: self.coolify_headers(),
            body:    None,
        };
        let response = transport.send(&request)?;
        self.ensure_success(&request, &response)
    }

    fn start<T: Transport>(&self, transport: &mut T) -> Result<()> {
        let request = PlannedRequest {
            method:  Method::Post,
            url:     format!("{}/start", self.app_url()),
            headers: self.coolify_headers(),
            body:    None,
        };
        let response = transport.send(&request)?;
        self.ensure_success(&request, &response)
    }

    fn wait_for_status<T, C>(
        &self,
        transport: &mut T,
        clock: &mut C,
        step: &str,
        timeout: Duration,
        matches: impl Fn(&str) -> bool,
    ) -> Result<()>
    where
        T: Transport,
        C: Clock,
    {
        let deadline = clock.elapsed() + timeout;
        let mut last: String;
        loop {
            last = match self.poll_application(transport) {
                Ok(app) => {
                    let status = app.get("status").and_then(Value::as_str).unwrap_or_default();
                    if matches(status) {
                        return Ok(());
                    }
                    format!("status {status:?}")
                }
                Err(error) => error,
            };
            if clock.elapsed() >= deadline {
                bail!("{step} timed out after {}s (last observed: {last})", timeout.as_secs());
            }
            clock.sleep(POLL_INTERVAL);
        }
    }

    fn verify_git_sha<T, C>(&self, transport: &mut T, clock: &mut C) -> Result<()>
    where
        T: Transport,
        C: Clock,
    {
        let deadline = clock.elapsed() + self.timeouts.verify;
        let want = self.tag.short_sha();
        let mut last_sha = String::new();
        loop {
            let request = PlannedRequest {
                method:  Method::Get,
                url:     self.system_info_url(),
                headers: self.system_info_headers(),
                body:    None,
            };
            // A transport error or non-2xx here is also "not yet": Cloudflare
            // Access or the app itself can be briefly unready right after start.
            if let Ok(response) = transport.send(&request) {
                if (200..300).contains(&response.status) {
                    if let Ok(value) = serde_json::from_str::<Value>(&response.body) {
                        last_sha = value.get("git_sha").and_then(Value::as_str).unwrap_or_default().to_string();
                        if !last_sha.is_empty() && last_sha == want {
                            return Ok(());
                        }
                    }
                }
            }
            if clock.elapsed() >= deadline {
                bail!(
                    "verify timed out after {}s (want git_sha {want:?}, last observed {last_sha:?})",
                    self.timeouts.verify.as_secs()
                );
            }
            clock.sleep(POLL_INTERVAL);
        }
    }

    /// GET guard -> PATCH tag -> stop -> poll exited -> start -> poll
    /// running:healthy -> poll system/info until git_sha matches. Never
    /// restarts or redeploys in place.
    fn run<T, C>(&self, transport: &mut T, clock: &mut C) -> Result<()>
    where
        T: Transport,
        C: Clock,
    {
        let app = self.get_application(transport)?;
        self.guard(&app)?;
        self.patch_tag(transport)?;
        self.stop(transport)?;
        self.wait_for_status(transport, clock, "stop", self.timeouts.stop, |status| {
            status.starts_with("exited")
        })?;
        self.start(transport)?;
        self.wait_for_status(transport, clock, "start", self.timeouts.start, |status| {
            status == "running:healthy"
        })?;
        self.verify_git_sha(transport, clock)
    }

    fn dry_run_lines(&self) -> Vec<String> {
        let app_url = self.app_url();
        vec![
            request_line(Method::Get, &app_url, &self.coolify_headers()),
            request_line(Method::Patch, &app_url, &self.coolify_headers()),
            format!(
                "  body: {{\"docker_registry_image_tag\":{:?},\"instant_deploy\":false}}",
                self.tag.raw()
            ),
            request_line(Method::Post, &format!("{app_url}/stop"), &self.coolify_headers()),
            format!(
                "poll GET {app_url} until status starts with \"exited\" (timeout {}s, interval {}s)",
                self.timeouts.stop.as_secs(),
                POLL_INTERVAL.as_secs()
            ),
            request_line(Method::Post, &format!("{app_url}/start"), &self.coolify_headers()),
            format!(
                "poll GET {app_url} until status == \"running:healthy\" (timeout {}s, interval {}s)",
                self.timeouts.start.as_secs(),
                POLL_INTERVAL.as_secs()
            ),
            request_line(Method::Get, &self.system_info_url(), &self.system_info_headers()),
            format!(
                "poll GET {} until git_sha == {:?} (timeout {}s, interval {}s)",
                self.system_info_url(),
                self.tag.short_sha(),
                self.timeouts.verify.as_secs(),
                POLL_INTERVAL.as_secs()
            ),
        ]
    }
}

fn request_line(method: Method, url: &str, headers: &[(String, String)]) -> String {
    let header_list = headers
        .iter()
        .map(|(name, _)| format!("{name}: [REDACTED]"))
        .collect::<Vec<_>>()
        .join(", ");
    if header_list.is_empty() {
        format!("{method} {url}")
    } else {
        format!("{method} {url}  headers: {header_list}")
    }
}

#[expect(
    clippy::disallowed_types,
    reason = "stage-deploy parses Coolify/stage URLs only to extract and compare hostnames for the prod-refusal guard; the parsed URL is never logged, so DisplaySafeUrl's redaction is not needed here"
)]
fn url_host(raw: &str) -> Result<String> {
    let parsed = Url::parse(raw).with_context(|| format!("parsing URL {raw:?}"))?;
    parsed
        .host_str()
        .map(str::to_string)
        .with_context(|| format!("URL {raw:?} has no host"))
}

fn scrub_and_truncate(body: &str, secrets: &[&str]) -> String {
    let mut scrubbed = body.to_string();
    for secret in secrets {
        if !secret.is_empty() {
            scrubbed = scrubbed.replace(*secret, "[REDACTED]");
        }
    }
    if scrubbed.len() > MAX_ERROR_BODY_LEN {
        let mut end = MAX_ERROR_BODY_LEN;
        while end > 0 && !scrubbed.is_char_boundary(end) {
            end -= 1;
        }
        scrubbed.truncate(end);
        scrubbed.push_str("...[truncated]");
    }
    scrubbed
}

#[expect(
    clippy::disallowed_methods,
    reason = "stage-deploy tests build fixture secret files, a stub docker binary, and read the checked-in workflow file synchronously"
)]
#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::time::Duration;

    use serde_json::json;

    use super::{
        Clock, CurlTransport, Method, PlannedRequest, StageDeployArgs, StageDeployPlan, StageSettings, StageTag,
        Timeouts, Transport, TransportResponse, fabro_path, format_curl_failure, parse_secret_contents,
        read_secret_file, timeouts_from_args, validate_app_uuid,
    };

    #[derive(Default)]
    struct ScriptedTransport {
        requests:  Vec<PlannedRequest>,
        responses: std::collections::HashMap<String, VecDeque<TransportResponse>>,
    }

    impl ScriptedTransport {
        fn queue(&mut self, method: Method, url: &str, status: u16, body: &str) -> &mut Self {
            self.responses
                .entry(format!("{method} {url}"))
                .or_default()
                .push_back(TransportResponse { status, body: body.to_string() });
            self
        }
    }

    impl Transport for ScriptedTransport {
        fn send(&mut self, request: &PlannedRequest) -> anyhow::Result<TransportResponse> {
            self.requests.push(request.clone());
            let key = format!("{} {}", request.method, request.url);
            let queue = self
                .responses
                .get_mut(&key)
                .ok_or_else(|| anyhow::anyhow!("no scripted response for {key}"))?;
            if queue.len() > 1 {
                Ok(queue.pop_front().expect("queue length was checked above"))
            } else {
                Ok(queue.front().cloned().expect("a queued key is never left empty"))
            }
        }
    }

    struct FakeClock {
        elapsed: Duration,
    }

    impl FakeClock {
        fn new() -> Self {
            Self { elapsed: Duration::ZERO }
        }
    }

    impl Clock for FakeClock {
        fn elapsed(&self) -> Duration {
            self.elapsed
        }

        fn sleep(&mut self, duration: Duration) {
            self.elapsed += duration;
        }
    }

    const PROD_FQDN: &str = "http://factory.eovidiu.dev";
    const PROD_IMAGE: &str = "ghcr.io/fabro-sh/fabro";
    const PROD_UUID: &str = "auamnukef5qyu1lveh7vpkf3";

    fn test_settings() -> StageSettings {
        StageSettings {
            coolify_api_url:         "http://coolify.test/api/v1".to_string(),
            coolify_token:           "sentinel-coolify-token".to_string(),
            stage_app_uuid:          "stage-uuid-1234".to_string(),
            stage_url:               "https://factory-stage.eovidiu.dev".to_string(),
            stage_image_repo:        "ghcr.io/eovidiu/fabro".to_string(),
            cf_access_client_id:     "sentinel-cf-client-id".to_string(),
            cf_access_client_secret: "sentinel-cf-client-secret".to_string(),
            fabro_dev_token:         "sentinel-fabro-dev-token".to_string(),
        }
    }

    fn test_plan() -> StageDeployPlan {
        StageDeployPlan {
            tag:      StageTag::parse("stage-0123456789ab").unwrap(),
            settings: test_settings(),
            app_uuid: "stage-uuid-1234".to_string(),
            timeouts: Timeouts {
                stop:   Duration::from_secs(30),
                start:  Duration::from_secs(60),
                verify: Duration::from_secs(90),
            },
        }
    }

    #[test]
    fn stage_deploy_cli_timeouts_wire_into_the_plan_unchanged() {
        let args = StageDeployArgs {
            tag:                 "stage-0123456789ab".to_string(),
            settings:            None,
            app_uuid:            None,
            dry_run:             true,
            stop_timeout_secs:   11,
            start_timeout_secs:  22,
            verify_timeout_secs: 33,
        };
        let timeouts = timeouts_from_args(&args);
        assert_eq!(timeouts.stop, Duration::from_secs(11));
        assert_eq!(timeouts.start, Duration::from_secs(22));
        assert_eq!(timeouts.verify, Duration::from_secs(33));
    }

    fn stage_app(status: &str) -> String {
        json!({
            "fqdn": "https://factory-stage.eovidiu.dev",
            "docker_registry_image_name": "ghcr.io/eovidiu/fabro",
            "status": status,
        })
        .to_string()
    }

    fn settings_file_text(dir: &std::path::Path) -> String {
        format!(
            "# a comment\n\nCOOLIFY_API_URL=\"http://coolify.test/api/v1/\"\nCOOLIFY_TOKEN_FILE={}\nSTAGE_APP_UUID=stageuuid1\nSTAGE_URL='https://factory-stage.eovidiu.dev'\nSTAGE_IMAGE_REPO=ghcr.io/eovidiu/fabro\nCF_ACCESS_CLIENT_ID_FILE={}\nCF_ACCESS_CLIENT_SECRET_FILE={}\nFABRO_DEV_TOKEN_FILE={}\n",
            dir.join("coolify-token").display(),
            dir.join("cf-id").display(),
            dir.join("cf-secret").display(),
            dir.join("dev-token").display(),
        )
    }

    fn write_fixture_secrets(dir: &std::path::Path) {
        fs::write(dir.join("coolify-token"), "tok-coolify\n").unwrap();
        fs::write(dir.join("cf-id"), "tok-cf-id\n").unwrap();
        fs::write(dir.join("cf-secret"), "tok-cf-secret\n").unwrap();
        fs::write(dir.join("dev-token"), "tok-dev\n").unwrap();
    }

    // --- StageTag ----------------------------------------------------------

    #[test]
    fn stage_tag_parses_a_valid_tag() {
        let tag = StageTag::parse("stage-0123456789ab").unwrap();
        assert_eq!(tag.raw(), "stage-0123456789ab");
        assert_eq!(tag.short_sha(), "0123456");
    }

    #[test]
    fn stage_tag_rejects_wrong_shapes() {
        for bad in [
            "stage-0123456789a",
            "stage-0123456789abc",
            "stage-0123456789AB",
            "0123456789ab",
            "stage-012345678zzz",
            "",
        ] {
            assert!(StageTag::parse(bad).is_err(), "expected {bad:?} to be rejected");
        }
    }

    // --- --app-uuid validation -------------------------------------------

    #[test]
    fn app_uuid_arg_accepts_lowercase_hex_and_digits() {
        assert_eq!(validate_app_uuid("auamnukef5qyu1lveh7vpkf3").unwrap(), "auamnukef5qyu1lveh7vpkf3");
    }

    #[test]
    fn app_uuid_arg_rejects_invalid_shapes() {
        for bad in ["", "ABC123", "abc-123", "abc 123", "abc\n123"] {
            assert!(validate_app_uuid(bad).is_err(), "expected {bad:?} to be rejected");
        }
    }

    // --- settings parsing ----------------------------------------------

    #[test]
    fn settings_parse_reads_comments_and_quotes() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture_secrets(dir.path());
        let contents = settings_file_text(dir.path());

        let settings = StageSettings::parse(&contents, &dir.path().join("stage.env")).unwrap();
        assert_eq!(settings.coolify_api_url, "http://coolify.test/api/v1");
        assert_eq!(settings.coolify_token, "tok-coolify");
        assert_eq!(settings.stage_url, "https://factory-stage.eovidiu.dev");
        assert_eq!(settings.stage_image_repo, "ghcr.io/eovidiu/fabro");
        assert_eq!(settings.cf_access_client_id, "tok-cf-id");
        assert_eq!(settings.cf_access_client_secret, "tok-cf-secret");
        assert_eq!(settings.fabro_dev_token, "tok-dev");
    }

    #[test]
    fn settings_parse_expands_tilde_prefixed_secret_file_paths() {
        // Mutating $HOME (even to prove expansion) would need `unsafe`, which
        // this workspace denies. Instead, point one secret file at a
        // deliberately missing `~`-prefixed path and check the resulting
        // error names the real, expanded home directory rather than a
        // literal `~` — proof `expand_tilde` ran, without touching the real
        // home directory or any global state.
        let dir = tempfile::tempdir().unwrap();
        write_fixture_secrets(dir.path());
        let missing_marker = "__stage_deploy_test_missing_token__";
        let contents = settings_file_text(dir.path()).replace(
            &format!("FABRO_DEV_TOKEN_FILE={}", dir.path().join("dev-token").display()),
            &format!("FABRO_DEV_TOKEN_FILE=~/.config/fabro/{missing_marker}"),
        );

        let error = StageSettings::parse(&contents, &dir.path().join("stage.env"))
            .unwrap_err()
            .to_string();

        let expanded_home = fabro_path::expand_tilde(std::path::Path::new("~")).display().to_string();
        assert!(error.contains(&expanded_home), "error should show the expanded home directory: {error}");
        assert!(!error.contains('~'), "the ~ should have been expanded before the file read: {error}");
        assert!(error.contains(missing_marker));
    }

    #[test]
    fn settings_parse_names_the_missing_key() {
        let error = StageSettings::parse("COOLIFY_API_URL=http://x\n", std::path::Path::new("/tmp/stage.env"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("COOLIFY_TOKEN_FILE"), "error should name the missing key: {error}");
        assert!(error.contains("/tmp/stage.env"), "error should name the file: {error}");
    }

    #[test]
    fn settings_parse_rejects_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture_secrets(dir.path());
        let contents = format!("{}SOME_UNKNOWN_KEY=x\n", settings_file_text(dir.path()));

        let error = StageSettings::parse(&contents, &dir.path().join("stage.env")).unwrap_err().to_string();
        assert!(error.contains("SOME_UNKNOWN_KEY"), "error should name the unknown key: {error}");
    }

    #[test]
    fn settings_parse_rejects_an_empty_value() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture_secrets(dir.path());
        let contents = settings_file_text(dir.path()).replace("STAGE_APP_UUID=stageuuid1", "STAGE_APP_UUID=");

        let error = StageSettings::parse(&contents, &dir.path().join("stage.env")).unwrap_err().to_string();
        assert!(error.contains("STAGE_APP_UUID"), "error should name the empty key: {error}");
    }

    #[test]
    fn settings_parse_requires_https_stage_url() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture_secrets(dir.path());
        let contents = settings_file_text(dir.path())
            .replace("STAGE_URL='https://factory-stage.eovidiu.dev'", "STAGE_URL=http://factory-stage.eovidiu.dev");

        let error = StageSettings::parse(&contents, &dir.path().join("stage.env")).unwrap_err().to_string();
        assert!(error.contains("https"), "error should explain https is required: {error}");
    }

    #[test]
    fn settings_parse_rejects_an_invalid_stage_app_uuid() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture_secrets(dir.path());
        let contents =
            settings_file_text(dir.path()).replace("STAGE_APP_UUID=stageuuid1", "STAGE_APP_UUID=./bad-uuid");

        let error = StageSettings::parse(&contents, &dir.path().join("stage.env")).unwrap_err().to_string();
        assert!(error.contains("STAGE_APP_UUID"), "error should name the invalid key: {error}");
    }

    #[test]
    fn settings_parse_refuses_a_fabro_sh_stage_repository() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture_secrets(dir.path());
        let contents = settings_file_text(dir.path())
            .replace("STAGE_IMAGE_REPO=ghcr.io/eovidiu/fabro", "STAGE_IMAGE_REPO=ghcr.io/fabro-sh/fabro");

        let error = StageSettings::parse(&contents, &dir.path().join("stage.env")).unwrap_err().to_string();
        assert!(error.contains("fabro-sh"), "error should name the forbidden prefix: {error}");
    }

    #[test]
    fn settings_parse_refuses_a_fabro_sh_stage_repository_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture_secrets(dir.path());
        let contents = settings_file_text(dir.path())
            .replace("STAGE_IMAGE_REPO=ghcr.io/eovidiu/fabro", "STAGE_IMAGE_REPO=GHCR.IO/Fabro-SH/fabro");

        let error = StageSettings::parse(&contents, &dir.path().join("stage.env")).unwrap_err().to_string();
        assert!(error.contains("fabro-sh"), "error should name the forbidden prefix: {error}");
    }

    #[test]
    fn settings_parse_malformed_line_error_never_contains_the_line_content() {
        let sentinel = "sentinel-leaked-secret-on-its-own-line";
        let error = StageSettings::parse(sentinel, std::path::Path::new("/tmp/stage.env"))
            .unwrap_err()
            .to_string();
        assert!(!error.contains(sentinel), "error should never echo the offending line: {error}");
    }

    #[test]
    fn secret_file_accepts_a_raw_value_or_one_name_equals_value_line() {
        assert_eq!(parse_secret_contents("plain-secret-value\n").unwrap(), "plain-secret-value");
        assert_eq!(parse_secret_contents("FABRO_DEV_TOKEN=\"quoted-value\"\n").unwrap(), "quoted-value");
        assert_eq!(parse_secret_contents("FABRO_DEV_TOKEN=bare-value\n").unwrap(), "bare-value");
    }

    #[test]
    fn secret_file_error_names_the_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing-secret");
        let error = read_secret_file(&missing).unwrap_err().to_string();
        assert!(error.contains(missing.to_str().unwrap()));
    }

    #[test]
    fn secret_file_rejects_an_empty_or_whitespace_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty-secret");
        fs::write(&path, "   \n\n").unwrap();
        let error = read_secret_file(&path).unwrap_err().to_string();
        assert!(error.contains(path.to_str().unwrap()));
    }

    #[test]
    fn secret_file_rejects_multiple_lines() {
        let sentinel = "sentinel-multiline-secret";
        let error = parse_secret_contents(&format!("{sentinel}\nsecond line\n")).unwrap_err().to_string();
        assert!(!error.contains(sentinel), "error should not echo the secret: {error}");
    }

    #[test]
    fn secret_file_rejects_control_characters_within_a_single_line() {
        let sentinel = "sentinel-cr-secret";
        let error = parse_secret_contents(&format!("bad\r{sentinel}")).unwrap_err().to_string();
        assert!(!error.contains(sentinel), "error should not echo the secret: {error}");
    }

    // --- guard -------------------------------------------------------------

    #[test]
    fn guard_accepts_the_staging_app() {
        let plan = test_plan();
        let app = json!({
            "fqdn": "https://factory-stage.eovidiu.dev",
            "docker_registry_image_name": "ghcr.io/eovidiu/fabro",
        });
        assert!(plan.guard(&app).is_ok());
    }

    #[test]
    fn guard_accepts_an_http_stored_fqdn_against_an_https_stage_url() {
        let plan = test_plan();
        let app = json!({
            "fqdn": "http://factory-stage.eovidiu.dev",
            "docker_registry_image_name": "ghcr.io/eovidiu/fabro",
        });
        assert!(plan.guard(&app).is_ok(), "scheme must be ignored when comparing hosts");
    }

    #[test]
    fn guard_refuses_prods_real_app_by_uuid_fqdn_and_image() {
        let mut plan = test_plan();
        plan.app_uuid = PROD_UUID.to_string();
        let app = json!({ "fqdn": PROD_FQDN, "docker_registry_image_name": PROD_IMAGE });
        let error = plan.guard(&app).unwrap_err().to_string();
        assert!(error.contains(PROD_UUID));
    }

    #[test]
    fn guard_refuses_prod_fqdn_host_alone_even_with_the_correct_image() {
        let plan = test_plan();
        let app = json!({ "fqdn": PROD_FQDN, "docker_registry_image_name": "ghcr.io/eovidiu/fabro" });
        let error = plan.guard(&app).unwrap_err().to_string();
        assert!(error.contains("factory.eovidiu.dev"), "error should name prod's host: {error}");
    }

    #[test]
    fn guard_refuses_more_than_one_fqdn_host() {
        let plan = test_plan();
        let app = json!({
            "fqdn": "https://factory-stage.eovidiu.dev,https://other.example.com",
            "docker_registry_image_name": "ghcr.io/eovidiu/fabro",
        });
        assert!(plan.guard(&app).is_err());
    }

    #[test]
    fn guard_refuses_an_image_mismatch() {
        let plan = test_plan();
        let app = json!({
            "fqdn": "https://factory-stage.eovidiu.dev",
            "docker_registry_image_name": "ghcr.io/other-org/fabro",
        });
        assert!(plan.guard(&app).is_err());
    }

    #[test]
    fn guard_refuses_a_non_stage_single_host_with_the_correct_image() {
        // Neither prod's hard-coded host nor the configured stage host: must
        // still refuse on the ordinary host_ok comparison, not a hard check.
        let plan = test_plan();
        let app = json!({
            "fqdn": "https://other.eovidiu.dev",
            "docker_registry_image_name": "ghcr.io/eovidiu/fabro",
        });
        let error = plan.guard(&app).unwrap_err().to_string();
        assert!(error.contains("factory-stage.eovidiu.dev"), "error should name the configured stage host: {error}");
    }

    #[test]
    fn guard_refuses_a_non_stage_single_host_with_zero_writes() {
        let plan = test_plan();
        let mut transport = ScriptedTransport::default();
        transport.queue(
            Method::Get,
            &plan.app_url(),
            200,
            &json!({
                "fqdn": "https://other.eovidiu.dev",
                "docker_registry_image_name": "ghcr.io/eovidiu/fabro",
            })
            .to_string(),
        );
        let mut clock = FakeClock::new();

        let result = plan.run(&mut transport, &mut clock);

        assert!(result.is_err());
        assert_eq!(transport.requests.len(), 1, "only the guard GET should have been sent");
    }

    #[test]
    fn guard_refuses_an_app_image_under_the_fabro_sh_prefix_even_if_settings_match() {
        let plan = test_plan();
        let app = json!({ "fqdn": "https://factory-stage.eovidiu.dev", "docker_registry_image_name": PROD_IMAGE });
        let error = plan.guard(&app).unwrap_err().to_string();
        assert!(error.contains("fabro-sh"), "error should name the forbidden prefix: {error}");
    }

    #[test]
    fn guard_refuses_prod_even_with_prod_shaped_settings() {
        // The settings file itself is misconfigured to describe prod; the
        // hard-coded prod checks must still refuse, independent of settings.
        let mut plan = test_plan();
        plan.settings.stage_url = PROD_FQDN.to_string();
        plan.settings.stage_image_repo = PROD_IMAGE.to_string();
        plan.app_uuid = PROD_UUID.to_string();
        let app = json!({ "fqdn": PROD_FQDN, "docker_registry_image_name": PROD_IMAGE });
        assert!(plan.guard(&app).is_err());
    }

    #[test]
    fn guard_refusal_makes_zero_writes() {
        let mut plan = test_plan();
        plan.app_uuid = PROD_UUID.to_string();
        let mut transport = ScriptedTransport::default();
        transport.queue(
            Method::Get,
            &plan.app_url(),
            200,
            &json!({ "fqdn": PROD_FQDN, "docker_registry_image_name": PROD_IMAGE }).to_string(),
        );
        let mut clock = FakeClock::new();

        let result = plan.run(&mut transport, &mut clock);

        assert!(result.is_err());
        assert_eq!(transport.requests.len(), 1, "only the guard GET should have been sent");
        assert_eq!(transport.requests[0].method, Method::Get);
    }

    // --- sequence ------------------------------------------------------

    #[test]
    fn run_sends_requests_in_order_with_the_right_bodies_and_headers_and_never_restarts_or_redeploys() {
        let plan = test_plan();
        let app_url = plan.app_url();
        let mut transport = ScriptedTransport::default();
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:healthy"));
        transport.queue(Method::Patch, &app_url, 200, "{}");
        transport.queue(Method::Post, &format!("{app_url}/stop"), 200, "{}");
        transport.queue(Method::Get, &app_url, 200, &stage_app("exited:unhealthy"));
        transport.queue(Method::Post, &format!("{app_url}/start"), 200, "{}");
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:healthy"));
        transport.queue(
            Method::Get,
            &plan.system_info_url(),
            200,
            &json!({ "git_sha": plan.tag.short_sha() }).to_string(),
        );
        let mut clock = FakeClock::new();

        plan.run(&mut transport, &mut clock).unwrap();

        let methods_and_urls: Vec<(Method, String)> =
            transport.requests.iter().map(|r| (r.method, r.url.clone())).collect();
        assert_eq!(
            methods_and_urls,
            vec![
                (Method::Get, app_url.clone()),
                (Method::Patch, app_url.clone()),
                (Method::Post, format!("{app_url}/stop")),
                (Method::Get, app_url.clone()),
                (Method::Post, format!("{app_url}/start")),
                (Method::Get, app_url.clone()),
                (Method::Get, plan.system_info_url()),
            ]
        );
        for request in &transport.requests {
            assert!(!request.url.contains("/restart"), "must never call /restart: {}", request.url);
            assert!(!request.url.contains("/deploy"), "must never call /deploy: {}", request.url);
        }

        assert_eq!(
            transport.requests[1].body,
            Some(json!({ "docker_registry_image_tag": "stage-0123456789ab", "instant_deploy": false }))
        );

        let coolify_auth = ("Authorization".to_string(), "Bearer sentinel-coolify-token".to_string());
        for index in 0..6 {
            assert!(
                transport.requests[index].headers.contains(&coolify_auth),
                "request {index} should carry the Coolify bearer token"
            );
        }
        let system_info_headers = &transport.requests[6].headers;
        assert!(system_info_headers.contains(&("CF-Access-Client-Id".to_string(), "sentinel-cf-client-id".to_string())));
        assert!(system_info_headers.contains(&(
            "CF-Access-Client-Secret".to_string(),
            "sentinel-cf-client-secret".to_string()
        )));
        assert!(system_info_headers.contains(&(
            "Authorization".to_string(),
            "Bearer sentinel-fabro-dev-token".to_string()
        )));
    }

    #[test]
    fn patch_failure_stops_before_stop_or_start() {
        let plan = test_plan();
        let app_url = plan.app_url();
        let mut transport = ScriptedTransport::default();
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:healthy"));
        transport.queue(Method::Patch, &app_url, 500, "internal error");
        let mut clock = FakeClock::new();

        assert!(plan.run(&mut transport, &mut clock).is_err());
        assert_eq!(transport.requests.len(), 2, "no stop or start should follow a failed PATCH");
    }

    #[test]
    fn stop_failure_stops_before_start() {
        let plan = test_plan();
        let app_url = plan.app_url();
        let mut transport = ScriptedTransport::default();
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:healthy"));
        transport.queue(Method::Patch, &app_url, 200, "{}");
        transport.queue(Method::Post, &format!("{app_url}/stop"), 404, "not found");
        let mut clock = FakeClock::new();

        assert!(plan.run(&mut transport, &mut clock).is_err());
        assert_eq!(transport.requests.len(), 3, "no start should follow a failed stop");
    }

    // --- timeouts --------------------------------------------------------

    #[test]
    fn stop_wait_times_out_when_the_app_never_reports_exited() {
        let plan = test_plan();
        let app_url = plan.app_url();
        let mut transport = ScriptedTransport::default();
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:healthy"));
        transport.queue(Method::Patch, &app_url, 200, "{}");
        transport.queue(Method::Post, &format!("{app_url}/stop"), 200, "{}");
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:unhealthy"));
        let mut clock = FakeClock::new();

        let error = plan.run(&mut transport, &mut clock).unwrap_err().to_string();

        assert!(error.contains("stop"), "error should name the step: {error}");
        assert!(error.contains("30s"), "error should name the stop timeout, not another field's: {error}");
        assert!(error.contains("running:unhealthy"), "error should carry the last observed status: {error}");
    }

    #[test]
    fn stop_wait_tolerates_a_transient_poll_failure_before_succeeding() {
        let plan = test_plan();
        let app_url = plan.app_url();
        let mut transport = ScriptedTransport::default();
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:healthy"));
        transport.queue(Method::Patch, &app_url, 200, "{}");
        transport.queue(Method::Post, &format!("{app_url}/stop"), 200, "{}");
        transport.queue(Method::Get, &app_url, 503, "upstream hiccup");
        transport.queue(Method::Get, &app_url, 200, &stage_app("exited:unhealthy"));
        transport.queue(Method::Post, &format!("{app_url}/start"), 200, "{}");
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:healthy"));
        transport.queue(
            Method::Get,
            &plan.system_info_url(),
            200,
            &json!({ "git_sha": plan.tag.short_sha() }).to_string(),
        );
        let mut clock = FakeClock::new();

        plan.run(&mut transport, &mut clock).unwrap();
    }

    #[test]
    fn start_wait_times_out_when_the_app_never_reports_running_healthy() {
        let plan = test_plan();
        let app_url = plan.app_url();
        let mut transport = ScriptedTransport::default();
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:healthy"));
        transport.queue(Method::Patch, &app_url, 200, "{}");
        transport.queue(Method::Post, &format!("{app_url}/stop"), 200, "{}");
        transport.queue(Method::Get, &app_url, 200, &stage_app("exited:unhealthy"));
        transport.queue(Method::Post, &format!("{app_url}/start"), 200, "{}");
        transport.queue(Method::Get, &app_url, 200, &stage_app("starting"));
        let mut clock = FakeClock::new();

        let error = plan.run(&mut transport, &mut clock).unwrap_err().to_string();

        assert!(error.contains("start"), "error should name the step: {error}");
        assert!(error.contains("60s"), "error should name the start timeout, not another field's: {error}");
        assert!(error.contains("starting"), "error should carry the last observed status: {error}");
    }

    #[test]
    fn start_wait_times_out_when_status_stays_running_unhealthy() {
        // Guards against loosening the start predicate to `starts_with("running")`,
        // which would wrongly accept `running:unhealthy`.
        let plan = test_plan();
        let app_url = plan.app_url();
        let mut transport = ScriptedTransport::default();
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:healthy"));
        transport.queue(Method::Patch, &app_url, 200, "{}");
        transport.queue(Method::Post, &format!("{app_url}/stop"), 200, "{}");
        transport.queue(Method::Get, &app_url, 200, &stage_app("exited:unhealthy"));
        transport.queue(Method::Post, &format!("{app_url}/start"), 200, "{}");
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:unhealthy"));
        let mut clock = FakeClock::new();

        let error = plan.run(&mut transport, &mut clock).unwrap_err().to_string();

        assert!(error.contains("start"), "error should name the step: {error}");
        assert!(error.contains("running:unhealthy"), "error should carry the last observed status: {error}");
    }

    #[test]
    fn verify_times_out_when_git_sha_never_matches() {
        let plan = test_plan();
        verify_timeout_case(&plan, &json!({ "git_sha": "mismatch" }).to_string(), "mismatch");
    }

    #[test]
    fn verify_times_out_when_git_sha_is_empty() {
        let plan = test_plan();
        verify_timeout_case(&plan, &json!({ "git_sha": "" }).to_string(), "verify");
    }

    #[test]
    fn verify_times_out_when_git_sha_is_absent() {
        let plan = test_plan();
        verify_timeout_case(&plan, &json!({}).to_string(), "verify");
    }

    fn verify_timeout_case(plan: &StageDeployPlan, system_info_body: &str, expect_contains: &str) {
        let app_url = plan.app_url();
        let mut transport = ScriptedTransport::default();
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:healthy"));
        transport.queue(Method::Patch, &app_url, 200, "{}");
        transport.queue(Method::Post, &format!("{app_url}/stop"), 200, "{}");
        transport.queue(Method::Get, &app_url, 200, &stage_app("exited:unhealthy"));
        transport.queue(Method::Post, &format!("{app_url}/start"), 200, "{}");
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:healthy"));
        transport.queue(Method::Get, &plan.system_info_url(), 200, system_info_body);
        let mut clock = FakeClock::new();

        let error = plan.run(&mut transport, &mut clock).unwrap_err().to_string();

        assert!(error.contains("verify"), "error should name the step: {error}");
        assert!(error.contains("90s"), "error should name the verify timeout, not another field's: {error}");
        assert!(error.contains(expect_contains), "error should mention {expect_contains:?}: {error}");
    }

    // --- dry run & redaction ------------------------------------------

    #[test]
    fn dry_run_never_prints_secret_values() {
        let plan = test_plan();
        let lines = plan.dry_run_lines().join("\n");
        for secret in plan.secrets() {
            assert!(!lines.contains(secret), "dry-run output leaked a secret: {lines}");
        }
        assert!(lines.contains("[REDACTED]"));
        assert!(lines.contains("stage-0123456789ab"));
    }

    #[test]
    fn dry_run_sends_zero_requests_through_the_execute_path() {
        let plan = test_plan();
        let mut transport = ScriptedTransport::default();
        let mut clock = FakeClock::new();

        super::execute(&plan, true, &mut transport, &mut clock).unwrap();

        assert!(transport.requests.is_empty(), "dry-run must send zero requests");
    }

    #[test]
    fn stage_settings_debug_never_contains_the_secrets() {
        let settings = test_settings();
        let rendered = format!("{settings:?}");
        assert!(!rendered.contains("sentinel-coolify-token"));
        assert!(!rendered.contains("sentinel-cf-client-id"));
        assert!(!rendered.contains("sentinel-cf-client-secret"));
        assert!(!rendered.contains("sentinel-fabro-dev-token"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn planned_request_debug_redacts_header_values() {
        let request = PlannedRequest {
            method:  Method::Get,
            url:     "https://coolify.test/api/v1/applications/u".to_string(),
            headers: vec![("Authorization".to_string(), "Bearer sentinel-debug-secret".to_string())],
            body:    None,
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("sentinel-debug-secret"));
        assert!(rendered.contains("Authorization"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn run_scrubs_a_leaked_secret_from_a_failing_response_body() {
        let plan = test_plan();
        let app_url = plan.app_url();
        let mut transport = ScriptedTransport::default();
        transport.queue(Method::Get, &app_url, 200, &stage_app("running:healthy"));
        transport.queue(
            Method::Patch,
            &app_url,
            500,
            "Authorization: Bearer sentinel-coolify-token was rejected",
        );
        let mut clock = FakeClock::new();

        let error = plan.run(&mut transport, &mut clock).unwrap_err().to_string();

        assert!(!error.contains("sentinel-coolify-token"), "error leaked the Coolify token: {error}");
        assert!(error.contains("[REDACTED]"));
    }

    #[test]
    fn curl_error_message_scrubs_known_secrets() {
        let message = format_curl_failure(
            Some(6),
            "could not resolve host, token Bearer sentinel-curl-secret rejected",
            &["sentinel-curl-secret"],
        );
        assert!(!message.contains("sentinel-curl-secret"));
        assert!(message.contains("[REDACTED]"));
    }

    // --- curl transport --------------------------------------------------

    #[test]
    fn curl_config_sets_content_type_when_body_present_and_accept_always() {
        let get_request = PlannedRequest {
            method:  Method::Get,
            url:     "https://coolify.test/api/v1/applications/u".to_string(),
            headers: vec![],
            body:    None,
        };
        let config = CurlTransport::curl_config(&get_request, Duration::from_secs(3));
        assert!(config.contains("header = \"Accept: application/json\""));
        assert!(!config.contains("Content-Type"));

        let patch_request = PlannedRequest {
            method:  Method::Patch,
            url:     "https://coolify.test/api/v1/applications/u".to_string(),
            headers: vec![],
            body:    Some(json!({ "a": 1 })),
        };
        let config = CurlTransport::curl_config(&patch_request, Duration::from_secs(3));
        assert!(config.contains("header = \"Content-Type: application/json\""));
        assert!(config.contains("header = \"Accept: application/json\""));
    }

    #[test]
    fn curl_command_never_carries_the_secret_as_an_arg_or_env_value() {
        let secret = "sentinel-only-on-stdin";
        let request = PlannedRequest {
            method:  Method::Get,
            url:     "https://coolify.test/api/v1/applications/u".to_string(),
            headers: vec![("Authorization".to_string(), format!("Bearer {secret}"))],
            body:    None,
        };

        let command = CurlTransport::configured_command(&request);
        for arg in command.get_args() {
            assert!(!arg.to_string_lossy().contains(secret));
        }
        for (_, value) in command.get_envs() {
            if let Some(value) = value {
                assert!(!value.to_string_lossy().contains(secret));
            }
        }
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec!["-q", "-sS", "-K", "-"],
            "curl must ignore the operator's ~/.curlrc (-q first) and read everything else from stdin"
        );

        let config = CurlTransport::curl_config(&request, Duration::from_secs(3));
        assert!(config.contains(secret), "the secret should travel over curl's stdin config, not argv/env");
    }

    // --- workflow structure -------------------------------------------

    fn read_stage_image_workflow() -> String {
        let workflow_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../.github/workflows/stage-image.yml");
        fs::read_to_string(workflow_path).unwrap_or_else(|error| panic!("reading {workflow_path}: {error}"))
    }

    #[test]
    fn stage_image_workflow_is_sha_pinned_and_refuses_fabro_sh() {
        let contents = read_stage_image_workflow();

        let mut saw_uses = false;
        for line in contents.lines() {
            let Some(at) = line.find("uses:") else { continue };
            saw_uses = true;
            let reference = line[at + "uses:".len()..].trim();
            let action_ref = reference.split_whitespace().next().unwrap_or("");
            let Some((_, pin)) = action_ref.split_once('@') else {
                panic!("uses: line is not pinned to a ref: {line}");
            };
            assert!(
                pin.len() == 40 && pin.bytes().all(|b| b.is_ascii_hexdigit()),
                "uses: line is not pinned to a 40-hex commit SHA: {line}"
            );
            assert!(reference.contains('#'), "uses: line is missing a version comment: {line}");
        }
        assert!(saw_uses, "expected at least one uses: line");

        assert!(contents.contains("github.repository_owner"));
        assert!(contents.contains("fabro-sh"));
        assert!(
            !contents.contains("tags: ghcr.io/fabro-sh")
                && !contents.contains("-t ghcr.io/fabro-sh")
                && !contents.contains("name=ghcr.io/fabro-sh"),
            "workflow must never publish under ghcr.io/fabro-sh/"
        );

        // The build legs must check out the commit `resolve` pinned, not the
        // mutable `inputs.ref` a branch could move out from under them.
        assert_eq!(
            contents.matches("ref: ${{ inputs.ref }}").count(),
            1,
            "only the resolve job should check out the raw ref input"
        );
        assert!(
            contents.contains("ref: ${{ needs.resolve.outputs.sha }}"),
            "the build job must check out the sha resolve resolved"
        );

        let job_order = ["resolve", "build", "merge"];
        for (index, job) in job_order.iter().enumerate() {
            let job_marker = format!("\n  {job}:\n");
            let job_at = contents
                .find(&job_marker)
                .unwrap_or_else(|| panic!("job {job} not found in workflow"));
            let body_start = job_at + job_marker.len();
            let job_end = match job_order.get(index + 1) {
                Some(next_job) => {
                    let next_marker = format!("\n  {next_job}:\n");
                    contents[body_start..]
                        .find(&next_marker)
                        .map_or(contents.len(), |offset| body_start + offset)
                }
                None => contents.len(),
            };
            let job_body = &contents[body_start..job_end];

            let steps_marker = "steps:\n";
            let steps_at = job_body
                .find(steps_marker)
                .unwrap_or_else(|| panic!("job {job} has no steps:"));
            let after_steps = &job_body[steps_at + steps_marker.len()..];

            let refusal_marker = "Refuse to run in the upstream fabro-sh repository";
            let refusal_at = after_steps
                .find(refusal_marker)
                .unwrap_or_else(|| panic!("job {job}'s first step must be the fabro-sh refusal"));
            let before_refusal = &after_steps[..refusal_at];
            // Exclude the trailing partial line (the refusal step's own
            // "      - name: " prefix), which otherwise self-matches "- name:".
            let before_refusal_complete_lines = before_refusal.rfind('\n').map_or("", |at| &before_refusal[..at]);
            assert!(
                !before_refusal_complete_lines.contains("- name:") && !before_refusal_complete_lines.contains("- uses:"),
                "job {job}'s fabro-sh refusal must be its first step"
            );

            let refusal_step_end = after_steps[refusal_at..]
                .match_indices("\n      - ")
                .map(|(index, _)| index)
                .next()
                .map_or(after_steps.len(), |index| refusal_at + index);
            let refusal_step = &after_steps[refusal_at..refusal_step_end];
            assert!(refusal_step.contains("REPOSITORY_OWNER"), "job {job}'s refusal must read REPOSITORY_OWNER");
            assert!(refusal_step.contains("fabro-sh"), "job {job}'s refusal must check for fabro-sh");
            assert!(refusal_step.contains("exit 1"), "job {job}'s refusal must exit 1");
        }
    }

    fn extract_run_script(contents: &str, step_name: &str) -> String {
        let name_at = contents
            .find(step_name)
            .unwrap_or_else(|| panic!("step {step_name:?} not found in workflow"));
        let run_marker = "run: |\n";
        let run_at = contents[name_at..]
            .find(run_marker)
            .unwrap_or_else(|| panic!("step {step_name:?} has no 'run: |' block"))
            + name_at
            + run_marker.len();
        let mut lines = Vec::new();
        for line in contents[run_at..].lines() {
            if line.trim().is_empty() {
                lines.push(String::new());
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            if indent < 8 {
                break;
            }
            lines.push(line.trim_start().to_string());
        }
        lines.join("\n")
    }

    /// Runs `script` under `bash -c`, with `docker` defined as a shell
    /// function (never a freshly written executable file): execing a new
    /// binary costs 0.4-4.8s on this Mac for its first run (macOS Gatekeeper
    /// policy scanning), which blew the nextest default profile's 3s
    /// terminate-after in round 2. A function call inside the same `bash -c`
    /// process has none of that cost.
    fn run_workflow_script(
        script: &str,
        docker_stub_body: &str,
        cwd: &std::path::Path,
        envs: &[(&str, &str)],
    ) -> std::process::Output {
        let combined = format!("set -e\ndocker() {{\n{docker_stub_body}\n}}\n{script}\n");
        let mut command = std::process::Command::new("bash");
        command.arg("-c").arg(&combined).current_dir(cwd);
        for (key, value) in envs {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    #[test]
    fn stage_image_merge_step_builds_one_ref_per_digest() {
        let contents = read_stage_image_workflow();
        let script = extract_run_script(&contents, "Create and push the multi-arch manifest");
        assert!(!script.is_empty());

        let digests_dir = tempfile::tempdir().unwrap();
        let log_dir = tempfile::tempdir().unwrap();
        let digest_a = "a".repeat(64);
        let digest_b = "b".repeat(64);
        fs::write(digests_dir.path().join(&digest_a), "").unwrap();
        fs::write(digests_dir.path().join(&digest_b), "").unwrap();
        let log_path = log_dir.path().join("docker-args.log");

        let stub = "for a in \"$@\"; do printf '%s\\n' \"$a\" >> \"$DOCKER_ARGS_LOG\"; done";
        let output = run_workflow_script(
            &script,
            stub,
            digests_dir.path(),
            &[
                ("IMAGE", "ghcr.io/eovidiu/fabro"),
                ("TAG", "stage-0123456789ab"),
                ("DOCKER_ARGS_LOG", log_path.to_str().unwrap()),
            ],
        );
        assert!(output.status.success(), "merge script failed: {}", String::from_utf8_lossy(&output.stderr));

        let logged = fs::read_to_string(&log_path).unwrap();
        let args: Vec<String> = logged.lines().map(str::to_string).collect();
        assert_eq!(
            args,
            vec![
                "buildx".to_string(),
                "imagetools".to_string(),
                "create".to_string(),
                "-t".to_string(),
                "ghcr.io/eovidiu/fabro:stage-0123456789ab".to_string(),
                format!("ghcr.io/eovidiu/fabro@sha256:{digest_a}"),
                format!("ghcr.io/eovidiu/fabro@sha256:{digest_b}"),
            ],
            "expected exactly one buildx imagetools create call, the right -t target, and one ref per digest in glob order"
        );
    }

    // A manifest list as `docker buildx imagetools create` actually writes it
    // (Go `json.MarshalIndent(&idx, "", "  ")`): keys use `"key": value`, with
    // a space after the colon, unlike the compact form round 1's grep assumed.
    const INDENTED_INDEX_BOTH_ARCHES: &str = r#"{
   "schemaVersion": 2,
   "mediaType": "application/vnd.oci.image.index.v1+json",
   "manifests": [
      {
         "mediaType": "application/vnd.oci.image.manifest.v1+json",
         "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         "size": 123,
         "platform": {
            "architecture": "amd64",
            "os": "linux"
         }
      },
      {
         "mediaType": "application/vnd.oci.image.manifest.v1+json",
         "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
         "size": 456,
         "platform": {
            "architecture": "arm64",
            "os": "linux"
         }
      }
   ]
}
"#;

    const INDENTED_INDEX_AMD64_ONLY: &str = r#"{
   "schemaVersion": 2,
   "mediaType": "application/vnd.oci.image.index.v1+json",
   "manifests": [
      {
         "mediaType": "application/vnd.oci.image.manifest.v1+json",
         "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         "size": 123,
         "platform": {
            "architecture": "amd64",
            "os": "linux"
         }
      }
   ]
}
"#;

    fn run_verify_script_against_index(script: &str, index_json: &str) -> std::process::Output {
        let dir = tempfile::tempdir().unwrap();
        let index_path = dir.path().join("index.json");
        fs::write(&index_path, index_json).unwrap();
        let stub = r#"if [ "$1" = "buildx" ] && [ "$2" = "imagetools" ] && [ "$3" = "inspect" ]; then
  for a in "$@"; do
    if [ "$a" = "--raw" ]; then
      cat "$FAKE_INDEX_FILE"
      return 0
    fi
  done
  return 0
fi
echo "unexpected docker invocation: $*" >&2
return 1"#;
        run_workflow_script(
            script,
            stub,
            dir.path(),
            &[
                ("IMAGE", "ghcr.io/eovidiu/fabro"),
                ("TAG", "stage-0123456789ab"),
                ("FAKE_INDEX_FILE", index_path.to_str().unwrap()),
            ],
        )
    }

    #[test]
    fn stage_image_verify_step_accepts_an_indented_index_with_both_arches() {
        let contents = read_stage_image_workflow();
        let script = extract_run_script(&contents, "Verify the published manifest lists both architectures");
        assert!(!script.is_empty());

        let output = run_verify_script_against_index(&script, INDENTED_INDEX_BOTH_ARCHES);

        assert!(
            output.status.success(),
            "verify script should accept an indented index with both arches: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn stage_image_verify_step_rejects_an_index_missing_an_architecture() {
        let contents = read_stage_image_workflow();
        let script = extract_run_script(&contents, "Verify the published manifest lists both architectures");

        let output = run_verify_script_against_index(&script, INDENTED_INDEX_AMD64_ONLY);

        assert!(!output.status.success(), "verify script should reject an index missing arm64");
        assert!(String::from_utf8_lossy(&output.stderr).contains("arm64"));
    }
}
