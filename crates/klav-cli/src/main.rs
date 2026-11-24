//! `klav`: Klav command-line interface. See `docs/cli.md`.

mod backend;
/// The commit this binary was built from (`klav-daemon/build.rs`): only
/// `--version` reads it.
#[allow(dead_code)]
mod build {
    include!(concat!(env!("OUT_DIR"), "/build_identity.rs"));
}
mod cli;
mod clients;
mod commands;
mod context;
mod error;
mod input;
mod mcp;
mod output;
mod presence;
mod project;
mod secret_files;
mod skill;
mod task_file;
#[cfg(test)]
mod tests_support;
mod time;

use std::process::ExitCode;

use clap::Parser;
use klav_client::Home;

use crate::cli::{Cli, Command};
use crate::commands::{
    account, agent, client, deletion, extension, generate, generated, health, import, inject, item,
    log, presence as presence_command, proxy, run as run_command, sandbox, secret_request,
    skill as skill_command, task, vault,
};
use crate::context::Ctx;
use crate::error::CliResult;
use crate::input::Input;

async fn run(cli: Cli) -> CliResult<()> {
    if let Command::Generate(args) = cli.command {
        return generate::generate_cmd(args, cli.no_daemon).await;
    }
    let home = Home::from_env()?;
    let mut ctx = Ctx::new(home, Input::new(cli.password_stdin), cli.no_daemon);
    match cli.command {
        Command::Signup(args) => account::signup_cmd(&mut ctx, args).await,
        Command::Login(args) => account::login_cmd(&mut ctx, args).await,
        Command::Unlock(args) => account::unlock_cmd(&mut ctx, args).await,
        Command::Lock(args) => account::lock_cmd(&mut ctx, args).await,
        Command::Presence(cmd) => presence_command::presence_cmd(&ctx, cmd).await,
        Command::Logout(args) => deletion::logout_cmd(&mut ctx, args).await,
        Command::Status(args) => account::status_cmd(&mut ctx, args).await,
        Command::Sync(args) => account::sync_cmd(&mut ctx, &args).await,
        Command::Account(cmd) => account::account_cmd(&mut ctx, cmd).await,
        Command::Vault(cmd) => vault::vault_cmd(&mut ctx, cmd).await,
        Command::Project(cmd) => vault::project_cmd(&mut ctx, cmd).await,
        Command::Item(cmd) => item::item_cmd(&mut ctx, cmd).await,
        Command::Totp(args) => item::totp_cmd(&mut ctx, args).await,
        Command::Import(args) => import::import_cmd(&mut ctx, args).await,
        Command::Run(args) => run_command::run_cmd(&mut ctx, args).await,
        Command::Inject(args) => inject::inject_cmd(&mut ctx, args).await,
        Command::Agent(cmd) => agent::agent_cmd(&mut ctx, cmd).await,
        Command::Proxy(cmd) => proxy::proxy_cmd(&mut ctx, cmd).await,
        Command::Sandbox(cmd) => sandbox::sandbox_cmd(&ctx, cmd).await,
        Command::Approval(cmd) => agent::approval_cmd(&mut ctx, cmd).await,
        Command::Task(cmd) => task::task_cmd(&mut ctx, cmd).await,
        Command::SecretRequest(cmd) => secret_request::secret_request_cmd(&mut ctx, cmd).await,
        Command::Log(args) => log::log_cmd(&mut ctx, args).await,
        Command::Extension(cmd) => extension::extension_cmd(&mut ctx, cmd).await,
        Command::Mcp(args) => mcp::mcp_cmd(&ctx, args).await,
        Command::Client(cmd) => client::client_cmd(&mut ctx, cmd).await,
        Command::Skill(cmd) => skill_command::skill_cmd(&mut ctx, cmd),
        Command::Generated(cmd) => generated::generated_cmd(&mut ctx, cmd).await,
        Command::Health(args) => health::health_cmd(&mut ctx, args).await,
        Command::Generate(_) => unreachable!("handled above"),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            output::warn(&format!("cannot start: {e}"));
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if let Some(msg) = e.message() {
                eprintln!("klav: {msg}");
            }
            ExitCode::from(e.exit_code())
        }
    }
}
