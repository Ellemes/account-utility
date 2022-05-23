use structopt::StructOpt;
use std::process::{Command, ExitStatus, Stdio};
use std::io::{BufReader, BufRead, Error, Write, BufWriter};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::borrow::Borrow;
use std::{env, fs};

#[derive(StructOpt)]
struct Args {
    #[structopt(default_value = "current")]
    account: String,
    #[structopt(default_value = "github")]
    service: String,
}

struct Account {
    folder_path: PathBuf,
    identifier: String,
    name: String,
    email: String,
    ssh_key: String,
    gpg_key: String,
    gh_auth_token: Option<String>,
}

impl Account {
    fn get_path(&self, file: &str) -> PathBuf {
        let mut path = self.folder_path.clone();
        path.push(file);
        path
    }

    fn get_identifier(&self) -> String {
        self.identifier.to_owned()
    }
}

struct CurrentAccount {
    identifier: String,
    is_gh_authed: bool,
}

// todo: should probably add some safe guards e.g. halting early if ssh key fails to copy and perform cleanup
fn main() {
    if let Ok(exe_path) = env::current_exe() {
        if let Some(parent_dir) = exe_path.as_path().parent() {
            let args = Args::from_args();
            let current_account_details = &load_current_account(parent_dir);
            if args.account == "current" {
                match current_account_details {
                    Some(account) => println!("Currently logged into: {}.", account.identifier),
                    None => println!("Currently not logged in.")
                };
            } else {
                if let Some(account) = current_account_details {
                    let current_account_identifier = account.identifier.as_str();
                    if format!("{}/{}", args.service, args.account).eq(current_account_identifier) {
                        println!("Already logged into {}.", current_account_identifier);
                        return;
                    };
                };
                match load_account(parent_dir, &args.account, &args.service) {
                    Ok(account) => switch_account(parent_dir, account, current_account_details.as_ref().map(|t| { t.is_gh_authed }).unwrap_or(false)),
                    Err(reason) => println!("Cannot load account: {}", reason)
                };
            };
            return;
        };
    };
    println!("Cannot find executable path."); 
}

fn load_current_account(parent_dir: &Path) -> Option<CurrentAccount> {
    let mut path = parent_dir.to_path_buf();
    path.push("accounts/current.properties");
    return if path.exists() {
        let mut current_account_details = CurrentAccount {
            identifier: "".to_string(),
            is_gh_authed: false,
        };
        {
            let file = File::open(<PathBuf as AsRef<Path>>::as_ref(path.borrow())).expect("");
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line.unwrap();
                let parts = line.split(" = ").collect::<Vec<&str>>();
                if let [key, value] = parts[..] {
                    match key {
                        "identifier" => current_account_details.identifier = value.to_string(),
                        "is_gh_authed" => current_account_details.is_gh_authed = value.eq("true"),
                        _ => println!("Ignoring unknown key: {} in {}", key, path.display())
                    };
                };
            };
        }
        Some(current_account_details)
    } else {
        None
    };
}

fn load_account(parent_dir: &Path, account: &str, service: &str) -> Result<Account, String> {
    let mut path = parent_dir.to_path_buf();
    path.push(format!("accounts/{}/{}/account.properties", service, account));
    return if path.exists() {
        let account_path = path.parent().unwrap().to_path_buf();
        let mut account_details = Account {
            folder_path: account_path,
            identifier: format!("{}/{}", service, account),
            name: "".to_string(),
            email: "".to_string(),
            ssh_key: "".to_string(),
            gpg_key: "".to_string(),
            gh_auth_token: None,
        };
        {
            let file = File::open(<PathBuf as AsRef<Path>>::as_ref(path.borrow())).expect("");
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line.unwrap();
                let parts = line.split(" = ").collect::<Vec<&str>>();
                if let [key, value] = parts[..] {
                    match key {
                        "name" => account_details.name = value.to_string(),
                        "email" => account_details.email = value.to_string(),
                        "ssh_key" => account_details.ssh_key = value.to_string(),
                        "gpg_key" => account_details.gpg_key = value.to_string(),
                        "gh_auth_token" => account_details.gh_auth_token = Some(value.to_string()),
                        _ => println!("Ignoring unknown key: {} in {}", key, path.display())
                    };
                };
            };
        }
        Ok(account_details)
    } else {
        Err(format!("Account file not found at {}", path.display()))
    };
}

fn switch_account(parent_dir: &Path, account: Account, is_gh_authed: bool) {
    if let Some(user_home) = get_environment_variable() {
        let ssh_dir = format!("{}/.ssh/", user_home);
        let ssh_path = Path::new(ssh_dir.as_str());
        if ssh_path.exists() {
            fs::remove_dir_all(ssh_path).expect("TODO: panic message");
        }
        fs::create_dir_all(ssh_path).expect("TODO: panic message");
        if let Err(reason) = fs::copy(account.get_path(account.ssh_key.as_str()), format!("{}/.ssh/{}", user_home, account.ssh_key)) {
            println!("Failed to copy private ssh key: {}", reason);
        };
        if let Err(reason) = fs::copy(account.get_path(format!("{}.pub", account.ssh_key).as_str()), format!("{}/.ssh/{}.pub", user_home, account.ssh_key)) {
            println!("Failed to copy public ssh key: {}", reason);
        };
        if is_gh_authed {
            match execute_interactive_command("gh", &["auth", "logout", "--hostname", "github.com"], "Y") {
                Ok(status) => println!("GH un-auth succeeded: {}", status),
                Err(reason) => eprintln!("GH un-auth failed: {}", reason)
            };
        };
        if let Some(ref token) = account.gh_auth_token {
            match execute_interactive_command("gh", &["auth", "login", "--with-token"], token) {
                Ok(status) => println!("GH auth succeeded: {}", status),
                Err(reason) => eprintln!("GH auth failed: {}", reason)
            };
        };
        // todo: if no user set this has an obscure output: "fatal: no such section: user"
        if let Err(reason) = Command::new("git").args(&["config", "--global", "--remove-section", "user"]).status() {
            println!("Removing current git user failed: {}", reason);
        };
        if let Err(reason) = set_git_user(&account) {
            println!("Setting git user to {} failed: {}", account.get_identifier(), reason);
        };
        if let Err(reason) = set_current_user(parent_dir, &account) {
            println!("Overwriting current account file to {} failed: {}", account.get_identifier(), reason);
        };
    } else {
        println!("Cannot find user home, cannot change accounts!")
    }
}

fn get_environment_variable() -> Option<String> {
    env::vars().find(|thing| {
        let object = thing.to_owned();
        let key = object.0;
        key.eq("HOME") || key.eq("USERPROFILE")
    }).to_owned().map(|thing| {thing.1} )
}

fn set_current_user(parent_dir: &Path, account: &Account) -> Result<i32, Error> {
    let mut path = parent_dir.to_path_buf();
    path.push("accounts/current.properties");
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    writer.write_all(format!("identifier = {}\n", account.get_identifier()).as_bytes())?;
    match account.gh_auth_token {
        Some(_) => writer.write_all(b"is_gh_authed = true\n")?,
        None => writer.write_all(b"is_gh_authed = false\n")?
    };
    writer.flush()?;
    Ok(0)
}

fn set_git_user(account: &Account) -> Result<i32, Error> {
    Command::new("git").args(&["config", "--global", "--add", "user.name", account.name.as_str()]).status()?;
    Command::new("git").args(&["config", "--global", "--add", "user.email", account.email.as_str()]).status()?;
    Command::new("git").args(&["config", "--global", "--add", "user.signingkey", account.gpg_key.as_str()]).status()?;
    Command::new("git").args(&["config", "--global", "commit.gpgsign", "true"]).status()?;
    Ok(0)
}

fn execute_interactive_command(program: &str, args: &[&str], input: &str) -> Result<ExitStatus, Error> {
    let mut process = Command::new(program).stdin(Stdio::piped()).args(args).spawn()?;
    process.stdin.as_ref().unwrap().write_all(input.as_bytes())?;
    match process.try_wait()? {
        Some(status) => Ok(status),
        None => process.wait()
    }
}
