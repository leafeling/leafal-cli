use clap::{Parser, Subcommand};
use confy::ConfyError;
use rpassword::read_password;
use serde::{Serialize, Deserialize};
use std::{io::{self, Write}, env};
use surrealdb::{Surreal, engine::remote::ws::{Ws, Client}, opt::auth::{Scope, Jwt}};
use dotenv::dotenv;

#[derive(Parser)]
#[command(name = "leafal-cli")]
#[command(author = "Hazel H. <hazel@leafal.io>")]
#[command(version = "1.0")]
#[command(about = "CLI to interface with leafal.io")]
struct Cli {
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Log into leafal.io and save the authentication token")]
    Login,
    #[command(about = "Returns information for the current user")]
    User,
    #[command(about = "Returns information for a given profile")]
    Profile,
}

#[derive(Serialize)]
struct Credentials<'a> {
    identifier: &'a str,
    password: &'a str
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    avatar: String,
    email: String,
    profile: Option<Profile>,
    username: String
}

#[derive(Debug, Serialize, Deserialize)]
struct Profile {
    displayname: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    token: Option<String>
}

impl Default for Config {
    fn default() -> Self { Self { token: None } }
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let cli = Cli::parse();
    let config: Config = load_config();

    match &cli.command {
        Commands::Login => { login(config).await },
        Commands::User => { get_user(config).await.expect("No user authenticated") },
        Commands::Profile => todo!()
    };
}

async fn login(config: Config) {
    let conn: Surreal<Client> = connect(config, false).await;

    // Ask for identifier.
    print!("Username or e-mail: ");
    io::stdout().flush().unwrap();
    let mut identifier = String::new();
    io::stdin().read_line(&mut identifier).expect("Read line failed.");

    // Ask for password.
    print!("Password: ");
    io::stdout().flush().unwrap();
    let password = read_password().unwrap();

    let token = get_token(conn, &identifier, &password).await;

    save_config(&Config {
        token: Some(token.into_insecure_token()),
        ..config
    });
}

async fn get_user(config: Config) -> surrealdb::Result<()> {
    let conn: Surreal<Client> = connect(config, true).await;
    let user: Vec<User> = conn.select("user").await?;

    dbg!(user);
    Ok(())
}


fn load_config() -> Config {
    let config: Result<Config, ConfyError> = confy::load("leafal-io", "main");

    match &config {
        Err(e) => println!("Configuration error, running stateless: {:?}", e),
        _ => {}
    }

    config.unwrap()
}

fn save_config(config: &Config) {
    let config = confy::store("leafal-io", "main", config);

    match &config {
        Err(e) => println!("File system error, could not save to configuration: {:?}", e),
        _ => {}
    }
}

async fn connect(config: Config, do_auth: bool) -> Surreal<Client> {
    println!("Establishing connection with leafal.io...");

    let endpoint = match env::var("LEAFAL_ENDPOINT") {
        Ok(var) => var,
        _ => String::from("leafal.io")
    };
    let conn = Surreal::new::<Ws>(endpoint).await;

    match &conn {
        Err(e) => println!("Connection error: {:?}", e),
        _ => println!("Connection successful.")
    }

    let conn = conn.unwrap();
    let _ = conn.use_ns("leafal-io").use_db("leafal-io-deployment_development").await;

    if do_auth && config.token.is_some() {
        authenticate(&conn, Jwt::from(config.token.unwrap())).await;
    }

    conn
}

async fn authenticate(conn: &Surreal<Client>, token: Jwt) -> bool {
    println!("Authenticating...");
    let auth = conn.authenticate(token).await;

    match &auth {
        Err(e) => { println!("Authentication error: {:?}", e); false },
        _ => { println!("Authentication successful."); true }
    }
}

async fn get_token(conn: Surreal<Client>, identifier: &str, password: &str) -> Jwt {
    println!("Signing in...");
    let token = conn.signin(Scope {
        namespace: "leafal-io",
        database: &format!("leafal-io-deployment_{}", match env::var("LEAFAL_MODE") {
            Ok(var) => var,
            _ => String::from("production")
        }),
        scope: "user",
        params: Credentials {
            identifier: &identifier.trim(),
            password: &password.trim(),
        },
    }).await;

    match &token {
        Err(e) => println!("Sign in error: {:?}", e),
        _ => println!("Sign in successful.")
    }

    token.unwrap()
}