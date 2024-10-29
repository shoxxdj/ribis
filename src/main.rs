use clap::{Arg, Command};
use shellexpand;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
mod create;
use sqlite;
use yaml_rust2::{Yaml, YamlEmitter, YamlLoader};
fn main() -> io::Result<()> {
    //First time

    let config_file_dir: &str = "~/.config/ribis/";
    let config_file_location: String =
        [config_file_dir.to_string(), "config.yml".to_string()].join("");
    let expanded_path_config_file_location = shellexpand::tilde(&config_file_location);
    let path = Path::new(expanded_path_config_file_location.as_ref());
    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("Failed to create directory: {}", e);
            return Ok(());
        }
    }

    match File::create_new(path) {
        Ok(_) => {
            println!(
                "Config file created successfully at {}",
                expanded_path_config_file_location
            );
            let mut config = Vec::new();
            let mut yaml_map = yaml_rust2::yaml::Hash::new();
            let homePath = shellexpand::tilde("~");
            yaml_map.insert(
                Yaml::String("storage_path".to_string()),
                Yaml::String([homePath.to_string(), "/ribis_storage".to_string()].join("")),
            );

            yaml_map.insert(
                Yaml::String("keys_location".to_string()),
                Yaml::String([config_file_dir.to_string(), "keys".to_string()].join("")),
            );

            yaml_map.insert(
                Yaml::String("compression_method".to_string()),
                Yaml::String("xz".to_string()),
            );

            yaml_map.insert(Yaml::String("encrypting".to_string()), Yaml::Boolean(true));
            // Create the pgp_infos map and add it as a nested structure
            let mut pgp_infos = yaml_rust2::yaml::Hash::new();
            pgp_infos.insert(
                Yaml::String("comment".to_string()),
                Yaml::String("none".to_string()),
            );
            print!("Enter your email for pgp keys: ");
            io::stdout().flush()?;
            let mut email = String::new();
            io::stdin().read_line(&mut email)?;
            let email = email.trim();
            pgp_infos.insert(
                Yaml::String("email".to_string()),
                Yaml::String(email.to_string()),
            );
            print!("Enter your name for pgp keys: ");
            io::stdout().flush()?;
            let mut username = String::new();
            io::stdin().read_line(&mut username)?;
            let username = username.trim();
            pgp_infos.insert(
                Yaml::String("name".to_string()),
                Yaml::String(username.to_string()),
            );

            yaml_map.insert(Yaml::String("pgp_infos".to_string()), Yaml::Hash(pgp_infos));

            config.push(Yaml::Hash(yaml_map));
            let mut out_str = String::new();
            {
                let mut emitter = YamlEmitter::new(&mut out_str);
                emitter.dump(&config[0]).unwrap();
            }
            // Write the YAML string to a file
            let mut file = File::create(path)?;
            file.write_all(out_str.as_bytes())?;
            println!("YAML file written successfully!");
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            eprintln!("Error creating config file: {}", e);
            // You might want to handle the error or exit the program here
        }
    }

    //Open db or create if not exist
    let db_file_location: String =
        [config_file_dir.to_string(), "database.sqlite".to_string()].join("");
    let expanded_path_db_file_location = shellexpand::tilde(&db_file_location);
    let db_path = Path::new(expanded_path_db_file_location.as_ref());

    let conn = sqlite::open(db_path).unwrap();
    let query = " CREATE TABLE IF NOT EXISTS ribis (
            name VARCHAR(255) NOT NULL,
            private_key_path VARCHAR(255) NOT NULL,
            public_key_path VARCHAR(255) NOT NULL,
            status VARCHAR(10) NOT NULL,
            mount_point VARCHAR(255) NOT NULL
        ); ";
    conn.execute(query).unwrap();

    let matches = Command::new("my_program")
        .version("1.0")
        .author("Votre Nom <votremail@example.com>")
        .about("Un programme simple avec clap et des arguments positionnels")
        .arg(
            Arg::new("action")
                .required(true)
                .value_parser(["create", "list", "lock", "unlock", "delete"])
                .help("What you want"),
        )
        .arg(Arg::new("name").required(false).help("name"))
        .get_matches();

    // Récupérer la valeur de l'argument positionnel "action"
    let action = matches
        .get_one::<String>("action")
        .expect("Argument requis");

    let mut name: Option<&String> = None;

    if action != "list" {
        // Vérifier si l'argument "name" est manquant
        if matches.get_one::<String>("name").is_none() {
            // Si le nom est manquant, afficher un message d'erreur
            eprintln!("Err : name is required for '{}'.", action);
            std::process::exit(-1); // Sortir avec un code d'erreur propre
        } else {
            // Si le nom est présent, afficher l'action et le nom
            name = matches.get_one::<String>("name");
        }
    }
    // Faire quelque chose en fonction de l'action
    match action.as_str() {
        "create" => {
            let name = name.expect("name must be defined");
            create::create(name);
        }
        "list" => println!("Vous avez choisi l'action list"),
        "lock" => println!("Vous avez choisi l'action lock"),
        "unlock" => println!("Vous avez choisi l'action unlock"),
        "delete" => println!("Vous avez choisi l'action delete"),
        _ => unreachable!(), // Ne devrait jamais arriver grâce à `value_parser`
    }
    return Ok(());
}
