use chalk_rs::Chalk;
use rusqlite::{Connection, Result};
use std::path::Path;

//use yaml_rust2::{Yaml, YamlEmitter, YamlLoader};

#[derive(Debug)]
struct Entries {
    name: String,
    status: String,
    mount_point: String,
}

pub fn list() -> Result<()> {
    let config_file_dir: &str = "~/.config/ribis/";
    let db_file_location: String =
        [config_file_dir.to_string(), "database.sqlite".to_string()].join("");
    let expanded_path_db_file_location = shellexpand::tilde(&db_file_location);
    let db_path = Path::new(expanded_path_db_file_location.as_ref());

    let conn = Connection::open(db_path).unwrap();
    let query = "Select name,status,mount_point from ribis";

    let mut stmt = conn.prepare(&query)?;
    let result_iter = stmt.query_map([], |row| {
        Ok(Entries {
            name: row.get(0)?,
            status: row.get(1)?,
            mount_point: row.get(2)?,
        })
    })?;

    let mut chalk = Chalk::new();

    for result in result_iter {
        match result {
            Ok(entry) => {
                if entry.status == "unlocked" {
                    chalk.red().println(&format!(
                        "[{}] : {} {} ",
                        entry.status, entry.name, entry.mount_point
                    ));
                } else {
                    chalk.green().println(&format!(
                        "[{}] : {} {} ",
                        entry.status, entry.name, entry.mount_point
                    ));
                }
            }
            Err(e) => {
                eprintln!("Error");
            }
        }
    }

    return Ok(());
}
