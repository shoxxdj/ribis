use pgp_lib::native::composed::message::Message;
use pgp_lib::native::crypto::hash::HashAlgorithm;
use pgp_lib::native::crypto::sym::SymmetricKeyAlgorithm;
use pgp_lib::native::ser::Serialize;
use pgp_lib::native::types::CompressionAlgorithm;
use pgp_lib::native::types::SecretKeyTrait;
use pgp_lib::native::types::StringToKey;
use pgp_lib::native::{
    Deserializable, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
    StandaloneSignature, SubkeyParamsBuilder,
};

use pgp_lib::{decrypt, encrypt, gen_key_pair, read_sig_from_bytes, sign, verify};
use rpassword::read_password;
//use rusqlite::{Connection, Result};
use smallvec::smallvec;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{self, Error, Read, Write};
use std::path::Path;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tar::Archive;
use tokio::runtime::{Builder, Runtime};
use yaml_rust2::{Yaml, YamlEmitter, YamlLoader};

use rand::prelude::*;
use rand::thread_rng;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use tar::Builder as tarBuilder;
use xz2::read::XzDecoder;
use xz2::write::XzEncoder;

//use crate::create::encrypt::SignedPublicKeyOrSubkey;
use pgp_lib::encrypt::SignedPublicKeyOrSubkey;

use anyhow::{Context, Result}; // Importation de anyhow pour gérer les erreurs.
use spinoff::{spinners, Color, Spinner};

fn generate_armored_string(
    msg: Message,
    _public_key: SignedPublicKey,
) -> Result<String, Box<dyn std::error::Error>> {
    // Convertit le message en format armored PGP
    Ok(msg.to_armored_string(None)?)
}

async fn create_pgp_keypair(
    name: &str,
    email: &str,
    passphrase: &str,
    output_dir: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let key_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Rsa((4096)))
        .can_create_certificates(true)
        .can_sign(true)
        .primary_user_id(email.to_string())
        .passphrase(Some(passphrase.to_string()))
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
        .preferred_hash_algorithms(smallvec![HashAlgorithm::SHA2_256])
        .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB])
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(KeyType::ECDH)
                .can_encrypt(true)
                .passphrase(Some(passphrase.to_string()))
                .build()
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?,
        )
        .build()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    let skey = key_params
        .generate()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    let skey = skey
        .sign(|| passphrase.to_string())
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    skey.verify()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    let pkey = skey.public_key();
    let pkey = pkey
        .sign(&skey, || passphrase.to_string())
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    pkey.verify()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    // Export private key
    let private_key_path = Path::new(output_dir).join(format!("{}_private.asc", name));
    let mut private_key_file = File::create(&private_key_path)?;
    private_key_file.write_all(skey.to_armored_string(None)?.as_bytes())?;

    // Export public key
    let public_key_path = Path::new(output_dir).join(format!("{}_public.asc", name));
    let mut public_key_file = File::create(&public_key_path)?;
    public_key_file.write_all(pkey.to_armored_string(None)?.as_bytes())?;

    // println!("Private key saved to: {}", private_key_path.display());
    // println!("Public key saved to: {}", public_key_path.display());

    Ok((
        private_key_path.to_string_lossy().into_owned(),
        public_key_path.to_string_lossy().into_owned(),
    ))
}

fn entry_exists(conn: &rusqlite::Connection, value: &str) -> Result<bool> {
    let mut stmt = conn.prepare("SELECT status FROM ribis WHERE name = ?1")?;
    let mut rows = stmt.query(&[value])?;
    if rows.next()?.is_some() {
        Ok(true) // Entry exists
    } else {
        Ok(false) // Entry does not exist
    }
}

pub fn create(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    //Get email from config
    let config_file_dir: &str = "~/.config/ribis/";
    let config_file_location: String =
        [config_file_dir.to_string(), "config.yml".to_string()].join("");
    let expanded_path_config_file_location = shellexpand::tilde(&config_file_location);
    let path = Path::new(expanded_path_config_file_location.as_ref());

    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let docs = YamlLoader::load_from_str(&contents).expect("Failed to parse YAML");
    let doc = &docs[0];

    let db_file_location: String =
        [config_file_dir.to_string(), "database.sqlite".to_string()].join("");
    let expanded_path_db_file_location = shellexpand::tilde(&db_file_location);
    let db_path = Path::new(expanded_path_db_file_location.as_ref());

    let conn = rusqlite::Connection::open(db_path).unwrap();

    if entry_exists(&conn, &name)? {
        eprintln!("Err : A container with this name already exists");
        std::process::exit(-1); // Sortir avec un code d'erreur propre
    }

    // Access the `email` field within `pgp_infos`
    if let Some(email) = doc["pgp_infos"]["email"].as_str() {
        //println!("Email: {}", email);
        if let Some(keys_location) = doc["keys_location"].as_str() {
            print!("Enter your passphrase: ");
            io::stdout().flush()?;
            let passphrase = read_password()?;

            print!("Enter your passphrase again: ");
            io::stdout().flush()?;
            let passphrase_confirm = read_password()?;

            if passphrase != passphrase_confirm {
                eprintln!("Passphrases did not match");
                return Ok(());
            }

            let pgp_creation_string = format!("Creating PGP key pair for {}", name);
            let mut spinner = Spinner::new(spinners::Line, pgp_creation_string, Color::Yellow);

            let output_dir = [keys_location.to_string(), "/".to_string(), name.to_string()]
                .join("")
                .to_string();
            //println!("{}", &output_dir);

            let expanded_path_output_dir = shellexpand::tilde(&output_dir);
            let keys_path = Path::new(expanded_path_output_dir.as_ref());

            if let Err(e) = fs::create_dir_all(&keys_path) {
                eprintln!("Failed to create directory: {}", e);
                return Ok(());
            }

            if let Some(keys_path_string) = keys_path.to_str() {
                let runtime = Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to create Tokio runtime");

                let result = runtime.block_on(create_pgp_keypair(
                    name,
                    email,
                    &passphrase,
                    keys_path_string,
                ));

                match result {
                    Ok((private_key_path, public_key_path)) => {
                        spinner.update_text("Creating entry in database");

                        // println!("PGP key pair created successfully.");
                        // println!("Will now create the entry in the database");

                        let query = "INSERT INTO ribis(name,private_key_path,public_key_path,status,mount_point) VALUES(?,?,?,?,?) ";

                        conn.execute(
                            query,
                            &[
                                &name,
                                private_key_path.as_str(),
                                public_key_path.as_str(),
                                "locked",
                                "",
                            ],
                        )?;

                        /*
                        Create empty dir for convenance
                            path=Path(static.tibis_empty_dir)
                            path.mkdir(parents=True,exist_ok=True)
                            path=Path(static.tibis_tmp_dir)
                            path.mkdir(parents=True,exist_ok=True)
                            archive=common.createArchive(dirname,static.tibis_empty_dir,static.tibis_tmp_dir)
                            common.cryptArchive(publicKeyLocation,archive,config.storage_path(),dirname)
                        */
                        spinner.update_text("Creating initial archive");

                        let directory_location = ["/tmp/".to_string(), name.to_string()].join("");
                        fs::create_dir(&directory_location)?;

                        let archive_location =
                            ["/tmp/".to_string(), name.to_string(), ".tar".to_string()].join("");

                        let archive = File::create(&archive_location).unwrap(); //voir pour créer un dir
                        let mut archive_builder: tarBuilder<File> = tarBuilder::new(archive);

                        archive_builder
                            .append_dir_all("", &directory_location)
                            .unwrap();

                        archive_builder.finish().unwrap();

                        // Chemin du fichier TAR source et du fichier compressé de sortie
                        let tar_path = &archive_location;
                        let xz_path = [archive_location.to_string(), ".xz".to_string()].join("");
                        //let xz_path = "/tmp/archive.tar.xz";

                        // Ouvre le fichier TAR en lecture
                        let tar_file = File::open(tar_path)?;
                        let tar_reader = BufReader::new(tar_file);

                        // Ouvre (ou crée) le fichier de sortie en écriture
                        let xz_file = File::create(xz_path.clone())?;
                        let mut xz_writer = BufWriter::new(xz_file);

                        // Définit le niveau de compression (6 est un bon compromis entre vitesse et taux de compression)
                        let mut encoder = XzEncoder::new(xz_writer, 6);

                        // Copie les données du fichier TAR dans le compresseur XZ
                        std::io::copy(&mut tar_reader.take(std::u64::MAX), &mut encoder)?;
                        let xz_writer = encoder.finish()?;

                        let mut xz_content = Vec::new();
                        File::open(&xz_path)?.read_to_end(&mut xz_content)?;

                        let _ = runtime.block_on(create_encrypted_file(&xz_path, &public_key_path));

                        let storage_location = doc["storage_path"].as_str().unwrap();
                        let in_path = [&xz_path.to_string(), ".ribis"].join("").to_string();
                        let out_name: String = [storage_location, &name].join("/");
                        fs::create_dir_all(storage_location)?;
                        println!("{}", in_path.as_str());
                        println!("{}", out_name.as_str());
                        //Cant rename here as /tmp is a tmpfile system
                        match (fs::copy(&in_path, out_name)) {
                            Ok(_) => {
                                fs::remove_file(&in_path)?;
                                //Should handle here also
                                spinner.stop_and_persist("📜", "Ready to rock !");
                            }
                            Err((e)) => {
                                spinner.fail("Something went wrong on file copying");
                                println!("{:?}", e)
                            }
                        }
                        return Ok(());
                    }
                    Err(e) => eprintln!("Error creating PGP key pair: {}", e),
                }
            } else {
                println!("Keys location field not found in config.");
                return Ok(());
            }
        }

        Ok(())
    } else {
        println!("Email field not found in config.");
        return Ok(());
    }
}

async fn create_encrypted_file(xz_path: &str, public_key_path: &str) -> Result<String> {
    if let Err(err) = try_create_encrypted_file(xz_path, public_key_path).await {
        // Afficher l'erreur sur la sortie d'erreur standard
        eprintln!("Error: {:?}", err);
        return Err(err); // Propager l'erreur pour que l'appelant puisse la gérer
    }

    Ok("ok".to_string())
}

async fn try_create_encrypted_file(xz_path: &str, public_key_path: &str) -> Result<()> {
    // Lire le contenu de la clé publique
    let key_string = fs::read_to_string(public_key_path).with_context(|| {
        format!(
            "Failed to read the public key file at '{}'",
            public_key_path
        )
    })?;

    // Convertir la clé publique depuis la chaîne
    let (public_key, _) =
        SignedPublicKey::from_string(&key_string).context("Failed to parse the public key")?;

    //let xz_path = "/tmp/file.tar.xz";
    // Ouvrir le fichier compressé
    let xz_file =
        File::open(xz_path).with_context(|| format!("Failed to open the file at '{}'", xz_path))?;

    let mut xz_content = Vec::new();
    let _ = BufReader::new(xz_file).read_to_end(&mut xz_content);

    //File::open("/tmp/file.tar.xz")?.read_to_end(&mut xz_content)?;
    let b = &xz_content;
    let c: &[u8] = &b;

    // Créer un message à partir des octets du fichier
    let msg = Message::new_literal_bytes("this_name_is_random_4GKdSand_never4GKdS_used_4GKdSanywhere4GKdS_unless_a_star_colision_is_coming_4GKdS", c);

    // Générer une chaîne encodée en utilisant la clé publique
    // let armored = generate_armored_string(msg, public_key)
    //     .map_err(|e| anyhow::Error::msg(e.to_string())) // Encapsulation explicite de l'erreur
    //     .context("Failed to generate the armored string with the public key")?;

    let mut rng = StdRng::from_entropy();
    let new_msg = &msg.encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES256, &[&public_key])?;
    let encrypted_message = new_msg.to_bytes()?;

    let out_path = [&xz_path.to_string(), ".ribis"].join("");
    println!("{}", out_path);
    // Écrire le résultat dans un fichier
    fs::write(out_path, &encrypted_message)
        .with_context(|| "Failed to write the encrypted content to '/tmp/res2'")?;

    Ok(())
}

// pub async fn spawn_blocking<F, T>(f: F) -> Result<T>
// where
//     F: FnOnce() -> T + Send + 'static,
//     T: Send + 'static,
// {
//     Ok(async_std::task::spawn_blocking(f).await)
// }
