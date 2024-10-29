use pgp::native::crypto::hash::HashAlgorithm;
use pgp::native::crypto::sym::SymmetricKeyAlgorithm;
use pgp::native::types::CompressionAlgorithm;
use pgp::native::types::SecretKeyTrait;
use pgp::native::{
    Deserializable, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
    StandaloneSignature, SubkeyParamsBuilder,
};
use pgp::{decrypt, encrypt, gen_key_pair, read_sig_from_bytes, sign, verify};
use rpassword::read_password;
use smallvec::smallvec;
use std::fs;
use std::fs::File;
use std::io::{self, Error, Read, Write};
use std::path::Path;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::runtime::{Builder, Runtime};
use yaml_rust2::{Yaml, YamlEmitter, YamlLoader};

async fn create_pgp_keypair(
    name: &str,
    email: &str,
    passphrase: &str,
    output_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::EdDSA)
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

    println!("PGP key pair created successfully.");
    println!("Private key saved to: {}", private_key_path.display());
    println!("Public key saved to: {}", public_key_path.display());

    Ok(())
}

pub fn create(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating PGP key pair for {}", name);

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

    // Access the `email` field within `pgp_infos`
    if let Some(email) = doc["pgp_infos"]["email"].as_str() {
        println!("Email: {}", email);
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

            let output_dir = [keys_location.to_string(), "/".to_string(), name.to_string()]
                .join("")
                .to_string(); // You can change this to any directory you prefer
            println!("{}", &output_dir);

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
                    Ok(_) => {
                        println!("PGP key pair created successfully.");
                        println!("Will now create the entry in the database");
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
