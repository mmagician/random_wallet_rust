use serde::{Serialize};
use uuid::Uuid;
use crypto::scrypt::{ScryptParams, scrypt};
use crypto::aes::{ctr, KeySize};
extern crate hex;
extern crate secp256k1;
extern crate rand;
use rand::Rng;
use secp256k1::key::{SecretKey, PublicKey};
use sha3::{Digest, Keccak256};
use serde_json::{Value, Map};


const DK_LEN: usize = 32;
const ETH_ADDRESS_LEN: usize = 20;

#[derive(Serialize, Debug)]
struct KeyStore<'a> {
    version: u8,
    id: &'a str,
    address: &'a str,
    crypto: &'a Map<String, Value>
}

fn serialize(store: &KeyStore ) {
    let serialized: String = serde_json::to_string(&store).unwrap();
    println!("serialized = {}", serialized);
    // TODO write to file
}


fn kdf (salt: &String, passphrase: &String, params: &ScryptParams, output: &mut [u8]){
    scrypt(passphrase.as_bytes(), salt.as_bytes(), &params, output);
}


fn main() {
    let uuid:String = Uuid::new_v4().to_hyphenated().to_string();

    // Private key is 256 bits = 32 bytes
    let private_key:[u8; DK_LEN] = rand::thread_rng().gen::<[u8; DK_LEN]>();
    println!("Private key: {}", hex::encode(&private_key));

    let passphrase:String = String::from("very secure");
    // Salt can be up to 32 bytes long
    let salt:String = String::from("my salt");

    let mut full_key = [0x00; DK_LEN];
    let log_n:u8 = 2;
    // Use 2^18 = 262,144 for production
    // let log_n:u8 = 18;
    let p:u32 = 1;
    let r:u32 = 8;
    let kdf_params:ScryptParams = ScryptParams::new(log_n, r, p);

    kdf(&salt, &passphrase, &kdf_params, &mut full_key);
    // Only the first part: 128 bits are used for AES.
    let encryption_key = &full_key[..DK_LEN/2];
    // The second part of the derived key is used for validation
    let validation_key = &full_key[DK_LEN/2..];
    println!("The encryption key: {}", hex::encode(encryption_key));
    println!("The validation key: {}", hex::encode(validation_key));

    // Run AES

    // We need an initialization vector, any #bytes will do (up to 32?)
    let iv:[u8; 8] = [0x00; 8];
    let mut aes_128 = ctr(KeySize::KeySize128, encryption_key, &iv);
    let mut ciphertext:[u8; DK_LEN] = [0u8; DK_LEN];
    aes_128.process(&private_key, &mut ciphertext);
    println!("Ciphertext is: {}", hex::encode(&ciphertext));

    // The MAC address is a hash of validation_key + ciphertext
    let mut hasher = Keccak256::new();
    hasher.input([validation_key, &ciphertext].concat());
    let mac_address = hasher.result();

    // Now create a public key from the private key. For this, use the secp256k1 library
    let secret_key = SecretKey::from_slice(&private_key);
    let context = secp256k1::Secp256k1::new();
    let public_key_full = PublicKey::from_secret_key(&context, &secret_key.unwrap());

    // The calculated public key has a leading 0x04 byte
    // (a prefix meaning that the Eliptic Curve public key is uncompressed,
    // according to a common standard SEC1). We only use the actual key w/o prefix
    let public_key: &[u8] = &public_key_full.serialize()[..DK_LEN];

    println!("Public key is: {}", hex::encode(public_key));

    let mut hasher = Keccak256::new();
    hasher.input(public_key);
    let result = hasher.result();
    let eth_address: &[u8] = &result[0..ETH_ADDRESS_LEN];
    println!("Ethereum address is: {}", hex::encode(&eth_address));

    // Finally, let's go about creating the JSON.
    // TODO this could use a clean up
    let mut crypto = Map::new();
    crypto.insert("cipher".to_string(), Value::String("aes-128-ctr".to_string()));
    crypto.insert("ciphertext".to_string(), Value::String( hex::encode(&ciphertext)));
    crypto.insert("kdf".to_string(), Value::String("scrypt".to_string()));
    crypto.insert("mac".to_string(), Value::String(hex::encode(mac_address)));

    let mut cipher_params = Map::new();
    cipher_params.insert("iv".to_string(), Value::String(hex::encode(&iv)));
    crypto.insert("cipherparams".to_string(), Value::Object(cipher_params));

    let mut kdf_params_map = Map::new();
    let base: u32 = 2; // an explicit type is required
    kdf_params_map.insert("n".to_string(), Value::String(base.pow(log_n.into()).to_string()));
    kdf_params_map.insert("p".to_string(), Value::String(p.to_string()));
    kdf_params_map.insert("r".to_string(), Value::String(r.to_string()));
    kdf_params_map.insert("dklen".to_string(), Value::String(DK_LEN.to_string()));
    kdf_params_map.insert("salt".to_string(), Value::String(hex::encode(salt)));
    crypto.insert("kdf_params".to_string(), Value::Object(kdf_params_map));

    let store = KeyStore{
        version: 3,
        id: &uuid,
        address: &hex::encode(eth_address),
        crypto: &crypto,
    };
    serialize(&store);
}