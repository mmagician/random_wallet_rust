use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
struct KeyStore {
    version: u8,
    id: String
}

fn serialize(store: &KeyStore ) {
    let serialized: String = serde_json::to_string(&store).unwrap();
    println!("serialized = {}", serialized);
}

fn main() {
    let uuid:String = Uuid::new_v4().to_hyphenated().to_string();
    let store = KeyStore { version: 1, id: uuid };
    serialize(&store);
}