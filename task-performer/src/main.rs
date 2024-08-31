use ethers::abi::Token;
use ethers::utils::hex;
use tokio::time::Duration;
use serde_json::json;
use dotenvy::dotenv;
use std::env;
use ethers::signers::{LocalWallet, Signer};
use ethers::{utils, prelude::*};
use ethers::utils::hex::encode as hex_encode;
use serde::Serialize;

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
}

// Call jsonRPC get_dkim_public_key every 60 seconds
async fn call_get_dkim_key() -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let url = "http://10.8.0.43:4003";
    // let url = "http://localhost:3030";
    let res = client
        .post(url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "get_dkim_public_key",
            "params": ["20230601", "gmail.com"],
            "id": 1
        }))
        .send()
        .await;
    match res {
        Ok(res) => {
            let body = res.text().await.unwrap();
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            let proof_of_task = json["result"].as_str().unwrap();
            return Ok(proof_of_task.to_string());
        }
        Err(e) => {
            println!("Error: {:?}", e);
            return Err(e.into());
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>{
    dotenv().ok();

    // Read the private key from the environment variable
    let private_key = env::var("PRIVATE_KEY")
        .expect("PRIVATE_KEY must be set in .env file");
    println!("Private key: {}", private_key);

    let wallet: LocalWallet = private_key.parse::<LocalWallet>()?;
    let performer_address = wallet.address();
    println!("Performer address: {:?}", performer_address);

    println!("Calling get_dkim_key every 60 seconds");
    println!("Additional 10 second timeout for aggregator to spin up");
    tokio::time::sleep(Duration::from_secs(10)).await;
    let mut increment = 0;
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        increment += 1;
        println!("Interval: {}", increment);
        interval.tick().await;
        match call_get_dkim_key().await {
            Ok(proof_of_task) => {
                println!("Proof of task: {}", proof_of_task);
                let client = reqwest::Client::new();
                let url = "http://10.8.0.69:8545";
                // let url = "https://hashkat.free.beeceptor.com";
                let data = "0x1234567890abcdef";
                let data_bytes = data.as_bytes();
                let data_hex = hex_encode(data_bytes);
                let task_definition_id = 0;
                let encoded_message = ethers::abi::encode(&[
                    Token::String(proof_of_task.clone()),
                    Token::Bytes(hex::decode(data_hex).unwrap()),
                    Token::Address(performer_address),
                    Token::Uint(U256::from(task_definition_id)),
                ]);
                // Hash the encoded message using keccak256
                let message_hash = utils::keccak256(&encoded_message);

                // Sign the hashed message
                let signature = wallet.sign_message(&message_hash).await?;

                let serialized_signature = signature.to_vec();
                let serialized_signature_hex = hex_encode(&serialized_signature);
                // EC recover in js/solidity
                // Pass message hash and signature to the smart contract
                // This should return the address that has signed the message hash
                println!("Serialized Signature: {:?}", serialized_signature_hex);
                let json_rpc_body = JsonRpcRequest {
                    jsonrpc: "2.0".to_string(),
                    method: "sendTask".to_string(),
                    params: vec![
                        json!(proof_of_task),
                        json!(data),
                        json!(task_definition_id),
                        json!(performer_address),
                        json!(serialized_signature_hex),
                    ],
                };
                let res = client
                    .post(url)
                    .json(&json_rpc_body)
                    .send()
                    .await;
                match res {
                    Ok(res) => {
                        let body = res.text().await.unwrap();
                        println!("Body: {}", body);
                        ()
                    }
                    Err(e) => {
                        println!("Error: {:?}", e);
                        return Err(e.into());
                    }
                }
            },
            Err(e) => {
                println!("Error: {:?}", e);
                return Err(e.into());
            }
        }
    }
}
