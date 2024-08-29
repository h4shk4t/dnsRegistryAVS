use axum::{
    routing::post,
    Json, Router,
};

use serde::Deserialize;
use serde_json::Value;
use regex::Regex;
use hickory_resolver::{config::ResolverOpts, TokioAsyncResolver};
use hickory_client::rr::RecordType;
use hickory_resolver::config::ResolverConfig;
// const jsonRpcBody = {
//     jsonrpc: "2.0",
//     method: "sendTask",
//     params: [proofOfTask, data, taskDefinitionId, performerAddress, sig],
//   };

#[derive(Deserialize)]
struct JsonRpcBody {
    jsonrpc: String,
    method: String,
    params: Vec<String>,
}

// async fn validate(Json(send_task): Json<SendTask>) -> String {
//     println!("json_rpc_body: {:?}", send_task.proof_of_task);
//     println!("json_rpc_body: {:?}", send_task.data);
//     println!("json_rpc_body: {:?}", send_task.task_definition_id);
//     println!("json_rpc_body: {:?}", send_task.performer_address);
//     format!("json_rpc_body: {:?}", send_task.proof_of_task)
// }

// curl -s "https://cloudflare-dns.com/dns-query?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"
// curl -s "https://dns.quad9.net/dns-query?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"
// curl -s "https://dns.nextdns.io?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"
// curl -s "https://doh.opendns.com/dns-query?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"
// curl -s "https://doh.cleanbrowsing.org/doh/family-filter/?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/task/validate", post(handle_validate_dkim_key));
    println!("Running on http://localhost:4002");
    // Start Server
    axum::Server::bind(&"127.0.0.1:4002".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
    Ok(())
}



// Your function remains largely unchanged, except for the error type in the return signature
async fn validate_dkim_public_key(
    selector: String,
    domain: String,
    proof_of_task: String
) -> Result<Value, Box<dyn std::error::Error>> {
    let resolver_config = ResolverConfig::quad9();
    let resolver_opts = ResolverOpts::default();
    
    let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);

    // let selector = "mail".to_string();
    // let domain = "sdslabs.co".to_string();
    let dkim_name = format!("{}._domainkey.{}", selector, domain);

    match resolver.lookup(dkim_name, RecordType::TXT).await {
        Ok(response) => {
            for record in response{
                if let hickory_client::rr::RData::TXT(txt) = record {
                    let txt_data = txt.txt_data();
                    for data in txt_data.iter() {
                        // Convert the byte slice to a UTF-8 string
                        match std::str::from_utf8(&data) {
                            Ok(text) => {
                                if Regex::new("k=rsa").unwrap().is_match(text) {
                                    if let Some(pubkey_base64) = Regex::new("p=([A-Za-z0-9+/=]+)").unwrap().captures(text) {
                                        let pubkey = pubkey_base64.get(1).map_or("", |m| m.as_str());
                                        println!("Public key (base64): {}", pubkey);
                                        return Ok(Value::Bool(pubkey == proof_of_task));
                                    }
                                }
                            },
                            Err(_) => {
                                eprintln!("Invalid UTF-8 sequence in TXT record");
                                return Ok(Value::Bool(false));
                            },
                        
                        }
                    }
                }
            }
            eprintln!("DKIM public key not found");
            return Ok(Value::Bool(false));
        },
        Err(err) => {
            eprintln!("DNS query failed: {:?}", err);
            return Err(err.into());
        }
    }
}

// Wrapper function to parse Params and call your async function
async fn handle_validate_dkim_key(Json(rpc_body): Json<JsonRpcBody>) -> bool {
//     params: [proofOfTask, data, taskDefinitionId, performerAddress, sig],
    let proof_of_task = rpc_body.params[0].clone();
    let data = rpc_body.params[1].clone();
    let task_definition_id = rpc_body.params[2].clone();
    let performer_address = rpc_body.params[3].clone();
    let sig = rpc_body.params[4].clone();
    // Attempt to get the DKIM public key
    let selector = "20230601".to_string();
    let domain = "gmail.com".to_string();
    match validate_dkim_public_key(selector, domain, proof_of_task).await {
        Ok(is_approved) => is_approved.as_bool().unwrap_or(false),
        Err(err) => {
            println!("Error: {}", err);
            false
        },
    }
}