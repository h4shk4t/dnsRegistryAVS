use axum::{
    routing::post,
    Json, Router,
    http::StatusCode
};
use serde::Deserialize;
use serde_json::Value;
use regex::Regex;
use hickory_resolver::{config::ResolverOpts, TokioAsyncResolver};
use hickory_client::rr::RecordType;
use hickory_resolver::config::ResolverConfig;
// {
//     "proofOfTask": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAntvSKT1hkqhKe0xcaZ0x+QbouDsJuBfby/S82jxsoC/SodmfmVs2D1KAH3mi1AqdMdU12h2VfETeOJkgGYq5ljd996AJ7ud2SyOLQmlhaNHH7Lx+Mdab8/zDN1SdxPARDgcM7AsRECHwQ15R20FaKUABGu4NTbR2fDKnYwiq5jQyBkLWP+LgGOgfUF4T4HZb2",
//     "data": "0x1234567890abcdef",
//     "taskDefinitionId": 0,
//     "performer": "0x164214987558fff053c5815abc6effec632eee75"
// }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestBody {
    proof_of_task: String,
    data: String,
    task_definition_id: u64,
    performer: String,
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
    println!("Running on http://10.8.0.42:4002");
    // Start Server
    axum::Server::bind(&"0.0.0.0:4002".parse().unwrap())
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
async fn handle_validate_dkim_key(
    Json(rpc_body): Json<RequestBody>,
) -> Result<Json<Value>, StatusCode> {
    // JSON Body parameters are in camelcase, parse it into snake case
    let proof_of_task = rpc_body.proof_of_task;
    let data = rpc_body.data;
    let task_definition_id = rpc_body.task_definition_id;
    let performer_address = rpc_body.performer;
    // Extract domain and 
    let selector = "20230601".to_string();
    let domain = "gmail.com".to_string();

    match validate_dkim_public_key(selector, domain, proof_of_task).await {
        Ok(is_approved) => Ok(Json(is_approved)),
        Err(err) => {
            println!("Error: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}