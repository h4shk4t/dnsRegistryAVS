use jsonrpc_core::{IoHandler, Params, Error, ErrorCode};
use jsonrpc_http_server::ServerBuilder;

use serde_json::{Value, json};
use regex::Regex;
use hickory_resolver::{config::ResolverOpts, TokioAsyncResolver};
use hickory_client::rr::RecordType;
use hickory_resolver::config::ResolverConfig;

// curl -s "https://cloudflare-dns.com/dns-query?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"
// curl -s "https://dns.quad9.net/dns-query?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"
// curl -s "https://dns.nextdns.io?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"
// curl -s "https://doh.opendns.com/dns-query?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"
// curl -s "https://doh.cleanbrowsing.org/doh/family-filter/?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"

#[tokio::main]
async fn main() {

    let mut io = IoHandler::default();

    io.add_method("get_dkim_public_key", |params: Params| async {
        match handle_get_dkim_public_key(params).await {
            Ok(result) => Ok(result),
            Err(err) => {
                let message = format!("Error fetching DKIM public key: {}", err);
                Err(Error {
                    code: ErrorCode::ServerError(-32001),  // Custom error code
                    message,
                    data: None,  // Optional: you could add additional error data here
                })
            }
        }
    });

    // Spin up Server
    let server = ServerBuilder::new(io)
        .threads(3)
        .start_http(&"0.0.0.0:3030".parse().unwrap())
        .unwrap();

    println!("Execution Service server running on port 3030");
    server.wait();
}

// Your function remains largely unchanged, except for the error type in the return signature
async fn get_dkim_public_key(
    selector: String,
    domain: String,
) -> Result<Value, Box<dyn std::error::Error>> {
    let resolver_config = ResolverConfig::quad9();
    let resolver_opts = ResolverOpts::default();
    
    let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);

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
                                        return Ok(Value::Object(
                                            serde_json::map::Map::from_iter(vec![
                                                ("proof_of_task".to_string(), Value::String(pubkey.to_string())),
                                                // Add data object which has an nested object with "transaction hash"
                                                ("data".to_string(), Value::Object(
                                                    serde_json::map::Map::from_iter(vec![
                                                        ("transaction_hash".to_string(), Value::String("0x1234567890abcdef".to_string())),
                                                    ])
                                                )),
                                                ("task_definition_id".to_string(), Value::Number(0.into())),
                                                ("signature".to_string(), Value::String("Some signed value".to_string())),
                                                ("performer_address".to_string(), Value::String("from_env".to_string())),
                                            ])
                                        )
                                    );
                                    }
                                }
                            },
                            Err(_) => {
                                eprintln!("Invalid UTF-8 sequence in TXT record");
                                return Err("Invalid UTF-8 sequence in TXT record".into());
                            },
                        
                        }
                    }
                }
            }
            Err("DKIM public key not found".into())
        },
        Err(err) => {
            eprintln!("DNS query failed: {:?}", err);
            return Err(err.into());
        }
    }
}

// Wrapper function to parse Params and call your async function
async fn handle_get_dkim_public_key(params: Params) -> Result<Value, Box<dyn std::error::Error>> {
    let (selector, domain): (String, String) = match params.parse(){
        Ok((selector, domain)) => (selector, domain),
        Err(err) => {
            println!("Error: {}", err);
            return Err(err.into())
        }
    };
    // Attempt to get the DKIM public key
    match get_dkim_public_key(selector, domain).await {
        Ok(public_key) => Ok(public_key),
        Err(err) => {
            println!("Error: {}", err);
            return Err(err.into())
        },
    }
}