use reqwest::Client;
use serde_json::Value;
use regex::Regex;


// curl -s "https://cloudflare-dns.com/dns-query?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"
// curl -s "https://dns.quad9.net/dns-query?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"
// curl -s "https://dns.nextdns.io?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"
// curl -s "https://doh.opendns.com/dns-query?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"
// curl -s "https://doh.cleanbrowsing.org/doh/family-filter/?name=<selector>._domainkey.<domain>&type=TXT" -H "Accept: application/dns-json"


#[tokio::main]
async fn get_dkim_public_key(
    selector: String,
    domain: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let hosts = vec!["dns.google", "dns.cloudflare", "dns.quad9"];
    let mut pubkey_found = false;

    for host in hosts {
        let url = format!("https://{}/resolve?name={}._domainkey.{}&type=TXT", host, selector, domain);

        let client = Client::new();
        let res = client.get(&url).send().await?.text().await?;

        let body_json: Value = serde_json::from_str(&res)?;
        let answers = body_json["Answer"].as_array().ok_or("No 'Answer' field found in response")?;

        for answer in answers {
            let data = answer["data"].as_str().unwrap_or("");
            if Regex::new("k=rsa").unwrap().is_match(data) {
                if let Some(pubkey_base64) = Regex::new("p=([A-Za-z0-9+/=]+)").unwrap().captures(data) {
                    let pubkey = pubkey_base64.get(1).map_or("", |m| m.as_str());
                    println!("Public key (base64): {}", pubkey);
                    pubkey_found = true;
                    break;
                }
            }
        }

        if pubkey_found {
            break;
        }
    }

    if pubkey_found {
        Ok(())
    } else {
        Err("No RSA public key found".into())
    }
}

// Call get_dkim_public_key in main function
fn main() {
    let selector = "mail".to_string();
    let domain = "sdslabs.co".to_string();
    // let client = 0;
    match get_dkim_public_key(selector, domain) {
        Ok(_) => println!("Success"),
        Err(e) => eprintln!("Error: {}", e),
    }
}