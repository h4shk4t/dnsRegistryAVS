use tokio::time::Duration;
use serde_json::json;

// Call jsonRPC get_dkim_public_key every 60 seconds
async fn call_get_dkim_key() {
    let client = reqwest::Client::new();
    let url = "http://localhost:3030";
    let res = client
        .post(url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "get_dkim_public_key",
            "params": ["mail", "sdslabs.co"],
            "id": 1
        }))
        .send()
        .await;
    match res {
        Ok(res) => {
            let body = res.text().await.unwrap();
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            let proof_of_task = json["result"]["proof_of_task"].as_str().unwrap();
            println!("Proof of task: {}", proof_of_task);
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }
}

#[tokio::main]
async fn main() {
    println!("Calling get_dkim_key every 60 seconds");
    let mut increment = 0;
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        increment += 1;
        println!("Interval: {}", increment);
        interval.tick().await;
        call_get_dkim_key().await;
    }
}
