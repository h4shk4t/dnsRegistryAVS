use axum::{
    // body::Body,
    // http::StatusCode,
    // response::{IntoResponse, Response},
    routing::post, 
    extract::Json,
    Router
};
use serde::Deserialize;

// const jsonRpcBody = {
//     jsonrpc: "2.0",
//     method: "sendTask",
//     params: [proofOfTask, data, taskDefinitionId, performerAddress, sig],
//   };

#[derive(Deserialize)]
struct SendTask{
    proof_of_task: String,
    data: String,
    task_definition_id: String,
    performer_address: String,
}

async fn validate(Json(send_task): Json<SendTask>) -> String {
    println!("json_rpc_body: {:?}", send_task.proof_of_task);
    println!("json_rpc_body: {:?}", send_task.data);
    println!("json_rpc_body: {:?}", send_task.task_definition_id);
    println!("json_rpc_body: {:?}", send_task.performer_address);
    format!("json_rpc_body: {:?}", send_task.proof_of_task)
}

#[tokio::main]
async fn main(){
    let app = Router::new()
    .route("/validate",post(validate));

    println!("Running on http://localhost:3000");
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}