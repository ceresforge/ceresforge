use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
};

use futures::{sink::SinkExt, stream::StreamExt};

pub async fn handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| callback(socket))
}

async fn callback(socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();
    loop {
        let message = receiver.next().await.unwrap().unwrap();
        match &message {
            Message::Text(_) => match sender.send(message).await {
                Ok(_) => (),
                Err(_) => break,
            },
            _ => break,
        }
    }
}
