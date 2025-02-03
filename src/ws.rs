use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
};
use futures::{sink::SinkExt, stream::StreamExt};

pub async fn websocket_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| websocket_callback(socket))
}

async fn websocket_callback(socket: WebSocket) {
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
