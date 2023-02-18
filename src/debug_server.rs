use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Response, Server};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::ports::PortHandler;

pub async fn debug_server(addr: SocketAddr, port_handler: Arc<Mutex<PortHandler>>) {
    let server = Server::bind(&addr).serve(make_service_fn(move |_conn| {
        let port_handler = port_handler.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |_req| {
                let port_handler = port_handler.clone();
                async move {
                    Ok::<_, Infallible>(Response::new(Body::from(
                        port_handler.lock().await.status_string(),
                    )))
                }
            }))
        }
    }));

    // Run this server for... forever!
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
