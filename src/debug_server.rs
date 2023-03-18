use futures::Future;
use hyper::rt::Executor;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Response, Server};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::error;

use crate::ports::PortHandler;
use crate::spawn;

#[derive(Clone)]
struct NamedExecutor;
impl<T: Send + 'static, Fut: Future<Output = T> + Send + 'static> Executor<Fut> for NamedExecutor {
    fn execute(&self, fut: Fut) {
        spawn("http worker", fut);
    }
}

pub async fn debug_server(addr: SocketAddr, port_handler: Arc<Mutex<PortHandler>>) {
    let server = Server::bind(&addr)
        .executor(NamedExecutor)
        .serve(make_service_fn(move |_conn| {
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
    if let Err(error) = server.await {
        error!(%error, "debug server error");
    }
}
