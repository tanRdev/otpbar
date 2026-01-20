use hyper::{
    server::conn::http1,
    service::service_fn,
    Request, Response, StatusCode,
};
use hyper::Method;
use hyper_util::rt::TokioIo;
use http_body_util::Full;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

type BoxBody = http_body_util::Full<hyper::body::Bytes>;

fn html_response(html: String) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Full::new(html.into()))
        .unwrap()
}

fn success_html() -> String {
    r#"
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }
        .container {
            text-align: center;
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.1);
        }
        h1 { color: #333; margin-bottom: 10px; }
        p { color: #666; }
        .checkmark {
            font-size: 48px;
            color: #4CAF50;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark">✓</div>
        <h1>Authorization Successful</h1>
        <p>You can close this window and return to the app.</p>
    </div>
</body>
</html>
    "#.to_string()
}

fn error_html(error: &str) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Error</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }}
        .container {{
            text-align: center;
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.1);
        }}
        h1 {{ color: #d32f2f; margin-bottom: 10px; }}
        p {{ color: #666; }}
        .error {{ font-size: 48px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error">✕</div>
        <h1>Authorization Failed</h1>
        <p>{}</p>
    </div>
</body>
</html>
        "#,
        error
    )
}

async fn handle_callback(
    req: Request<hyper::body::Incoming>,
    tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let path = req.uri().path();
    let query = req.uri().query().unwrap_or("");

    if path == "/callback" && req.method() == Method::GET {
        let params: std::collections::HashMap<String, String> = query
            .split('&')
            .filter_map(|s| {
                let mut parts = s.splitn(2, '=');
                Some((parts.next()?.to_string(), parts.next()?.to_string()))
            })
            .collect();

        if let Some(code) = params.get("code") {
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send(code.clone());
            }
            return Ok(html_response(success_html()));
        }

        if let Some(error) = params.get("error") {
            return Ok(html_response(error_html(error)));
        }

        return Ok(html_response(error_html("No authorization code received")));
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new("Not Found".into()))
        .unwrap())
}

pub struct OAuthServer {
    shutdown_tx: Option<oneshot::Sender<()>>,
    code_rx: oneshot::Receiver<String>,
}

impl OAuthServer {
    pub async fn start(port: u16) -> Result<Self, String> {
        let (code_tx, code_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let code_tx = Arc::new(Mutex::new(Some(code_tx)));

        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        tokio::spawn(async move {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| format!("Failed to bind to port {}: {}", port, e));

            let listener = match listener {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("OAuth server error: {}", e);
                    return;
                }
            };

            let code_tx_clone: Arc<Mutex<Option<oneshot::Sender<String>>>> = Arc::clone(&code_tx);
            let mut shutdown_rx = Some(shutdown_rx);

            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let io = TokioIo::new(stream);
                                let tx_arc = Arc::clone(&code_tx_clone);

                                let service = service_fn(move |req| {
                                    handle_callback(req, Arc::clone(&tx_arc))
                                });

                                tokio::task::spawn(async move {
                                    let _ = http1::Builder::new()
                                        .serve_connection(io, service)
                                        .await;
                                });
                            }
                            Err(e) => {
                                eprintln!("Accept error: {}", e);
                            }
                        }
                    }
                    _ = async { shutdown_rx.as_mut().unwrap().await } => {
                        break;
                    }
                    _ = {
                        async {
                            loop {
                                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                                let tx = code_tx.lock().unwrap();
                                if tx.is_none() {
                                    break;
                                }
                                drop(tx);
                            }
                        }
                    } => {
                        break;
                    }
                }
            }
        });

        Ok(OAuthServer {
            shutdown_tx: Some(shutdown_tx),
            code_rx,
        })
    }

    pub async fn wait_for_code(&mut self) -> Result<String, String> {
        tokio::time::timeout(
            tokio::time::Duration::from_secs(300),
            &mut self.code_rx,
        )
        .await
        .map_err(|_| "Timeout waiting for authorization".to_string())?
        .map_err(|_| "Channel closed".to_string())
    }
}

impl Drop for OAuthServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}
