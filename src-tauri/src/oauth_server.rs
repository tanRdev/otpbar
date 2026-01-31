use http_body_util::Full;
use hyper::Method;
use hyper::{server::conn::http1, service::service_fn, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Notify};

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
    <meta charset="UTF-8">
    <title>Signed In</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: linear-gradient(135deg, #1a1a1a 0%, #0a0a0a 100%);
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 48px;
        }
        .icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 24px;
            background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 40px rgba(34, 197, 94, 0.3);
        }
        .icon svg {
            width: 32px;
            height: 32px;
            stroke: white;
            stroke-width: 3;
            fill: none;
        }
        h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
            letter-spacing: -0.02em;
        }
        p {
            color: rgba(255,255,255,0.5);
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"></polyline></svg>
        </div>
        <h1>Signed In</h1>
        <p>You can close this tab.</p>
    </div>
    <script>setTimeout(() => window.close(), 2000);</script>
</body>
</html>
    "#
    .to_string()
}

fn error_html(error: &str) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Sign In Failed</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: linear-gradient(135deg, #1a1a1a 0%, #0a0a0a 100%);
            color: #fff;
        }}
        .container {{
            text-align: center;
            padding: 48px;
            max-width: 400px;
        }}
        .icon {{
            width: 64px;
            height: 64px;
            margin: 0 auto 24px;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 40px rgba(239, 68, 68, 0.3);
        }}
        .icon svg {{
            width: 32px;
            height: 32px;
            stroke: white;
            stroke-width: 3;
            fill: none;
        }}
        h1 {{
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
            letter-spacing: -0.02em;
        }}
        p {{
            color: rgba(255,255,255,0.5);
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
        </div>
        <h1>Sign In Failed</h1>
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
    code_received: Arc<Notify>,
}

impl OAuthServer {
    pub async fn start(port: u16) -> Result<Self, String> {
        let (code_tx, code_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let code_tx = Arc::new(Mutex::new(Some(code_tx)));
        let code_received = Arc::new(Notify::new());
        let code_received_clone = Arc::clone(&code_received);

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
                                let notify = Arc::clone(&code_received_clone);

                                let service = service_fn(move |req| {
                                    let tx = Arc::clone(&tx_arc);
                                    let n = Arc::clone(&notify);
                                    async move {
                                        let res = handle_callback(req, tx).await;
                                        n.notify_one();
                                        res
                                    }
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
                    _ = code_received_clone.notified() => {
                        break;
                    }
                }
            }
        });

        Ok(OAuthServer {
            shutdown_tx: Some(shutdown_tx),
            code_rx,
            code_received,
        })
    }

    pub async fn wait_for_code(&mut self) -> Result<String, String> {
        tokio::time::timeout(tokio::time::Duration::from_secs(300), &mut self.code_rx)
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
