use ::http::HeaderValue;
use reqwest::Certificate;
use std::marker::PhantomData;

use loam_sdk::http;
use loam_sdk_networking::rpc;

#[derive(Debug, Default, Clone)]
pub struct ClientOptions {
    pub additional_root_certs: Vec<Certificate>,
}

#[derive(Clone, Debug, Default)]
pub struct Client<F: rpc::Service> {
    // reqwest::Client holds a connection pool. It's reference-counted
    // internally, so this field is relatively cheap to clone.
    http: reqwest::Client,
    _phantom_data: PhantomData<F>,
}

impl<F: rpc::Service> Client<F> {
    pub fn new(options: ClientOptions) -> Self {
        let mut b = reqwest::Client::builder().use_rustls_tls();
        for c in options.additional_root_certs {
            b = b.add_root_certificate(c);
        }
        Self {
            http: b.build().expect("TODO"),
            _phantom_data: PhantomData {},
        }
    }
}

impl<F: rpc::Service> http::Client for Client<F> {
    fn send(
        &self,
        request: http::Request,
        callback: Box<dyn FnOnce(Option<http::Response>) + Send>,
    ) {
        let mut request_builder = match request.method {
            http::Method::Get => self.http.get(request.url),
            http::Method::Put => self.http.put(request.url),
            http::Method::Post => self.http.post(request.url),
            http::Method::Delete => self.http.delete(request.url),
        };

        let mut headers = reqwest::header::HeaderMap::new();
        for (key, value) in request.headers {
            headers.extend(
                key.parse::<reqwest::header::HeaderName>()
                    .map_err(|_| ())
                    .and_then(|header_name| {
                        HeaderValue::from_str(&value)
                            .map(|header_value| (header_name, header_value))
                            .map_err(|_| ())
                    }),
            );
        }
        request_builder = request_builder.headers(headers);

        if let Some(body) = request.body {
            request_builder = request_builder.body(body);
        }

        tokio::spawn(async {
            match request_builder.send().await {
                Err(_) => callback(None),
                Ok(response) => {
                    let status = response.status().as_u16();
                    match response.bytes().await {
                        Err(_) => callback(None),
                        Ok(bytes) => callback(Some(http::Response {
                            status: http::ResponseStatus::from(status),
                            bytes: bytes.to_vec(),
                        })),
                    }
                }
            }
        });
    }
}
