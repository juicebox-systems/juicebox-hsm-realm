use http::HeaderValue;
use loam_sdk_core::HttpResponseStatus;
use reqwest::Certificate;
use std::marker::PhantomData;

use loam_sdk::{HttpClient, HttpMethod, HttpRequest, HttpResponse};
use loam_sdk_core::rpc::Service;

#[derive(Debug, Default, Clone)]
pub struct ClientOptions {
    pub additional_root_certs: Vec<Certificate>,
}

#[derive(Clone, Debug, Default)]
pub struct Client<F: Service> {
    // reqwest::Client holds a connection pool. It's reference-counted
    // internally, so this field is relatively cheap to clone.
    http: reqwest::Client,
    _phantom_data: PhantomData<F>,
}

impl<F: Service> Client<F> {
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

impl<F: Service> HttpClient for Client<F> {
    fn send(&self, request: HttpRequest, callback: Box<dyn FnOnce(Option<HttpResponse>) + Send>) {
        let mut request_builder = match request.method {
            HttpMethod::Get => self.http.get(request.url),
            HttpMethod::Put => self.http.put(request.url),
            HttpMethod::Post => self.http.post(request.url),
            HttpMethod::Delete => self.http.delete(request.url),
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
                        Ok(bytes) => callback(Some(HttpResponse {
                            status: HttpResponseStatus::from(status),
                            bytes: bytes.to_vec(),
                        })),
                    }
                }
            }
        });
    }
}
