use async_trait::async_trait;
use gcp_auth::AuthenticationManager;
use google::auth::AuthMiddleware;
use google::pubsub::v1::publisher_client::PublisherClient;
use google::pubsub::v1::subscriber_client::SubscriberClient;
use google::pubsub::v1::{
    ExpirationPolicy, PublishRequest, PublishResponse, PubsubMessage, Subscription, Topic,
};
use google::GrpcConnectionOptions;
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use tonic::transport::{Endpoint, Uri};
use tonic::{Code, Status};
use tracing::{info, instrument, warn};

use juicebox_realm_api::types::RealmId;
use observability::{metrics, metrics_tag as tag};
use pubsub_api::Message;
use retry_loop::{retry_logging, AttemptError, Retry, RetryError};

pub struct Publisher {
    project: String,
    pub_client: PublisherClient<AuthMiddleware>,
    sub_client: SubscriberClient<AuthMiddleware>,
    metrics: metrics::Client,
}

impl std::fmt::Debug for Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Publisher")
            .field("project", &self.project)
            .finish_non_exhaustive()
    }
}

impl Publisher {
    pub async fn new(
        service_url: Option<Uri>,
        project: String,
        auth: Option<AuthenticationManager>,
        metrics: metrics::Client,
        options: GrpcConnectionOptions,
    ) -> Result<Self, tonic::transport::Error> {
        let url = service_url.unwrap_or(Uri::from_static("https://pubsub.googleapis.com"));
        let endpoint = options.apply(Endpoint::from(url.clone())).connect().await?;
        let channel = AuthMiddleware::new(
            endpoint,
            auth,
            &["https://www.googleapis.com/auth/pubsub"],
            metrics.clone(),
        );

        let pub_client = PublisherClient::new(channel.clone());
        let sub_client = SubscriberClient::new(channel);
        Ok(Publisher {
            project,
            pub_client,
            sub_client,
            metrics,
        })
    }
}

#[async_trait]
impl pubsub_api::Publisher for Publisher {
    #[instrument(level = "trace", skip(self, m))]
    async fn publish(
        &self,
        realm: RealmId,
        tenant: &str,
        m: Message,
    ) -> Result<(), Box<dyn Error>> {
        let pub_req = PublishRequest {
            topic: topic_name(&self.project, realm, tenant),
            messages: vec![PubsubMessage {
                data: m.0.to_string().into_bytes(),
                attributes: HashMap::new(),
                message_id: String::from(""),
                publish_time: None,
                ordering_key: String::from(""),
            }],
        };
        let tags = [tag!(?realm)];
        match self.publish_msg(pub_req.clone(), &tags).await {
            Err(RetryError::Fatal { error }) if error.code() == Code::NotFound => {
                warn!(
                    ?realm,
                    ?tenant,
                    "tenant topic not found, attempting to create it"
                );
                self.create_topic_and_sub(realm, tenant, &tags).await?;
                self.publish_msg(pub_req, &tags).await?;
                Ok(())
            }
            Err(err) => Err(err.into()),
            Ok(_) => Ok(()),
        }
    }
}

pub fn topic_name(project: &str, realm: RealmId, tenant: &str) -> String {
    format!("projects/{}/topics/tenant-{}-{:?}", project, tenant, realm)
}

pub fn subscription_name(project: &str, realm: RealmId, tenant: &str) -> String {
    format!(
        "projects/{}/subscriptions/tenant-{}-{:?}-sub",
        project, tenant, realm
    )
}

impl Publisher {
    async fn publish_msg(
        &self,
        req: PublishRequest,
        tags: &[metrics::Tag],
    ) -> Result<PublishResponse, RetryError<Status>> {
        Retry::new("publishing to Google PubSub")
            .with(pubsub_retries)
            .with_metrics(&self.metrics, "pubsub.publish_msg", tags)
            .retry(
                |_| async {
                    let mut pc = self.pub_client.clone();
                    match pc.publish(req.clone()).await {
                        Ok(response) => Ok(response.into_inner()),
                        Err(err) => Err(inspect_grpc_error(err)),
                    }
                },
                retry_logging!(),
            )
            .await
    }

    async fn create_topic(
        &self,
        topic: Topic,
        tags: &[metrics::Tag],
    ) -> Result<tonic::Response<Topic>, RetryError<Status>> {
        Retry::new("creating topic in Google PubSub")
            .with(pubsub_retries)
            .with_metrics(&self.metrics, "pubsub.create_topic", tags)
            .retry(
                |_| async {
                    let mut pc = self.pub_client.clone();
                    pc.create_topic(topic.clone())
                        .await
                        .map_err(inspect_grpc_error)
                },
                retry_logging!(),
            )
            .await
    }

    async fn create_subscription(
        &self,
        sub: Subscription,
        tags: &[metrics::Tag],
    ) -> Result<tonic::Response<Subscription>, RetryError<Status>> {
        Retry::new("creating subscription in Google PubSub")
            .with(pubsub_retries)
            .with_metrics(&self.metrics, "pubsub.create_subscription", tags)
            .retry(
                |_| async {
                    let mut sc = self.sub_client.clone();
                    sc.create_subscription(sub.clone())
                        .await
                        .map_err(inspect_grpc_error)
                },
                retry_logging!(),
            )
            .await
    }

    #[instrument(level = "trace", skip(self))]
    async fn create_topic_and_sub(
        &self,
        realm: RealmId,
        tenant: &str,
        tags: &[metrics::Tag],
    ) -> Result<(), RetryError<Status>> {
        let labels = HashMap::from([
            (String::from("realm"), format!("{realm:?}")),
            (String::from("tenant"), tenant.to_owned()),
        ]);
        match self
            .create_topic(
                Topic {
                    name: topic_name(&self.project, realm, tenant),
                    labels: labels.clone(),
                    message_storage_policy: None,
                    kms_key_name: String::from(""),
                    schema_settings: None,
                    satisfies_pzs: false,
                    message_retention_duration: None,
                },
                tags,
            )
            .await
        {
            Err(RetryError::Fatal { error }) if error.code() == Code::AlreadyExists => {
                // We can end up concurrently trying to create the same topic, that's ok.
                info!(?realm, ?tenant, "topic for tenant already exists");
            }
            Err(err) => {
                // retry loop already warned
                return Err(err);
            }
            Ok(_) => {
                info!(?realm, ?tenant, "created topic for tenant");
            }
        }

        match self
            .create_subscription(
                Subscription {
                    name: subscription_name(&self.project, realm, tenant),
                    topic: topic_name(&self.project, realm, tenant),
                    push_config: None,
                    bigquery_config: None,
                    cloud_storage_config: None,
                    ack_deadline_seconds: 10,
                    retain_acked_messages: false,
                    message_retention_duration: None,
                    labels,
                    enable_message_ordering: false,
                    expiration_policy: Some(ExpirationPolicy { ttl: None }),
                    filter: String::from(""),
                    dead_letter_policy: None,
                    retry_policy: None,
                    detached: false,
                    enable_exactly_once_delivery: true,
                    // These 2 fields are output only, it doesn't matter what
                    // they're set to here.
                    topic_message_retention_duration: None,
                    state: 0,
                },
                tags,
            )
            .await
        {
            Err(RetryError::Fatal { error }) if error.code() == Code::AlreadyExists => {
                // We can end up concurrently trying to create the same
                // subscription, that's ok.
                info!(?realm, ?tenant, "subscription for tenant already exists");
                Ok(())
            }
            Err(err) => {
                // retry loop already warned
                Err(err)
            }
            Ok(_) => {
                info!(?realm, ?tenant, "created subscription for tenant");
                Ok(())
            }
        }
    }
}

/// Configures a retry loop with reasonable defaults for PubSub requests.
fn pubsub_retries(retry: Retry) -> Retry {
    retry
        .with_exponential_backoff(Duration::from_millis(50), 2.0, Duration::from_secs(2))
        .with_max_attempts(50)
        .with_timeout(Duration::from_secs(30))
}

/// Classifies a gRPC error as retryable and extracts its tags.
///
/// TODO: This is a fork of `bigtable::inspect_grpc_error`. Should they be
/// combined?
fn inspect_grpc_error(error: tonic::Status) -> AttemptError<tonic::Status> {
    let may_retry = matches!(
        error.code(),
        Code::DeadlineExceeded |
            // TODO: this seemed to be a bug in hyper, in that it didn't handle RST
            // properly. That was fixed according to
            // <https://github.com/hyperium/hyper/issues/2872>. Does this happen
            // anymore?
            Code::Internal |
            Code::ResourceExhausted |
            // Bad Gateway is reported as:
            // ```
            // "err":"Status { code: Unavailable, message: \"502:Bad Gateway\" // bunch of useless stuff }
            // ```
            // The Pub/Sub docs explictly say to retry 502 errors.
            Code::Unavailable |
            Code::Unknown
    );
    let tags = vec![tag!("kind": "grpc"), tag!("grpc_code": error.code())];
    if may_retry {
        AttemptError::Retryable { error, tags }
    } else {
        AttemptError::Fatal { error, tags }
    }
}
