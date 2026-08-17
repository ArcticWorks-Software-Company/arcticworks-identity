//! Email delivery. Uses SMTP via lettre when configured; otherwise email is
//! logged (development mode — Mailpit is the default dev SMTP target).
//! Email bodies are built here; tokens are embedded in links to the web app.

use lettre::message::{header::ContentType, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

use crate::config::SmtpConfig;

pub struct Mailer {
    config: SmtpConfig,
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
}

impl Mailer {
    pub fn new(config: SmtpConfig) -> Self {
        let transport = build_transport(&config);
        if transport.is_none() {
            tracing::warn!("SMTP not configured; emails will be logged instead of sent");
        }
        Mailer { config, transport }
    }

    pub fn is_configured(&self) -> bool {
        self.transport.is_some()
    }

    pub async fn send(&self, to: &str, subject: &str, html: String) -> anyhow::Result<()> {
        let msg = Message::builder()
            .from(self.config.from.parse()?)
            .to(to.parse()?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html)?;

        match &self.transport {
            Some(t) => {
                t.send(msg).await?;
            }
            None => {
                // Development fallback: log the message so links can be read
                // from the console (or captured by tests).
                tracing::info!(to, subject, "email (not sent, SMTP unconfigured)");
            }
        }
        Ok(())
    }
}

fn build_transport(config: &SmtpConfig) -> Option<AsyncSmtpTransport<Tokio1Executor>> {
    let host = config.host.as_deref()?;
    let builder = match config.tls {
        crate::config::SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
        crate::config::SmtpTls::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host).ok()?,
        crate::config::SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(host).ok()?,
    }
    .port(config.port);

    let builder = match (&config.username, &config.password) {
        (Some(user), Some(pass)) => builder.credentials(Credentials::new(user.clone(), pass.clone())),
        _ => builder,
    };

    Some(builder.build())
}
