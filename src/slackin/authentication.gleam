import gleam/http/request.{type Request}
import gleam/int
import gleam/result.{try}
import slackin/internal/hmac

/// A Slack signing secret.
pub type SigningSecret {
  SigningSecret(String)
}

/// The `X-Slack-Signature` header for a request.
pub type XSlackSignature {
  XSlackSignature(String)
}

/// Reads the `X-Slack-Signature` header from the request.
pub fn read_x_slack_signature(req: Request(a)) -> Result(XSlackSignature, Nil) {
  req
  |> request.get_header("x-slack-signature")
  |> result.map(XSlackSignature)
  |> result.nil_error
}

/// The `X-Slack-Request-Timestamp` header for a request.
pub type XSlackRequestTimestamp {
  XSlackRequestTimestamp(Int)
}

/// Reads the `X-Slack-Request-Timestamp` header from the request.
pub fn read_x_slack_request_timestamp(
  req: Request(a),
) -> Result(XSlackRequestTimestamp, Nil) {
  req
  |> request.get_header("x-slack-request-timestamp")
  |> result.try(int.parse)
  |> result.map(XSlackRequestTimestamp)
  |> result.nil_error
}

/// Verifies an HTTP request from Slack.
///
/// [Slack Docs: Verifying requests from Slack](https://api.slack.com/authentication/verifying-requests-from-slack)
pub fn verify_slack_request(
  signing_secret: SigningSecret,
  x_slack_signature: XSlackSignature,
  x_slack_request_timestamp: XSlackRequestTimestamp,
  body: String,
) -> Result(Nil, Nil) {
  let SigningSecret(signing_secret) = signing_secret
  let XSlackSignature(x_slack_signature) = x_slack_signature
  let XSlackRequestTimestamp(x_slack_request_timestamp) =
    x_slack_request_timestamp

  let version = "v0"
  let timestamp = int.to_string(x_slack_request_timestamp)

  let signature_base = version <> ":" <> timestamp <> ":" <> body
  use hash_digest <- try(hmac.sha256(signing_secret, signature_base))
  let computed_signature = "v0=" <> hash_digest

  case hmac.hash_equals(x_slack_signature, computed_signature) {
    True -> Ok(Nil)
    False -> Error(Nil)
  }
}
