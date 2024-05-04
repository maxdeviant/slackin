import slackin/authentication.{
  SigningSecret, XSlackRequestTimestamp, XSlackSignature,
}
import startest.{describe, it}
import startest/expect

pub fn verify_slack_request_tests() {
  describe("slackin/authentication", [
    describe("verify_slack_request", [
      describe("given a valid Slack request", [
        it("returns Ok", fn() {
          let signing_secret = SigningSecret("8f742231b10e8888abcd99yyyzzz85a5")
          let signature =
            XSlackSignature(
              "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
            )
          let timestamp = XSlackRequestTimestamp(1_531_420_618)

          let body =
            "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c"

          authentication.verify_slack_request(
            signing_secret,
            signature,
            timestamp,
            body,
          )
          |> expect.to_be_ok
        }),
      ]),
      describe("given a Slack request where the body has been manipulated", [
        it("returns an Error", fn() {
          let signing_secret = SigningSecret("8f742231b10e8888abcd99yyyzzz85a5")
          let signature =
            XSlackSignature(
              "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
            )
          let timestamp = XSlackRequestTimestamp(1_531_420_618)

          let body =
            "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=hackercorp&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c"

          authentication.verify_slack_request(
            signing_secret,
            signature,
            timestamp,
            body,
          )
          |> expect.to_be_error
        }),
      ]),
    ]),
  ])
}
