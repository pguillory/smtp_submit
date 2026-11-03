defmodule SMTPSubmit.ErrorTest do
  use ExUnit.Case, async: true

  alias SMTPSubmit.Error

  test "messages name only the code, stage and safe numbers" do
    assert Exception.message(%Error{code: :auth_failed, stage: :open}) ==
             "SMTP auth_failed during open"

    assert Exception.message(%Error{code: :rejected, stage: :deliver, reply_code: 550}) ==
             "SMTP rejected during deliver (reply 550)"

    assert Exception.message(%Error{code: :timeout, stage: :open, timeout_ms: 120_000}) ==
             "SMTP timeout during open after 120 seconds"
  end

  test "an unknown outcome warns against resending" do
    error = %Error{code: :timeout, stage: :deliver, timeout_ms: 1_500, outcome_unknown?: true}

    assert Exception.message(error) ==
             "SMTP timeout during deliver after 2 seconds. The server may already have " <>
               "accepted the email; do not retry automatically."
  end
end
