defmodule SMTPSubmit.Test.StallingCloseClient do
  @moduledoc false
  # gen_smtp_client with a close/1 that never returns, for testing that cleanup is
  # bounded and cannot change an accepted result. The fake can't stall cleanup
  # itself: gen_smtp's QUIT never waits for a reply.

  defdelegate open(options), to: :gen_smtp_client
  defdelegate deliver(socket, email), to: :gen_smtp_client

  def close(_socket) do
    receive do
      :never -> :ok
    end
  end
end
