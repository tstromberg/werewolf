# A PostgreSQL socket can exist while recovery is still running. Rails'
# db:prepare must wait for an actual connection before its first attempt.
require 'bundler/setup'
require 'pg'

deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 120
begin
  PG.connect(host: ENV.fetch('DB_HOST'), user: ENV.fetch('DB_USER'),
             dbname: 'postgres', connect_timeout: 3).finish
rescue PG::ConnectionBad => e
  if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
    abort "mastodon: PostgreSQL did not become ready: #{e.message}"
  end

  sleep 1
  retry
end
