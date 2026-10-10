# owner.rb, run by `rails runner` after db:prepare, before Puma serves:
# the owner from the config, made once, as `tootctl accounts create
# --role Owner --confirmed --approve` would, but with the config's
# password, which is never printed; and the streaming server's role,
# which may read the tables and nothing more.
conn = ActiveRecord::Base.connection
stream = conn.quote_column_name('mastodon-stream')
conn.execute("GRANT USAGE ON SCHEMA public TO #{stream}")
conn.execute("GRANT SELECT ON ALL TABLES IN SCHEMA public TO #{stream}")
conn.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO #{stream}")

username = ENV.fetch('MASTODON_OWNER')
return if Account.find_local(username)

password = File.read('/run/svc/mastodon/owner-password').chomp
# The owner's address is the operator's, from the config, not a
# stranger's sign-up: no MX lookup, which a machine whose resolver does
# not know the domain would fail.
User.singleton_class.define_method(:skip_mx_check?) { true }
user = User.new(
  email: ENV.fetch('MASTODON_OWNER_EMAIL'),
  password: password,
  agreement: true,
  role: UserRole.find_by!(name: 'Owner'),
  bypass_registration_checks: true
)
user.account = Account.new(username: username)
unless user.save
  abort "mastodon: the owner #{username}: #{user.errors.full_messages.join('; ')}"
end
user.mark_email_as_confirmed!
user.approve!
warn "mastodon: made the owner #{username}"
