# secrets.rb makes Mastodon's secrets once, and records its domain beside
# them, in /data/svc/mastodon/env, which Mastodon reads as .env.production
# (forms/mastodon/README.md). It runs before Rails, which cannot boot
# without them. The domain is Mastodon's identity on the network: a start
# whose config names another is refused, before anything is served.
require 'base64'
require 'openssl'
require 'securerandom'

path = '/data/svc/mastodon/env'
# The media, which nginx serves and the jobs and cron write too; group-
# writable by the directory's default ACL (share group).
Dir.mkdir('/data/svc/mastodon/system') unless Dir.exist?('/data/svc/mastodon/system')
domain = ENV.fetch('LOCAL_DOMAIN', '')
abort 'mastodon: no domain in the config (settings.json)' if domain.empty?

if File.exist?(path)
  recorded = File.foreach(path).find { |l| l.start_with?('LOCAL_DOMAIN=') }&.chomp&.delete_prefix('LOCAL_DOMAIN=')
  if recorded != domain
    abort "mastodon: this server is #{recorded}; the config says #{domain}, " \
          'and a Mastodon server keeps its domain for good'
  end
  exit
end

# A VAPID key pair for Web Push, as the webpush gem makes one.
key = OpenSSL::PKey::EC.generate('prime256v1')
values = {
  'LOCAL_DOMAIN' => domain,
  'SECRET_KEY_BASE' => SecureRandom.hex(64),
  'ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY' => SecureRandom.alphanumeric(32),
  'ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT' => SecureRandom.alphanumeric(32),
  'ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY' => SecureRandom.alphanumeric(32),
  'VAPID_PRIVATE_KEY' => Base64.urlsafe_encode64(key.private_key.to_s(2)),
  'VAPID_PUBLIC_KEY' => Base64.urlsafe_encode64(key.public_key.to_bn.to_s(2)),
}

# Whole or not at all: written beside it, synced, then renamed over.
partial = "#{path}.new"
File.delete(partial) if File.exist?(partial)
# The web's group, the jobs' and cron's, reads them; no one else.
File.open(partial, File::WRONLY | File::CREAT | File::EXCL, 0o640) do |f|
  values.each { |k, v| f.puts("#{k}=#{v}") }
  f.fsync
end
File.rename(partial, path)
warn "mastodon: made the secrets of #{domain}"
