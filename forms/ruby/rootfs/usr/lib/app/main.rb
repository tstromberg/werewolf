# The ruby form's application until yours replaces it: one line of text on
# :8080, to show Ruby runs here, leashed. Ruby's own sockets, no gem.
require "socket"

PORT = 8080
server = TCPServer.new("0.0.0.0", PORT)
$stdout.sync = true
puts "app: listening on :#{PORT}"

loop do
  Thread.new(server.accept) do |client|
    # The request line and headers, up to the blank line; a client that
    # sends nothing in 10 s is let go.
    ready = IO.select([client], nil, nil, 10)
    while ready && (line = client.gets) && line != "\r\n"
    end
    body = "werewolf: Ruby #{RUBY_VERSION} is answering\n"
    client.write "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n" \
                 "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}"
  rescue IOError, SystemCallError
    nil
  ensure
    client.close
  end
end
