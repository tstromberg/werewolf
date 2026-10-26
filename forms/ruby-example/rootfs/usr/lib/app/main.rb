# ruby-example's application: a greeting on :8080, to show Ruby runs here,
# leashed. Ruby's own sockets, no gem.
require "socket"

PORT = 8080
BODIES = { "/" => "Hello from Ruby on werewolf!\n", "/health" => "ok\n" }.freeze
REASONS = { 200 => "OK", 404 => "Not Found", 405 => "Method Not Allowed" }.freeze

# reply answers a request line: GET of a page it has, or why not. It changes
# nothing, so it takes nothing but GET.
def reply(request)
  method, target = request.to_s.split(" ", 3)
  return [405, "method not allowed\n", "Allow: GET\r\n"] unless method == "GET"
  body = BODIES[target.to_s.split("?", 2).first]
  body ? [200, body, ""] : [404, "not found\n", ""]
end

server = TCPServer.new("0.0.0.0", PORT)
$stdout.sync = true
puts "app: listening on :#{PORT}"

loop do
  Thread.new(server.accept) do |client|
    # The request line and headers, up to the blank line, then a body of up
    # to 64 KiB, read so closing does not reset the connection. A client
    # that sends nothing in 10 s is let go.
    request = IO.select([client], nil, nil, 10) && client.gets
    length = 0
    while request && (line = client.gets) && line != "\r\n"
      name, value = line.split(":", 2)
      length = value.to_i if name.casecmp?("content-length")
    end
    client.read(length.clamp(0, 1 << 16))
    status, body, extra = reply(request)
    client.write "HTTP/1.1 #{status} #{REASONS[status]}\r\n#{extra}" \
                 "Content-Type: text/plain; charset=utf-8\r\n" \
                 "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}"
  rescue IOError, SystemCallError
    nil
  ensure
    client.close
  end
end
