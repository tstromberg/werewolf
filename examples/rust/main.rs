// A dependency-free teaching server. Use an HTTP framework for a real app.
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

fn serve(mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    // Bound the first line, including clients that never send a newline.
    let mut line = String::new();
    BufReader::new((&stream).take(4096)).read_line(&mut line)?;
    let fields: Vec<_> = line.split_whitespace().collect();
    let (status, body, extra) = if !line.ends_with("\r\n")
        || fields.len() != 3
        || !matches!(fields[2], "HTTP/1.0" | "HTTP/1.1")
    {
        ("400 Bad Request", "bad request\n", "")
    } else if fields[0] != "GET" {
        (
            "405 Method Not Allowed",
            "method not allowed\n",
            "Allow: GET\r\n",
        )
    } else {
        match fields[1].split('?').next().unwrap_or("") {
            "/" => ("200 OK", "Hello from Rust on werewolf!\n", ""),
            "/health" => ("200 OK", "ok\n", ""),
            _ => ("404 Not Found", "not found\n", ""),
        }
    };
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}", body.len())
}

fn main() -> io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:8080")?;
    eprintln!("app: listening on :8080");
    for stream in listener.incoming() {
        // One request at a time, intentionally; errors affect only that client.
        if let Ok(stream) = stream {
            let _ = serve(stream);
        }
    }
    Ok(())
}
