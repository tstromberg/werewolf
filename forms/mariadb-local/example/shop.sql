-- A shop, dumped from a MariaDB that listened on a port and kept a password.
-- howl create --import applies it once. The same statements are safe as
-- image SQL, which runs on every start. The account is the system user
-- app, known by the socket, not a password.
CREATE DATABASE IF NOT EXISTS shop CHARACTER SET utf8mb4;

CREATE USER IF NOT EXISTS 'app'@'localhost' IDENTIFIED VIA unix_socket;

GRANT ALL PRIVILEGES ON shop.* TO 'app'@'localhost';

CREATE TABLE IF NOT EXISTS shop.items (
  sku VARCHAR(32) PRIMARY KEY,
  name VARCHAR(64) NOT NULL
);

INSERT IGNORE INTO shop.items (sku, name) VALUES ('bolt', 'M8 bolt');
INSERT IGNORE INTO shop.items (sku, name) VALUES ('nut', 'M8 nut');
