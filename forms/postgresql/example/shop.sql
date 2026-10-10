-- A two-row shop. howl create --import applies it once, in the postgres
-- database, through the single-user backend. The same statements are safe
-- to run again.
CREATE TABLE IF NOT EXISTS shop (
  sku text PRIMARY KEY,
  name text NOT NULL
);

INSERT INTO shop (sku, name) VALUES ('bolt', 'M8 bolt') ON CONFLICT DO NOTHING;
INSERT INTO shop (sku, name) VALUES ('nut', 'M8 nut') ON CONFLICT DO NOTHING;
