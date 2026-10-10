-- LimeSurvey's database and role, which mariadb-init applies before each
-- start of MariaDB (forms/mariadb/README.md). The role php logs in by
-- unix_socket, as the system user php-fpm runs as: there is no password.
-- It may do anything to its own database and nothing beyond it: no FILE,
-- no PROCESS, no SUPER, none of which a database grant can carry.

CREATE DATABASE IF NOT EXISTS limesurvey CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'php'@'localhost' IDENTIFIED VIA unix_socket;

GRANT ALL PRIVILEGES ON limesurvey.* TO 'php'@'localhost';
