CREATE TABLE IF NOT EXISTS `service_heartbeat` (
  `service` varchar(32) NOT NULL,
  `last_seen` datetime NOT NULL,
  `info` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`service`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
