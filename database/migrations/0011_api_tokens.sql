CREATE TABLE IF NOT EXISTS `api_tokens` (
  `token_id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `name` varchar(100) NOT NULL,
  `token_hash` char(64) NOT NULL,
  `prefix` varchar(16) NOT NULL,
  `created_by` varchar(100) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `expires_at` datetime NOT NULL,
  `last_used_at` datetime DEFAULT NULL,
  `last_used_ip` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`token_id`),
  UNIQUE KEY `uniq_api_token_hash` (`token_hash`),
  KEY `idx_api_tokens_user` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
