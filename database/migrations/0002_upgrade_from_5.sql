ALTER TABLE `history_jobs` ADD COLUMN IF NOT EXISTS `notified_at` datetime DEFAULT NULL;

ALTER TABLE `history_jobs`
  MODIFY `started_at` datetime DEFAULT current_timestamp(),
  MODIFY `finished_at` datetime DEFAULT NULL,
  MODIFY `notified_at` datetime DEFAULT NULL;

ALTER TABLE `user`
  MODIFY `name` varchar(100) NOT NULL,
  MODIFY `totp_secret` text DEFAULT NULL;

ALTER TABLE `user` ADD COLUMN IF NOT EXISTS `totp_last_counter` bigint(20) DEFAULT NULL AFTER `totp_confirmed`;

CREATE TABLE IF NOT EXISTS `notification_rules` (
  `rule_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `channel` enum('email','matrix') NOT NULL,
  `target` varchar(255) NOT NULL,
  `on_completed` tinyint(1) NOT NULL DEFAULT 0,
  `on_failed` tinyint(1) NOT NULL DEFAULT 1,
  `on_timeout` tinyint(1) NOT NULL DEFAULT 1,
  `on_cancelled` tinyint(1) NOT NULL DEFAULT 0,
  `job_type` enum('all','python','ansible') DEFAULT 'all',
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_by` varchar(100) DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`rule_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS `notification_settings` (
  `id` int(11) NOT NULL DEFAULT 1,
  `smtp_host` varchar(255) DEFAULT NULL,
  `smtp_port` int(11) DEFAULT 587,
  `smtp_security` enum('starttls','ssl','none') DEFAULT 'starttls',
  `smtp_user` varchar(255) DEFAULT NULL,
  `smtp_encrypted_password` text DEFAULT NULL,
  `smtp_from` varchar(255) DEFAULT NULL,
  `matrix_homeserver` varchar(255) DEFAULT NULL,
  `matrix_encrypted_token` text DEFAULT NULL,
  `base_url` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `single_row_notif` CHECK (`id` = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

UPDATE `host_groups` SET `ansible_vars` = REPLACE(`ansible_vars`, ',', '\n') WHERE `ansible_vars` IS NOT NULL;
