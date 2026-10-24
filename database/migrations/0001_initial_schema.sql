SET FOREIGN_KEY_CHECKS = 0;

CREATE TABLE IF NOT EXISTS `apscheduler_jobs` (
  `id` varchar(191) NOT NULL,
  `next_run_time` double DEFAULT NULL,
  `job_state` blob NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_apscheduler_jobs_next_run_time` (`next_run_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `history_jobs` (
  `job_id` int(11) NOT NULL AUTO_INCREMENT,
  `script_name` varchar(255) NOT NULL,
  `user_id` varchar(100) NOT NULL,
  `target` varchar(255) DEFAULT NULL,
  `variables` longtext DEFAULT NULL,
  `status` enum('running','planned','completed','failed','timeout','cancelled') DEFAULT 'running',
  `output` longtext DEFAULT NULL,
  `started_at` datetime DEFAULT current_timestamp(),
  `finished_at` datetime DEFAULT NULL,
  `duration` int(11) DEFAULT NULL,
  `credential` text DEFAULT NULL,
  `job_type` enum('python','ansible') DEFAULT 'python',
  `ansible_dry_run` tinyint(1) DEFAULT 0,
  `pid` int(11) DEFAULT NULL,
  `notified_at` datetime DEFAULT NULL,
  PRIMARY KEY (`job_id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_status` (`status`),
  KEY `idx_started` (`started_at`),
  KEY `idx_history_script_name` (`script_name`),
  KEY `idx_history_job_type` (`job_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `host_group_membership` (
  `host_id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  PRIMARY KEY (`host_id`,`group_id`),
  KEY `group_id` (`group_id`),
  CONSTRAINT `host_group_membership_ibfk_1` FOREIGN KEY (`host_id`) REFERENCES `hosts` (`host_id`) ON DELETE CASCADE,
  CONSTRAINT `host_group_membership_ibfk_2` FOREIGN KEY (`group_id`) REFERENCES `host_groups` (`group_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `host_groups` (
  `group_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `ansible_vars` text DEFAULT NULL,
  PRIMARY KEY (`group_id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `hosts` (
  `host_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostname` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`host_id`),
  UNIQUE KEY `hostname` (`hostname`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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

CREATE TABLE IF NOT EXISTS `playbook_templates` (
  `template_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `playbook_path` varchar(500) NOT NULL,
  `target` varchar(255) DEFAULT NULL,
  `extra_vars` text DEFAULT NULL,
  `secret_1` varchar(255) DEFAULT NULL,
  `secret_2` varchar(255) DEFAULT NULL,
  `secret_3` varchar(255) DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `created_by` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`template_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `playbooks` (
  `playbook_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `path` varchar(500) NOT NULL,
  `description` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`playbook_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `radius` (
  `id` int(11) NOT NULL DEFAULT 1,
  `server` varchar(255) DEFAULT NULL,
  `port` int(11) DEFAULT 1812,
  `encrypted_secret` text DEFAULT NULL,
  `timeout` int(11) DEFAULT 5,
  PRIMARY KEY (`id`),
  CONSTRAINT `single_row` CHECK (`id` = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS `schedule_jobs` (
  `job_id` int(11) NOT NULL AUTO_INCREMENT,
  `script_name` varchar(255) NOT NULL,
  `user_id` varchar(100) NOT NULL,
  `target` varchar(255) DEFAULT NULL,
  `variables` longtext DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime DEFAULT current_timestamp(),
  `schedule_expression` varchar(100) NOT NULL,
  `credential` text DEFAULT NULL,
  `use_venv` tinyint(1) DEFAULT 0,
  `job_type` varchar(20) DEFAULT 'python',
  PRIMARY KEY (`job_id`),
  KEY `idx_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `secrets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `username` varchar(100) NOT NULL,
  `encrypted_password` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `description` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `user` (
  `name` varchar(100) NOT NULL,
  `password` varchar(255) DEFAULT NULL,
  `totp_secret` text DEFAULT NULL,
  `totp_confirmed` tinyint(1) DEFAULT 0,
  `totp_last_counter` bigint(20) DEFAULT NULL,
  `method` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

INSERT IGNORE INTO `user` (`name`, `password`, `method`) VALUES
  ('admin', '$2b$12$3u9Sfbazd4cOpm9kEKspyO7aU0R0BnND.mo5JBTYH8QSmtIj.rk82', 'local');

SET FOREIGN_KEY_CHECKS = 1;
