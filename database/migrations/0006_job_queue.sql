ALTER TABLE `history_jobs` ADD COLUMN IF NOT EXISTS `resolved_hosts` text DEFAULT NULL;

ALTER TABLE `history_jobs` ADD COLUMN IF NOT EXISTS `run_payload` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL;
