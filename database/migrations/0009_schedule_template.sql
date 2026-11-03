ALTER TABLE `schedule_jobs` ADD COLUMN IF NOT EXISTS `template_id` int(11) DEFAULT NULL AFTER `job_type`;

CREATE INDEX IF NOT EXISTS `idx_schedule_template` ON `schedule_jobs` (`template_id`);
