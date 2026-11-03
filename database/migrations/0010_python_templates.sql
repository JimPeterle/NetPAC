ALTER TABLE `playbook_templates` ADD COLUMN IF NOT EXISTS `job_type` varchar(20) NOT NULL DEFAULT 'ansible' AFTER `playbook_path`;

ALTER TABLE `playbook_templates` ADD COLUMN IF NOT EXISTS `script_args` text DEFAULT NULL AFTER `extra_vars`;

ALTER TABLE `playbook_templates` ADD COLUMN IF NOT EXISTS `use_venv` tinyint(1) NOT NULL DEFAULT 0 AFTER `script_args`;
