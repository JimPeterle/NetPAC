ALTER TABLE `playbook_templates` ADD COLUMN IF NOT EXISTS `forks` int(11) DEFAULT NULL AFTER `use_venv`;
