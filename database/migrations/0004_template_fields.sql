CREATE TABLE IF NOT EXISTS `template_fields` (
  `field_id` int(11) NOT NULL AUTO_INCREMENT,
  `template_id` int(11) NOT NULL,
  `var_name` varchar(100) NOT NULL,
  `label` varchar(255) NOT NULL,
  `field_type` enum('text','textarea','number','select','multiselect','boolean','password') NOT NULL DEFAULT 'text',
  `required` tinyint(1) NOT NULL DEFAULT 0,
  `default_value` text DEFAULT NULL,
  `options` text DEFAULT NULL,
  `sort_order` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`field_id`),
  KEY `idx_template_fields_template` (`template_id`),
  CONSTRAINT `fk_template_fields_template` FOREIGN KEY (`template_id`) REFERENCES `playbook_templates` (`template_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
