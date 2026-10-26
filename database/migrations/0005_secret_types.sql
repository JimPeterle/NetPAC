ALTER TABLE `secrets` ADD COLUMN IF NOT EXISTS `secret_type` enum('password','ssh_key','vault_password') NOT NULL DEFAULT 'password' AFTER `name`;

ALTER TABLE `secrets` ADD COLUMN IF NOT EXISTS `encrypted_passphrase` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL AFTER `encrypted_password`;

ALTER TABLE `secrets` MODIFY `username` varchar(100) NOT NULL DEFAULT '';
