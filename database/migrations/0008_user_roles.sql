ALTER TABLE `user` ADD COLUMN IF NOT EXISTS `role` enum('admin','operator','viewer') NOT NULL DEFAULT 'viewer' AFTER `method`;

UPDATE `user` SET `role` = 'operator' WHERE `name` <> 'admin';

UPDATE `user` SET `role` = 'admin' WHERE `name` = 'admin';
