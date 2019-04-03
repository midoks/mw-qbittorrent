CREATE TABLE `pl_hash_list` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` text NOT NULL,
  `info_hash` varchar(40) NOT NULL,
  `length` bigint(20) NOT NULL,
  `status` char(10) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `create_time` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `info_hash` (`info_hash`),
  KEY `create_time` (`create_time`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE `pl_hash_file` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `pid` bigint(20)  NOT NULL,
  `name` text NOT NULL,
  `m3u8` varchar(40) NOT NULL,
  `key` char(40)  NULL DEFAULT '',
  `length` bigint(20)  NULL DEFAULT 0,
  `create_time` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `create_time` (`create_time`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE `pl_hash_queue` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `info_hash` char(40) NOT NULL,
  `create_at` datetime NOT NULL,
  `update_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `create_at` (`create_at`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;