/*
Navicat MySQL Data Transfer

Source Server         : MySQL3306
Source Server Version : 80015
Source Host           : localhost:3306
Source Database       : wj

Target Server Type    : MYSQL
Target Server Version : 80015
File Encoding         : 65001

Date: 2020-04-12 09:45:45
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for admin_menu
-- ----------------------------
DROP TABLE IF EXISTS `admin_menu`;
CREATE TABLE `admin_menu` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `path` varchar(64) DEFAULT NULL,
  `name` varchar(64) DEFAULT NULL,
  `name_zh` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `icon_cls` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `component` varchar(64) DEFAULT NULL,
  `parent_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Records of admin_menu
-- ----------------------------
INSERT INTO `admin_menu` VALUES ('1', '/admin', 'AdminIndex', 'home', 'el-icon-s-home', 'AdminIndex', '0');
INSERT INTO `admin_menu` VALUES ('2', '/admin/dashboard', 'DashboardAdmin', 'dashboard', null, 'dashboard/admin/index', '1');
INSERT INTO `admin_menu` VALUES ('3', '/admin', 'User', 'user-manage', 'el-icon-user', 'AdminIndex', '0');
INSERT INTO `admin_menu` VALUES ('4', '/admin', 'Content', 'content-manage', 'el-icon-tickets', 'AdminIndex', '0');
INSERT INTO `admin_menu` VALUES ('5', '/admin', 'System', 'sys-config', 'el-icon-s-tools', 'AdminIndex', '0');
INSERT INTO `admin_menu` VALUES ('6', '/admin/user/profile', 'Profile', 'user-info', null, 'user/UserProfile', '3');
INSERT INTO `admin_menu` VALUES ('7', '/admin/user/role', 'Role', 'role-config', null, 'user/Role', '3');
INSERT INTO `admin_menu` VALUES ('8', '/admin/content/book', 'BookManagement', 'book-manage', null, 'content/BookManagement', '4');
INSERT INTO `admin_menu` VALUES ('9', '/admin/content/banner', 'BannerManagement', 'banner-manage', null, 'content/BannerManagement', '4');
INSERT INTO `admin_menu` VALUES ('10', '/admin/content/article', 'ArticleManagement', 'article-manage', null, 'content/ArticleManagement', '4');

-- ----------------------------
-- Table structure for admin_permission
-- ----------------------------
DROP TABLE IF EXISTS `admin_permission`;
CREATE TABLE `admin_permission` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
  `desc_` varchar(100) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
  `url` varchar(100) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of admin_permission
-- ----------------------------
INSERT INTO `admin_permission` VALUES ('1', 'users_management', 'user-manage', '/api/admin/user');
INSERT INTO `admin_permission` VALUES ('2', 'roles_management', 'role-manage', '/api/admin/role');
INSERT INTO `admin_permission` VALUES ('3', 'content_management', 'content-manage', '/api/admin/content');

-- ----------------------------
-- Table structure for admin_role
-- ----------------------------
DROP TABLE IF EXISTS `admin_role`;
CREATE TABLE `admin_role` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
  `name_zh` varchar(100) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
  `enabled` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of admin_role
-- ----------------------------
INSERT INTO `admin_role` VALUES ('1', 'sysAdmin', 'sys-admin', '1');
INSERT INTO `admin_role` VALUES ('2', 'contentManager', 'content-admin', '1');
INSERT INTO `admin_role` VALUES ('3', 'visitor', 'visitor', '1');
INSERT INTO `admin_role` VALUES ('9', 'test', 'test-role', '1');

-- ----------------------------
-- Table structure for admin_role_menu
-- ----------------------------
DROP TABLE IF EXISTS `admin_role_menu`;
CREATE TABLE `admin_role_menu` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `rid` int(11) DEFAULT NULL,
  `mid` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=194 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Records of admin_role_menu
-- ----------------------------
INSERT INTO `admin_role_menu` VALUES ('19', '4', '1');
INSERT INTO `admin_role_menu` VALUES ('20', '4', '2');
INSERT INTO `admin_role_menu` VALUES ('21', '3', '1');
INSERT INTO `admin_role_menu` VALUES ('22', '3', '2');
INSERT INTO `admin_role_menu` VALUES ('23', '9', '1');
INSERT INTO `admin_role_menu` VALUES ('24', '9', '2');
INSERT INTO `admin_role_menu` VALUES ('121', '1', '1');
INSERT INTO `admin_role_menu` VALUES ('122', '1', '2');
INSERT INTO `admin_role_menu` VALUES ('123', '1', '3');
INSERT INTO `admin_role_menu` VALUES ('124', '1', '6');
INSERT INTO `admin_role_menu` VALUES ('125', '1', '7');
INSERT INTO `admin_role_menu` VALUES ('126', '1', '4');
INSERT INTO `admin_role_menu` VALUES ('127', '1', '8');
INSERT INTO `admin_role_menu` VALUES ('128', '1', '9');
INSERT INTO `admin_role_menu` VALUES ('129', '1', '10');
INSERT INTO `admin_role_menu` VALUES ('130', '1', '5');
INSERT INTO `admin_role_menu` VALUES ('188', '2', '1');
INSERT INTO `admin_role_menu` VALUES ('189', '2', '2');
INSERT INTO `admin_role_menu` VALUES ('190', '2', '4');
INSERT INTO `admin_role_menu` VALUES ('191', '2', '8');
INSERT INTO `admin_role_menu` VALUES ('192', '2', '9');
INSERT INTO `admin_role_menu` VALUES ('193', '2', '10');

-- ----------------------------
-- Table structure for admin_role_permission
-- ----------------------------
DROP TABLE IF EXISTS `admin_role_permission`;
CREATE TABLE `admin_role_permission` (
  `id` int(20) NOT NULL AUTO_INCREMENT,
  `rid` int(20) DEFAULT NULL,
  `pid` int(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_role_permission_role_1` (`rid`),
  KEY `fk_role_permission_permission_1` (`pid`)
) ENGINE=InnoDB AUTO_INCREMENT=140 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of admin_role_permission
-- ----------------------------
INSERT INTO `admin_role_permission` VALUES ('83', '5', '3');
INSERT INTO `admin_role_permission` VALUES ('108', '1', '1');
INSERT INTO `admin_role_permission` VALUES ('109', '1', '2');
INSERT INTO `admin_role_permission` VALUES ('110', '1', '3');
INSERT INTO `admin_role_permission` VALUES ('139', '2', '3');

-- ----------------------------
-- Table structure for admin_user_role
-- ----------------------------
DROP TABLE IF EXISTS `admin_user_role`;
CREATE TABLE `admin_user_role` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uid` int(11) DEFAULT NULL,
  `rid` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_operator_role_operator_1` (`uid`),
  KEY `fk_operator_role_role_1` (`rid`)
) ENGINE=InnoDB AUTO_INCREMENT=68 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of admin_user_role
-- ----------------------------
INSERT INTO `admin_user_role` VALUES ('40', '24', '2');
INSERT INTO `admin_user_role` VALUES ('63', '3', '2');
INSERT INTO `admin_user_role` VALUES ('64', '1', '1');
INSERT INTO `admin_user_role` VALUES ('67', '2', '3');

-- ----------------------------
-- Table structure for book
-- ----------------------------
DROP TABLE IF EXISTS `book`;
CREATE TABLE `book` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cover` varchar(255) DEFAULT '',
  `title` varchar(255) NOT NULL DEFAULT '',
  `author` varchar(255) DEFAULT '',
  `date` varchar(20) DEFAULT '',
  `press` varchar(255) DEFAULT '',
  `abs` varchar(255) DEFAULT NULL,
  `cid` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_book_category_on_cid` (`cid`),
  CONSTRAINT `fk_book_category_on_cid` FOREIGN KEY (`cid`) REFERENCES `category` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=109 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of book
-- ----------------------------
INSERT INTO `book` VALUES ('1', 'https://i.loli.net/2019/04/10/5cadaa0d0759b.jpg', 'aaa', 'aaa', '2019-2-1', 'aaa', 'aaa', '2');
INSERT INTO `book` VALUES ('2', 'https://i.loli.net/2019/04/10/5cada7e73d601.jpg', 'bbb', 'bbb', '2008-1', 'bbb', 'bbb', '2');
INSERT INTO `book` VALUES ('32', 'https://i.loli.net/2019/04/10/5cada99bd8ca5.jpg', 'ccc', 'ccc', '2019-3', 'ccc', 'ccc', '3');
INSERT INTO `book` VALUES ('35', 'https://i.loli.net/2019/04/10/5cada940e206a.jpg', 'ddd', 'ddd', '2019-3', 'ddd', 'ddd', '1');
INSERT INTO `book` VALUES ('37', 'https://i.loli.net/2019/04/10/5cada8986e13a.jpg', 'eee', 'eee', '2019-3', 'eee', 'eee', '3');
INSERT INTO `book` VALUES ('38', 'https://i.loli.net/2019/04/10/5cada8b8a3a17.jpg', 'eee', 'eee', '2019-4', 'eee', 'eee', '1');
INSERT INTO `book` VALUES ('54', 'https://i.loli.net/2019/04/10/5cada9d9d23a6.jpg', 'eee', 'eee', '2019-3-31', 'eee', 'eee', '3');
INSERT INTO `book` VALUES ('55', 'https://i.loli.net/2019/04/10/5cada824c7119.jpg', 'eee', 'eee', '2019-4', 'eee', 'eee', '1');
INSERT INTO `book` VALUES ('59', 'https://i.loli.net/2019/04/10/5cada87fd5c72.jpg', 'eee', 'eee', '2019-3', 'eee', 'eee', '4');
INSERT INTO `book` VALUES ('60', 'https://i.loli.net/2019/04/10/5cada976927da.jpg', 'eee', 'eee', '2019-4-11', 'eee', 'eee', '1');
INSERT INTO `book` VALUES ('61', 'https://i.loli.net/2019/04/10/5cada9202d970.jpg', 'eee', 'eee', '2019-3', 'eee', 'eee', '1');
INSERT INTO `book` VALUES ('62', 'https://i.loli.net/2019/04/10/5cada9c852298.jpg', 'eee', 'eee', '2019-4', 'eee', 'eee', '2');
INSERT INTO `book` VALUES ('63', 'https://i.loli.net/2019/04/10/5cada962c287c.jpg', 'eee', 'eee', '2019-3', 'eee', 'eee', '1');
INSERT INTO `book` VALUES ('64', 'https://i.loli.net/2019/04/10/5cada858e6019.jpg', 'eee', 'eee', '2019-4', 'eee', 'eee', '3');
INSERT INTO `book` VALUES ('65', 'https://i.loli.net/2019/04/10/5cada8e1aa892.jpg', 'eee', 'eee', '2019-3', 'eee', 'eee', '6');
INSERT INTO `book` VALUES ('66', 'https://i.loli.net/2019/04/10/5cada9ec514c9.jpg', 'eee', 'eee', '2019-5', 'eee', 'eee', '3');
INSERT INTO `book` VALUES ('67', 'https://i.loli.net/2019/04/10/5cada9870c2ab.jpg', 'eee', 'eee', '2019-3', 'eee', 'eee', '3');
INSERT INTO `book` VALUES ('68', 'https://i.loli.net/2019/04/10/5cad643643d4c.jpg', 'eee', 'eee', '2019-3', 'eee', 'eee', '1');
INSERT INTO `book` VALUES ('69', 'https://i.loli.net/2019/04/10/5cad63931ce27.jpg', 'eee', 'eee', '2019-3', 'eee', 'eee', '1');
INSERT INTO `book` VALUES ('70', 'http://localhost:8443/api/file/k09g2r.png', 'eee', 'eee', '2019-3', 'eee', 'eee', '3');

-- ----------------------------
-- Table structure for category
-- ----------------------------
DROP TABLE IF EXISTS `category`;
CREATE TABLE `category` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of category
-- ----------------------------
INSERT INTO `category` VALUES ('1', 'Literature');
INSERT INTO `category` VALUES ('2', 'Popular');
INSERT INTO `category` VALUES ('3', 'Culture');
INSERT INTO `category` VALUES ('4', 'Life');
INSERT INTO `category` VALUES ('5', 'Management');
INSERT INTO `category` VALUES ('6', 'SciTech');

-- ----------------------------
-- Table structure for jotter_article
-- ----------------------------
DROP TABLE IF EXISTS `jotter_article`;
CREATE TABLE `jotter_article` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `article_title` varchar(255) DEFAULT NULL,
  `article_content_html` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci,
  `article_content_md` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci,
  `article_abstract` varchar(255) DEFAULT NULL,
  `article_cover` varchar(255) DEFAULT NULL,
  `article_date` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Records of jotter_article
-- ----------------------------
INSERT INTO `jotter_article` VALUES ('1', 'aaa', 'hello', 'world', 'hello', 'https://i.loli.net/2020/01/16/d2ZlKI1WRE4p7XB.png', '2020-01-13 21:14:27');
INSERT INTO `jotter_article` VALUES ('2', 'bbb', 'goodbye', 'bye-bye', 'seeyou', 'https://i.loli.net/2020/01/16/DdGBk1R3mj5er6v.png', '2020-01-16 00:00:00');
INSERT INTO `jotter_article` VALUES ('3', 'ccc', 'abandon', 'abandon', 'abandon', 'https://i.loli.net/2020/01/19/egDEfu5jXlJ6r3a.png', '2020-01-19 00:00:00');

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` char(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `password` varchar(255) DEFAULT NULL,
  `salt` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `phone` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `enabled` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=110 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of user
-- ----------------------------
INSERT INTO `user` VALUES ('1', 'admin', '35b9529f89cfb9b848060ca576237e17', '8O+vDNr2sI3N82BI31fu1A==', 'admin', '99999999999', 'evan_nightly@163.com', '1');
INSERT INTO `user` VALUES ('2', 'test', '85087738b6c1e1d212683bfafc163853', 'JBba3j5qRykIPJQYTNNH9A==', 'test', '88888888888', '123@123.com', '1');
INSERT INTO `user` VALUES ('3', 'editor', '8583a2d965d6159edbf65c82d871fa3e', 'MZTe7Qwf9QgXBXrZzTIqJQ==', 'editor', null, null, '1');
