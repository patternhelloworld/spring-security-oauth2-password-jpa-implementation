-- --------------------------------------------------------
-- 호스트:                          127.0.0.1
-- 서버 버전:                        8.0.40 - MySQL Community Server - GPL
-- 서버 OS:                        Linux
-- HeidiSQL 버전:                  12.8.0.6908
-- --------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8 */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


-- sc_oauth2_pji 데이터베이스 구조 내보내기
CREATE DATABASE IF NOT EXISTS `sc_oauth2_pji` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;
USE `sc_oauth2_pji`;

-- 테이블 sc_oauth2_pji.admin 구조 내보내기
CREATE TABLE IF NOT EXISTS `admin` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `id_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password_changed_at` datetime DEFAULT NULL,
  `password_expiration_date` datetime DEFAULT NULL,
  `password_failed_count` int NOT NULL DEFAULT '0',
  `password_ttl` bigint NOT NULL DEFAULT (0),
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE KEY `id_name` (`id_name`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 테이블 데이터 sc_oauth2_pji.admin:~0 rows (대략적) 내보내기
INSERT INTO `admin` (`id`, `id_name`, `password`, `description`, `password_changed_at`, `password_expiration_date`, `password_failed_count`, `password_ttl`, `created_at`, `updated_at`, `deleted_at`) VALUES
	(1, 'manager01', '$2a$10$OTxjCyMO4Ou8rBoubddtwuT44GZiwevfEg19XfF6pjfB3A5BYj3MW', NULL, NULL, '2024-01-30 13:58:45', 0, 1209604, '2023-10-17 07:40:07', '2024-01-16 04:58:42', NULL);

-- 테이블 sc_oauth2_pji.admin_role 구조 내보내기
CREATE TABLE IF NOT EXISTS `admin_role` (
  `id` int NOT NULL AUTO_INCREMENT,
  `admin_id` bigint NOT NULL,
  `role_id` bigint NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE KEY `admin_id_role_id` (`admin_id`,`role_id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=54 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC;

-- 테이블 데이터 sc_oauth2_pji.admin_role:~2 rows (대략적) 내보내기
INSERT INTO `admin_role` (`id`, `admin_id`, `role_id`, `created_at`, `updated_at`) VALUES
	(48, 1, 1, '2024-01-16 15:21:03', '2024-01-16 15:21:03'),
	(49, 1, 4, '2024-01-16 15:21:03', '2024-01-16 15:21:03');

-- 테이블 sc_oauth2_pji.authorization_consent 구조 내보내기
CREATE TABLE IF NOT EXISTS `authorization_consent` (
  `registered_client_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `principal_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `authorities` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`registered_client_id`,`principal_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 테이블 데이터 sc_oauth2_pji.authorization_consent:~1 rows (대략적) 내보내기

-- 테이블 sc_oauth2_pji.customer 구조 내보내기
CREATE TABLE IF NOT EXISTS `customer` (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '일련번호',
  `id_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '일반 로그인의 사용자 식별 고유 ID',
  `deleted_id_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '비밀번호',
  `name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '유저명',
  `hp` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '핸드폰번호',
  `birthday` date DEFAULT NULL COMMENT '생일',
  `email` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '이메일주소',
  `sex` enum('M','F') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '성별',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP COMMENT '등록일',
  `create_admin_id` bigint DEFAULT NULL COMMENT '등록자',
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '수정일',
  `update_admin_id` bigint DEFAULT NULL COMMENT '수정자',
  `deleted_at` datetime DEFAULT NULL COMMENT '삭제일',
  `delete_admin_id` bigint DEFAULT NULL COMMENT '삭제자',
  `password_changed_at` datetime DEFAULT NULL,
  `password_expiration_date` datetime DEFAULT NULL,
  `password_failed_count` int DEFAULT NULL,
  `password_ttl` int DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE KEY `id_name` (`id_name`)
) ENGINE=InnoDB AUTO_INCREMENT=207 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 테이블 데이터 sc_oauth2_pji.customer:~2 rows (대략적) 내보내기
INSERT INTO `customer` (`id`, `id_name`, `deleted_id_name`, `password`, `name`, `hp`, `birthday`, `email`, `sex`, `created_at`, `create_admin_id`, `updated_at`, `update_admin_id`, `deleted_at`, `delete_admin_id`, `password_changed_at`, `password_expiration_date`, `password_failed_count`, `password_ttl`) VALUES
	(79, 'test@test.com', NULL, '$2a$10$YWOXPWh/IA/nl5PbJjfPXOqYym4eJzPmgNHyTth5oniQhX6sJohya', 'Tester', '01037343735', '1900-01-01', 'newuser3@google.com', 'F', '2023-11-02 04:09:23', NULL, '2024-04-08 05:32:34', NULL, NULL, 1, NULL, '2023-11-16 13:09:27', 0, 1209604),
	(89, 'cicd@test.com', NULL, '$2a$10$YWOXPWh/IA/nl5PbJjfPXOqYym4eJzPmgNHyTth5oniQhX6sJohya', 'CICD', '0103734371', '1900-01-01', 'newuser3@google.com', 'F', '2023-11-02 04:09:23', NULL, '2023-12-10 13:49:08', NULL, NULL, 1, NULL, '2023-11-16 13:09:27', 0, 1209604);

-- 테이블 sc_oauth2_pji.customer_role 구조 내보내기
CREATE TABLE IF NOT EXISTS `customer_role` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` bigint NOT NULL,
  `role_id` bigint NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id_role_id` (`customer_id`,`role_id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 테이블 데이터 sc_oauth2_pji.customer_role:~3 rows (대략적) 내보내기
INSERT INTO `customer_role` (`id`, `customer_id`, `role_id`, `created_at`, `updated_at`) VALUES
	(1, 3, 1, '2023-10-17 07:40:54', '2023-10-17 07:40:54'),
	(2, 79, 1, '2025-01-03 17:08:34', '2025-01-03 18:17:10'),
	(4, 89, 1, '2025-01-03 17:08:34', '2025-01-03 18:17:10');

-- 테이블 sc_oauth2_pji.oauth2_authorization 구조 내보내기
CREATE TABLE IF NOT EXISTS `oauth2_authorization` (
  `id` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `registered_client_id` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `principal_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `authorization_grant_type` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `authorized_scopes` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `attributes` blob,
  `state` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `authorization_code_value` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `authorization_code_issued_at` datetime DEFAULT NULL,
  `authorization_code_expires_at` datetime DEFAULT NULL,
  `authorization_code_metadata` blob,
  `access_token_value` varchar(150) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `access_token_issued_at` datetime DEFAULT NULL,
  `access_token_expires_at` datetime DEFAULT NULL,
  `access_token_metadata` blob,
  `access_token_type` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `access_token_scopes` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `access_token_app_token` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `access_token_user_agent` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `access_token_remote_ip` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `oidc_id_token_value` blob,
  `oidc_id_token_issued_at` datetime DEFAULT NULL,
  `oidc_id_token_expires_at` datetime DEFAULT NULL,
  `oidc_id_token_metadata` blob,
  `refresh_token_value` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `refresh_token_issued_at` datetime DEFAULT NULL,
  `refresh_token_expires_at` datetime DEFAULT NULL,
  `refresh_token_metadata` blob,
  `user_code_value` blob,
  `user_code_issued_at` datetime DEFAULT NULL,
  `user_code_expires_at` datetime DEFAULT NULL,
  `user_code_metadata` blob,
  `device_code_value` blob,
  `device_code_issued_at` datetime DEFAULT NULL,
  `device_code_expires_at` datetime DEFAULT NULL,
  `device_code_metadata` blob,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='oAuth2AuthorizationService.findByUserNameAndClientIdAndAppToken(userDetails.getUsername(), clientId, (String) additionalParameters.get(KnifeHttpHeaders.APP_TOKEN));\r\n \r\nSPRING SECURITY 6 <- 5 (Changes on columns)\r\n\r\nid : token_id\r\nregistered_client_id : client_id\r\nprincipal_name : user_name\r\nauthorization_grant_type\r\nauthorized_scopes : scope\r\naccess_token_value : authentication\r\n? : authentication_id\r\nauthentication : access_token_value';

-- 테이블 데이터 sc_oauth2_pji.oauth2_authorization:~0 rows (대략적) 내보내기

-- 테이블 sc_oauth2_pji.oauth2_registered_client 구조 내보내기
CREATE TABLE IF NOT EXISTS `oauth2_registered_client` (
  `id` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `client_id` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `client_id_issued_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `client_secret` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `client_secret_expires_at` timestamp NULL DEFAULT NULL,
  `client_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `client_authentication_methods` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `authorization_grant_types` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `redirect_uris` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `post_logout_redirect_uris` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `scopes` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `client_settings` varchar(2000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `token_settings` varchar(2000) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='id : UUID.randomUUID().toString()\r\n\r\n3600 : 1시간\r\n86400 : 24시간\r\n\r\nclient_id -> client_id\r\n\nclient_secret -> client_secret\r\n\nscope -> scopes\n\r\nauthorized_grant_types -> authorization_grant_types\r\n\nweb_server_redirect_uri -> redirect_uris';

-- 테이블 데이터 sc_oauth2_pji.oauth2_registered_client:~2 rows (대략적) 내보내기
INSERT INTO `oauth2_registered_client` (`id`, `client_id`, `client_id_issued_at`, `client_secret`, `client_secret_expires_at`, `client_name`, `client_authentication_methods`, `authorization_grant_types`, `redirect_uris`, `post_logout_redirect_uris`, `scopes`, `client_settings`, `token_settings`) VALUES
	('872e17be-6fe0-11ef-ac14-0242ac120003', 'client_admin', '2024-09-11 01:52:40', '$2a$12$7k0SKrGd/EyhjtjHMqC0WeXdspTrHF44UQiH.Z0WsY.CHiGcb2n6e', NULL, 'client_admin', 'client_secret_basic', 'password,refresh_token,authorization_code,openid,client_credentials', 'http://localhost:8081/callback1', NULL, 'openid,profile,read,write', '{}', '{\n  "access_token_time_to_live": 600,  \n  "refresh_token_time_to_live": 7200\n}'),
	('872e9689-6fe0-11ef-ac14-0242ac120003', 'client_customer', '2024-09-11 01:52:40', '$2a$10$9zlA1CTSvTT3TYDiReaydeANtezTEBFksqWbCtFqefWc6ViM.dcmi', NULL, 'client_customer', 'client_secret_basic', 'password,refresh_token,authorization_code,openid,client_credentials', 'http://localhost:8081/callback1', NULL, 'openid,profile,read,write', '{}', '{\n  "access_token_time_to_live": 600,  \n  "refresh_token_time_to_live": 7200\n}');

-- 테이블 sc_oauth2_pji.role 구조 내보내기
CREATE TABLE IF NOT EXISTS `role` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 테이블 데이터 sc_oauth2_pji.role:~4 rows (대략적) 내보내기
INSERT INTO `role` (`id`, `name`, `description`, `created_at`, `updated_at`) VALUES
	(1, 'SUPER_ADMIN', 'Super Admin', '2023-08-29 13:03:16', '2024-04-08 14:30:58'),
	(2, 'CUSTOMER', NULL, '2023-10-18 14:27:41', '2023-10-18 14:27:41'),
	(3, 'CUSTOMER_ADMIN', NULL, '2023-10-31 16:44:08', '2024-04-08 14:31:05'),
	(4, 'ADMIN', NULL, '2023-10-31 16:45:04', '2024-04-08 14:31:08');

/*!40103 SET TIME_ZONE=IFNULL(@OLD_TIME_ZONE, 'system') */;
/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IFNULL(@OLD_FOREIGN_KEY_CHECKS, 1) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40111 SET SQL_NOTES=IFNULL(@OLD_SQL_NOTES, 1) */;
