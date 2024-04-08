-- --------------------------------------------------------
-- 호스트:                          127.0.0.1
-- 서버 버전:                        8.0.34 - MySQL Community Server - GPL
-- 서버 OS:                        Linux
-- HeidiSQL 버전:                  12.6.0.6765
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

-- 테이블 데이터 sc_oauth2_pji.admin:~10 rows (대략적) 내보내기
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

-- 테이블 데이터 sc_oauth2_pji.admin_role:~11 rows (대략적) 내보내기
INSERT INTO `admin_role` (`id`, `admin_id`, `role_id`, `created_at`, `updated_at`) VALUES
	(48, 1, 1, '2024-01-16 15:21:03', '2024-01-16 15:21:03'),
	(49, 1, 4, '2024-01-16 15:21:03', '2024-01-16 15:21:03');

-- 테이블 sc_oauth2_pji.customer 구조 내보내기
CREATE TABLE IF NOT EXISTS `customer` (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '일련번호',
  `id_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '일반 로그인의 사용자 식별 고유 ID',
  `deleted_id_name` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
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

-- 테이블 데이터 sc_oauth2_pji.customer:~52 rows (대략적) 내보내기
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
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 테이블 데이터 sc_oauth2_pji.customer_role:~0 rows (대략적) 내보내기
INSERT INTO `customer_role` (`id`, `customer_id`, `role_id`, `created_at`, `updated_at`) VALUES
	(1, 3, 1, '2023-10-17 07:40:54', '2023-10-17 07:40:54');

-- 테이블 sc_oauth2_pji.oauth_access_token 구조 내보내기
CREATE TABLE IF NOT EXISTS `oauth_access_token` (
  `token_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `token` blob,
  `authentication_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `user_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `client_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `authentication` blob,
  `refresh_token` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `app_token` varchar(300) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `user_agent` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `remote_ip` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `expiration_date` datetime DEFAULT NULL,
  `otp_verified` tinyint NOT NULL DEFAULT '0',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`authentication_id`),
  KEY `refresh_token` (`refresh_token`),
  KEY `token_id` (`token_id`),
  KEY `client_id` (`client_id`),
  KEY `user_name` (`user_name`),
  KEY `app_token` (`app_token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Spring Security \r\n\r\ntoken_id : token 이 바뀌면 매번 바뀐다.\r\ntoken : acccess token 이 바뀌면 바뀐다.\r\n[중요] authentication_id : CLIENT_ID + SCOPE + USERNAME + APP_TOKEN 의 MD5 + Salt 1회,  다시 말해 이 단위로 사용자 세션을 유지한다. SCOPE는 항상 DEFAULT이고 APP_TOKEN 1개당 1개의 세션을 유지시켜 준다. \r\nclient_id : admin 테이블 / customer 테이블 에 따라 다랄짐\r\nauthentication : CLIENT_ID + USERNAME + APP_TOKEN 의 바이너리\r\nrefresh_token : 표준 Oauth2 문서 참조\r\napp_token : 사용자 기기당 고유 값\r\nuser_agent 및 remote_ip 는 수집 정보.';

-- 테이블 데이터 sc_oauth2_pji.oauth_access_token:~0 rows (대략적) 내보내기

-- 테이블 sc_oauth2_pji.oauth_client_details 구조 내보내기
CREATE TABLE IF NOT EXISTS `oauth_client_details` (
  `client_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '현재 spring security 가 application.properties 를 참조하여 이 값은 무시됨',
  `resource_ids` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `client_secret` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '현재 spring security 가 application.properties 를 참조하여 이 값은 무시됨',
  `scope` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '현재 spring security 가 application.properties 를 참조하여 이 값은 무시됨',
  `authorized_grant_types` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '현재 spring security 가 application.properties 를 참조하여 이 값은 무시됨',
  `web_server_redirect_uri` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '현재 spring security 가 application.properties 를 참조하여 이 값은 무시됨',
  `authorities` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '현재 spring security 가 application.properties 를 참조하여 이 값은 무시됨',
  `access_token_validity` int DEFAULT NULL COMMENT '현재 spring security 가 application.properties 를 참조하여 이 값은 무시됨',
  `refresh_token_validity` int DEFAULT NULL COMMENT '현재 spring security 가 application.properties 를 참조하여 이 값은 무시됨',
  `additional_information` varchar(4096) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '현재 spring security 가 application.properties 를 참조하여 이 값은 무시됨',
  `autoapprove` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '현재 spring security 가 application.properties 를 참조하여 이 값은 무시됨',
  PRIMARY KEY (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='3600 : 1시간\r\n86400 : 24시간\r\n\r\nclient_id : Admin 의 경우 refresh token을 사용하지 않으므로 Acccess Token 을 조금 길게 갖는다. Customer의 경우 사용 중.\r\n\r\n참고 자료 : https://jungjin.oopy.io/41d894e3-ca5f-43dc-978c-f6dec9edc467\r\n';

-- 테이블 데이터 sc_oauth2_pji.oauth_client_details:~2 rows (대략적) 내보내기
INSERT INTO `oauth_client_details` (`client_id`, `resource_ids`, `client_secret`, `scope`, `authorized_grant_types`, `web_server_redirect_uri`, `authorities`, `access_token_validity`, `refresh_token_validity`, `additional_information`, `autoapprove`) VALUES
	('client_admin', 'client_resource', '$2a$10$05AiLlJBI0b/BwgblaK3/ukNhoWW4q0gFs991wm/CUZO4DvPpG8wC', 'read,write', 'password,refresh_token,authorization_code', NULL, NULL, 7600, 86400, NULL, 'true'),
	('client_customer', 'client_resource', '$2a$10$9zlA1CTSvTT3TYDiReaydeANtezTEBFksqWbCtFqefWc6ViM.dcmi', 'read,write', 'password,refresh_token,authorization_code', NULL, NULL, 13600, 86400, NULL, 'true');

-- 테이블 sc_oauth2_pji.oauth_refresh_token 구조 내보내기
CREATE TABLE IF NOT EXISTS `oauth_refresh_token` (
  `token_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `token` blob,
  `authentication` blob,
  `expiration_date` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY `token_id` (`token_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 테이블 데이터 sc_oauth2_pji.oauth_refresh_token:~4 rows (대략적) 내보내기

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
