package com.patternknife.securityhelper.oauth2.domain.customer.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import lombok.Getter;

import java.sql.Timestamp;

public class CustomerResDTO {

    @Getter
    public static class Id {
        private Long id;

        public Id(Long id) {
            this.id = id;
        }
        public Id(Customer customer) {
            this.id = customer.getId();
        }
    }

    @Getter
    public static class IdAdminId {
        private Long id;
        private Long adminId;

        public IdAdminId(Long id, Long adminId) {
            this.id = id;
            this.adminId = adminId;
        }
    }




    @Getter
    public static class IdNameWithAccessTokenRemainingSeconds {

        private Long id;
        private String idName;
        private String name;
        private String email;
        private Integer accessTokenRemainingSeconds;

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp createdAt;
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
        private Timestamp updatedAt;

        public IdNameWithAccessTokenRemainingSeconds(Customer customer, Integer accessTokenRemainingSeconds) {
            this.id = customer.getId();
            this.idName = customer.getIdName();
            this.name = customer.getName();
            this.email = customer.getEmail();
            this.accessTokenRemainingSeconds = accessTokenRemainingSeconds;
            this.createdAt = customer.getCreatedAt();
            this.updatedAt = customer.getUpdatedAt();
        }
    }


}

