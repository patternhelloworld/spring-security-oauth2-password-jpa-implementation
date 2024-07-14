package com.patternknife.securityhelper.oauth2.client.util;

import com.mysema.commons.lang.Assert;
import com.querydsl.jpa.JPQLQuery;
import com.querydsl.jpa.sql.JPASQLQuery;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.support.Querydsl;

public class PaginationUtil {

    private final Querydsl querydsl;

    public PaginationUtil(Querydsl querydsl) {
        this.querydsl = querydsl;
    }

    public PaginationUtil() {
        this.querydsl = null;
    }

    public <T> Page<T> applyPagination(JPASQLQuery<T> query, int pageNum, int pageSize, boolean skipPagination) {
        if (skipPagination) {
            pageNum = Integer.parseInt(CommonConstant.COMMON_PAGE_NUM);
            pageSize = Integer.parseInt(CommonConstant.COMMON_PAGE_SIZE_DEFAULT_MAX);
        }

        long totalElements = query.fetch().size();
        PageRequest pageRequest = PageRequest.of(pageNum - 1, pageSize);

        Assert.notNull(pageRequest, "Pageable must not be null!");
        Assert.notNull(query, "JPASQLQuery must not be null!");

        if(pageRequest.isPaged()) {
            query.offset(pageRequest.getOffset());
            query.limit(pageRequest.getPageSize());
        }

        return new PageImpl<>(query.fetch(), pageRequest, totalElements);
    }

    public <T> Page<T> applyPagination(JPQLQuery<T> query, int pageNum, int pageSize, boolean skipPagination) {
        if (skipPagination) {
            pageNum = Integer.parseInt(CommonConstant.COMMON_PAGE_NUM);
            pageSize = Integer.parseInt(CommonConstant.COMMON_PAGE_SIZE_DEFAULT_MAX);
        }

        long totalElements = query.fetchCount();
        PageRequest pageRequest = PageRequest.of(pageNum - 1, pageSize);

        return new PageImpl<>(querydsl.applyPagination(pageRequest, query).fetch(), pageRequest, totalElements);
    }

    public <T> Page<T> applyPagination(JPQLQuery<T> query, int pageNum, int pageSize, boolean skipPagination, boolean skipCalculateTotalElements) {
        if (skipPagination) {
            pageNum = Integer.parseInt(CommonConstant.COMMON_PAGE_NUM);
            pageSize = Integer.parseInt(CommonConstant.COMMON_PAGE_SIZE_DEFAULT_MAX);
        }
        long totalElements;
        if(skipCalculateTotalElements){
            totalElements = 10000;
        }else{
            totalElements = query.fetchCount();
        }

        PageRequest pageRequest = PageRequest.of(pageNum - 1, pageSize);

        return new PageImpl<>(querydsl.applyPagination(pageRequest, query).fetch(), pageRequest, totalElements);
    }

    public <T> Page<T> applyPagination(JPQLQuery<T> query, int pageNum, int pageSize, boolean skipPagination, Long totalElements) {
        if (skipPagination) {
            pageNum = Integer.parseInt(CommonConstant.COMMON_PAGE_NUM);
            pageSize = Integer.parseInt(CommonConstant.COMMON_PAGE_SIZE_DEFAULT_MAX);
        }

        PageRequest pageRequest = PageRequest.of(pageNum - 1, pageSize);

        return new PageImpl<>(querydsl.applyPagination(pageRequest, query).fetch(), pageRequest, totalElements);
    }
}
