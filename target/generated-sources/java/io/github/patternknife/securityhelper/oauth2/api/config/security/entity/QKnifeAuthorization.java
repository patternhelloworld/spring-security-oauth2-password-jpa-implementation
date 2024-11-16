package io.github.patternknife.securityhelper.oauth2.api.config.security.entity;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;


/**
 * QKnifeAuthorization is a Querydsl query type for KnifeAuthorization
 */
@Generated("com.querydsl.codegen.DefaultEntitySerializer")
public class QKnifeAuthorization extends EntityPathBase<KnifeAuthorization> {

    private static final long serialVersionUID = -931946400L;

    public static final QKnifeAuthorization knifeAuthorization = new QKnifeAuthorization("knifeAuthorization");

    public final StringPath accessTokenAppToken = createString("accessTokenAppToken");

    public final DateTimePath<java.time.LocalDateTime> accessTokenExpiresAt = createDateTime("accessTokenExpiresAt", java.time.LocalDateTime.class);

    public final DateTimePath<java.time.LocalDateTime> accessTokenIssuedAt = createDateTime("accessTokenIssuedAt", java.time.LocalDateTime.class);

    public final StringPath accessTokenMetadata = createString("accessTokenMetadata");

    public final StringPath accessTokenRemoteIp = createString("accessTokenRemoteIp");

    public final StringPath accessTokenScopes = createString("accessTokenScopes");

    public final StringPath accessTokenType = createString("accessTokenType");

    public final StringPath accessTokenUserAgent = createString("accessTokenUserAgent");

    public final StringPath accessTokenValue = createString("accessTokenValue");

    public final StringPath attributes = createString("attributes");

    public final DateTimePath<java.time.LocalDateTime> authorizationCodeExpiresAt = createDateTime("authorizationCodeExpiresAt", java.time.LocalDateTime.class);

    public final DateTimePath<java.time.LocalDateTime> authorizationCodeIssuedAt = createDateTime("authorizationCodeIssuedAt", java.time.LocalDateTime.class);

    public final StringPath authorizationCodeMetadata = createString("authorizationCodeMetadata");

    public final StringPath authorizationCodeValue = createString("authorizationCodeValue");

    public final StringPath authorizationGrantType = createString("authorizationGrantType");

    public final StringPath authorizedScopes = createString("authorizedScopes");

    public final DateTimePath<java.time.Instant> deviceCodeExpiresAt = createDateTime("deviceCodeExpiresAt", java.time.Instant.class);

    public final DateTimePath<java.time.Instant> deviceCodeIssuedAt = createDateTime("deviceCodeIssuedAt", java.time.Instant.class);

    public final StringPath deviceCodeMetadata = createString("deviceCodeMetadata");

    public final StringPath deviceCodeValue = createString("deviceCodeValue");

    public final StringPath id = createString("id");

    public final DateTimePath<java.time.Instant> oidcIdTokenExpiresAt = createDateTime("oidcIdTokenExpiresAt", java.time.Instant.class);

    public final DateTimePath<java.time.Instant> oidcIdTokenIssuedAt = createDateTime("oidcIdTokenIssuedAt", java.time.Instant.class);

    public final StringPath oidcIdTokenMetadata = createString("oidcIdTokenMetadata");

    public final StringPath oidcIdTokenValue = createString("oidcIdTokenValue");

    public final StringPath principalName = createString("principalName");

    public final DateTimePath<java.time.LocalDateTime> refreshTokenExpiresAt = createDateTime("refreshTokenExpiresAt", java.time.LocalDateTime.class);

    public final DateTimePath<java.time.LocalDateTime> refreshTokenIssuedAt = createDateTime("refreshTokenIssuedAt", java.time.LocalDateTime.class);

    public final StringPath refreshTokenMetadata = createString("refreshTokenMetadata");

    public final StringPath refreshTokenValue = createString("refreshTokenValue");

    public final StringPath registeredClientId = createString("registeredClientId");

    public final StringPath state = createString("state");

    public final DateTimePath<java.time.Instant> userCodeExpiresAt = createDateTime("userCodeExpiresAt", java.time.Instant.class);

    public final DateTimePath<java.time.Instant> userCodeIssuedAt = createDateTime("userCodeIssuedAt", java.time.Instant.class);

    public final StringPath userCodeMetadata = createString("userCodeMetadata");

    public final StringPath userCodeValue = createString("userCodeValue");

    public QKnifeAuthorization(String variable) {
        super(KnifeAuthorization.class, forVariable(variable));
    }

    public QKnifeAuthorization(Path<? extends KnifeAuthorization> path) {
        super(path.getType(), path.getMetadata());
    }

    public QKnifeAuthorization(PathMetadata metadata) {
        super(KnifeAuthorization.class, metadata);
    }

}

