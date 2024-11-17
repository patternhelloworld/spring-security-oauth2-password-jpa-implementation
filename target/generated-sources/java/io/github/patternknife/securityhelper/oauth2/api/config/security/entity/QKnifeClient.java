package io.github.patternknife.securityhelper.oauth2.api.config.security.entity;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;


/**
 * QKnifeClient is a Querydsl query type for KnifeClient
 */
@Generated("com.querydsl.codegen.DefaultEntitySerializer")
public class QKnifeClient extends EntityPathBase<KnifeClient> {

    private static final long serialVersionUID = -1345963580L;

    public static final QKnifeClient knifeClient = new QKnifeClient("knifeClient");

    public final StringPath authorizationGrantTypes = createString("authorizationGrantTypes");

    public final StringPath clientAuthenticationMethods = createString("clientAuthenticationMethods");

    public final StringPath clientId = createString("clientId");

    public final DateTimePath<java.time.Instant> clientIdIssuedAt = createDateTime("clientIdIssuedAt", java.time.Instant.class);

    public final StringPath clientName = createString("clientName");

    public final StringPath clientSecret = createString("clientSecret");

    public final DateTimePath<java.time.Instant> clientSecretExpiresAt = createDateTime("clientSecretExpiresAt", java.time.Instant.class);

    public final StringPath clientSettings = createString("clientSettings");

    public final StringPath id = createString("id");

    public final StringPath postLogoutRedirectUris = createString("postLogoutRedirectUris");

    public final StringPath redirectUris = createString("redirectUris");

    public final StringPath scopes = createString("scopes");

    public final StringPath tokenSettings = createString("tokenSettings");

    public QKnifeClient(String variable) {
        super(KnifeClient.class, forVariable(variable));
    }

    public QKnifeClient(Path<? extends KnifeClient> path) {
        super(path.getType(), path.getMetadata());
    }

    public QKnifeClient(PathMetadata metadata) {
        super(KnifeClient.class, metadata);
    }

}

