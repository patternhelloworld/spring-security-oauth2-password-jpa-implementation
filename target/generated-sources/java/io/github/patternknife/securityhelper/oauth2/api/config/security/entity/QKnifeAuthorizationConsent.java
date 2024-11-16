package io.github.patternknife.securityhelper.oauth2.api.config.security.entity;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;


/**
 * QKnifeAuthorizationConsent is a Querydsl query type for KnifeAuthorizationConsent
 */
@Generated("com.querydsl.codegen.DefaultEntitySerializer")
public class QKnifeAuthorizationConsent extends EntityPathBase<KnifeAuthorizationConsent> {

    private static final long serialVersionUID = -1399288934L;

    public static final QKnifeAuthorizationConsent knifeAuthorizationConsent = new QKnifeAuthorizationConsent("knifeAuthorizationConsent");

    public final StringPath authorities = createString("authorities");

    public final StringPath principalName = createString("principalName");

    public final StringPath registeredClientId = createString("registeredClientId");

    public QKnifeAuthorizationConsent(String variable) {
        super(KnifeAuthorizationConsent.class, forVariable(variable));
    }

    public QKnifeAuthorizationConsent(Path<? extends KnifeAuthorizationConsent> path) {
        super(path.getType(), path.getMetadata());
    }

    public QKnifeAuthorizationConsent(PathMetadata metadata) {
        super(KnifeAuthorizationConsent.class, metadata);
    }

}

