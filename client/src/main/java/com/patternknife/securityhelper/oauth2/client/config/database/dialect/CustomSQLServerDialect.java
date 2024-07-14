package com.patternknife.securityhelper.oauth2.client.config.database.dialect;


import org.hibernate.boot.model.FunctionContributions;
import org.hibernate.dialect.SQLServerDialect;
import org.hibernate.query.sqm.function.FunctionKind;
import org.hibernate.query.sqm.function.SqmFunctionRegistry;
import org.hibernate.query.sqm.produce.function.PatternFunctionDescriptorBuilder;
import org.hibernate.type.spi.TypeConfiguration;

public class CustomSQLServerDialect extends SQLServerDialect {

    @Override
    public void initializeFunctionRegistry(FunctionContributions functionContributions) {
        super.initializeFunctionRegistry(functionContributions);
        SqmFunctionRegistry registry = functionContributions.getFunctionRegistry();
        TypeConfiguration types = functionContributions.getTypeConfiguration();

        new PatternFunctionDescriptorBuilder(registry, "FORMAT", FunctionKind.NORMAL, "FORMAT(?1, ?2)")
                .setExactArgumentCount(2)
                .setInvariantType(types.getBasicTypeForJavaType(String.class))
                .register();

        // 'string_agg' exists, so it doesn't need to be implemented
    }


}