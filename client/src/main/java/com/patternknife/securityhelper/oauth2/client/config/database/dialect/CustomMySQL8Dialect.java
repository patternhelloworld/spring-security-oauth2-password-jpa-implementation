package com.patternknife.securityhelper.oauth2.client.config.database.dialect;


import org.hibernate.boot.model.FunctionContributions;
import org.hibernate.dialect.MySQLDialect;
import org.hibernate.dialect.function.CommonFunctionFactory;


public class CustomMySQL8Dialect extends MySQLDialect {

    @Override
    public void initializeFunctionRegistry(FunctionContributions functionContributions) {
        super.initializeFunctionRegistry(functionContributions);

        CommonFunctionFactory functionFactory = new CommonFunctionFactory(functionContributions);
        functionFactory.listagg_groupConcat();
    }

    // 'group_concat' & 'date_format' exist, so they don't need to be implemented

}
