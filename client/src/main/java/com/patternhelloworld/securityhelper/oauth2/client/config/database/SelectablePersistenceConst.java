package com.patternhelloworld.securityhelper.oauth2.client.config.database;

public enum SelectablePersistenceConst {

    MYSQL_8("dialect.database.config.com.patternhelloworld.securityhelper.oauth2.client.CustomMySQL8Dialect"),
    MSSQL("dialect.database.config.com.patternhelloworld.securityhelper.oauth2.client.CustomSQLServerDialect");

    private final String value;

    SelectablePersistenceConst(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
