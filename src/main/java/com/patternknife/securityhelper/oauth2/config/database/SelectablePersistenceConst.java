package com.patternknife.securityhelper.oauth2.config.database;

public enum SelectablePersistenceConst {

    MYSQL_8("com.patternknife.securityhelper.oauth2.config.database.dialect.CustomMySQL8Dialect"),
    MSSQL("com.patternknife.securityhelper.oauth2.config.database.dialect.CustomSQLServerDialect");

    private final String value;

    SelectablePersistenceConst(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
