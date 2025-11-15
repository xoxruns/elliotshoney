"""
SQL Tool - Execute SQL statements
"""

from typing import Any, List


class SQLTool:
    """
    SQL tool for executing SQL statements.
    """
    
    def execute_sql(self, sql_statement: str) -> str:
        """
        Execute an SQL statement.
        
        Args:
            sql_statement: The SQL query to execute
            
        Returns:
            String confirming the SQL was executed
        """
        print(f"\n[SQL]: {sql_statement}\n")
        return f"SQL executed: {sql_statement}"
    
    def get_as_langchain_tools(self) -> List[Any]:
        """
        Convert to LangChain tool format.
        
        Returns:
            List of LangChain Tool objects
        """
        from langchain_core.tools import Tool
        
        return [
            Tool(
                name="execute_sql",
                description="Execute an SQL statement. Input: SQL query string.",
                func=self.execute_sql
            )
        ]


# Test
if __name__ == "__main__":
    sql_tool = SQLTool()
    sql_tool.execute_sql("SELECT * FROM users")
    sql_tool.execute_sql("INSERT INTO products (name) VALUES ('test')")
