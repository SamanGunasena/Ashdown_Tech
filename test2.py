import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect('site.db')
cursor = conn.cursor()

# Define the SQL query to add a new column
sql_query = "ALTER TABLE posts ADD COLUMN show_author BOOLEAN DEFAULT 0"

# Execute the query
cursor.execute(sql_query)

# Commit the changes
conn.commit()

# Close the connection
conn.close()
