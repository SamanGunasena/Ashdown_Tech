import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect('site.db')
cursor = conn.cursor()

# Define the SQL query to update a user's data cell
sql_query = "UPDATE users SET is_approved = ? WHERE id = ?"

# Provide the new value and the user ID
new_value = 1
user_id = 1  # Assuming 1 is the user's ID

# Execute the query with parameters
cursor.execute(sql_query, (new_value, user_id))

# Commit the changes
conn.commit()

# Close the connection
conn.close()
