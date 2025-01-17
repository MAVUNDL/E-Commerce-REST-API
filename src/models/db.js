const { Pool } = require('pg');
require('dotenv').config({ path: require('find-config')('.env') });

const pool = new Pool({
    host: process.env.DATABASE_URL,
    port: process.env.PORT, // PostgreSQL default port
    user: process.env.DATABASE_USER, // Your PostgreSQL username
    password: process.env.DATABASE_PASSWORD, // Your PostgreSQL password
    database: process.env.DATABASE_NAME, // Your database name
    port: process.env.DATABASE_PORT,
    ssl: {
        rejectUnauthorized: false, // For AWS RDS SSL certificates
    },
});

module.exports = {
    query: (text, params) => pool.query(text, params),
};
