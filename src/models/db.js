const { Pool } = require('pg');
require('dotenv').config({ path: require('find-config')('.env') });

const pool = new Pool({
    connectionString: process.env.DATABASE_URL, // Your full Aiven service URL
    ssl: {
        rejectUnauthorized: false, // Needed for Aiven SSL
    },
});

module.exports = {
    query: (text, params) => pool.query(text, params),
};
