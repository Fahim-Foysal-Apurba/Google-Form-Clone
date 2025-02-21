const { Pool } = require('pg');
require('dotenv').config();

const getConnection = () => {
  return new Pool({
    connectionString: process.env.DATABASE_URL,  
    ssl: {
      rejectUnauthorized: false 
    }
  });
};

module.exports = getConnection;