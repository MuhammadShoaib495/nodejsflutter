const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'localhost',
    port: '3306',
    user: 'Shoaib',
    password: 'Kingcar321$',
    database: 'fullstack',
});

connection.connect((err) => {
    if (err) {
      console.error('Error connecting to MySQL:', err);
      throw err;
    }
    console.log('Connected to MySQL database');
  });
  
module.exports = connection;
