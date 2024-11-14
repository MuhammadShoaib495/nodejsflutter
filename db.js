const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'autorack.proxy.rlwy.net',
    port: '10396',
    user: 'root',
    password: 'pKtOempbITFauOaoMWKaFNsDQciMqryW',
    database: 'railway',
});

connection.connect((err) => {
    if (err) {
      console.error('Error connecting to MySQL:', err);
      throw err;
    }
    console.log('Connected to MySQL database');
  });
  
module.exports = connection;




