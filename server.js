require('dotenv').config()
const serviceAccount = require('./service.json');
const cors = require('cors');
const bodyParser = require('body-parser');
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');
const authRoutes = require('./routes/auth');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const websocket = require('ws');
const secretKey = '47ffec81c5a2fe56d0a30e0c5b8df59b72673fffb9cb929c0d95d2a42929d969';
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const stripe = require('stripe')(process.env.STRIPE_PRIVATE_KEY);
const admin = require('firebase-admin');

///

const app = express()
app.use(cors())
app.use(bodyParser.json())
app.use(cookieParser())
app.use('/auth', authRoutes)




// Initialize Firebase Admin SDK with service account

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Send a notification to a device
app.post('/send-notification', (req, res) => {
  const { token, title, body } = req.body;

  // The message to send
  const message = {
    notification: {
      title: title,
      body: body,
    },
    token: token, // The device token
  };

  // Send the notification via Firebase Admin SDK
  admin
    .messaging()
    .send(message)
    .then((response) => {
      console.log('Successfully sent message:', response);
      res.status(200).send('Notification sent successfully');
    })
    .catch((error) => {
      console.log('Error sending message:', error);
      res.status(500).send('Error sending notification');
    });
});




///////////////////////////////////////////////

app.set('view engine', 'ejs')
// Testing 1

app.get('/', (req, res) => {
  res.render('index.ejs')
})

app.post('/checkout', async (req, res) => {
  const sessions = await stripe.checkout.sessions.create({
    line_items: [
      {
        price_data: {
          currency: 'usd',
          product_data: {
            name: 'Node.js and Express Book',
          },
          unit_amount: 50 * 100
        },
        quantity: 1
      }
    ],
    mode: 'payment',
    success_url: `${process.env.BASE_URL}/complete`,
    cancel_url: `${process.env.BASE_URL}/cancel`


  })
  res.redirect(sessions.url)
})



app.post('/payment', async (req, res) => {
  const { token, product } = req.body;

  // Create a unique key for idempotency
  const idempotencyKey = v4();

  try {

    const customer = await stripe.customers.create({
      email: token.email,
      source: token.id,
    });

    // 1. Create a payment method with the token provided by the frontend
    const paymentMethod = await stripe.paymentMethods.create({
      type: 'card',
      card: {
        token: token.id,  // Use token received from frontend (not hardcoded)
      },
      billing_details: {
        name: product.name, // Use product or user details from request
        email: product.email,
        address: {
          line1: token.line1,
          city: token.city,
          country: token.country,
          postal_code: token.postal_code,
          state: token.state,
        },
      },
    });

    console.log('Payment Method Created:', paymentMethod.id);

    // 2. Create a payment intent using the payment method just created
    const paymentIntent = await stripe.paymentIntents.create({
      amount: product.price * 100,  // Convert price to cents
      currency: 'usd',
      payment_method: paymentMethod.id, // Use the payment method created above
      confirm: true,
      automatic_payment_methods: {
        enabled: true, // This should be the correct way to enable it
      },
      return_url: 'https://your-website.com/payment-success', // Automatically confirm the payment
    }, {
      idempotencyKey: idempotencyKey // Pass the UUID as the idempotency key
    });

    console.log('Payment Intent Created:', paymentIntent.id);

    const customerData = {
      customer_id: customer.id,
      product_name: product.name,
      address_line1: token.line1,
      customer_city: token.city,
      customer_state: token.state,
      customer_postalcode: token.postal_code,
    }
    await saveCustomerAndChargeToData(customerData, paymentIntent);
    // Respond with payment intent details
    res.status(200).json({
      success: true,
      paymentIntent: paymentIntent,
    });
  } catch (error) {
    console.error('Error creating payment intent:', error);
    res.status(500).json({
      success: false,
      message: 'Payment processing failed',
      error: error.message,
    });
  }
});

async function saveCustomerAndChargeToData(customerData, paymentIntent) {
  // Example: Insert customer and charge data into MySQL database
  const query = 'INSERT INTO details (customer_id, product_name, address_line1, customer_city, customer_state, customer_postalcode) VALUES (?, ?, ?, ?, ?, ?)';
  const values = [customerData.customer_id, customerData.product_name, customerData.address_line1, customerData.customer_city, customerData.customer_state, customerData.customer_postalcode];

  return new Promise((resolve, reject) => {
    db.query(query, values, (err, result) => {
      if (err) {
        console.error('Error saving payment to database:', err);
        reject(err);
      } else {
        console.log('Payment saved to database:', result);
        resolve(result);
      }
    });
  });
}


app.post('/processPayment', async (req, res) => {
  const { token, product } = req.body;

  try {
    // Create or retrieve Stripe customer
    const customer = await stripe.customers.create({
      email: token.email,
      source: token.id,
    });

    // Create a charge for the customer
    const charge = await stripe.charges.create({
      amount: product.price * 100, // amount in cents
      currency: 'usd',
      customer: customer.id,
      description: `Charge for ${product.name}`,
    });

    // Store customer information and charge details in SQL database
    const customerData = {
      stripe_customer_id: customer.id,
      email: token.email,
      address: token.card.address_line1,
      country: token.card.address_country,
    };

    await saveCustomerAndChargeToDatabase(customerData, charge);

    // Respond with success message or relevant data
    res.status(200).json({ message: 'Payment successful', charge });
  } catch (error) {
    console.error('Error processing payment:', error);
    res.status(500).json({ error: 'An error occurred while processing payment' });
  }
});

async function saveCustomerAndChargeToDatabase(customerData, charge) {
  // Example: Insert customer and charge data into MySQL database
  const query = 'INSERT INTO payments (customer_id, email, amount, currency, description) VALUES (?, ?, ?, ?, ?)';
  const values = [customerData.stripe_customer_id, customerData.email, charge.amount / 100, charge.currency.toUpperCase(), charge.description];

  return new Promise((resolve, reject) => {
    db.query(query, values, (err, result) => {
      if (err) {
        console.error('Error saving payment to database:', err);
        reject(err);
      } else {
        console.log('Payment saved to database:', result);
        resolve(result);
      }
    });
  });
}


app.get('/complete', (req, res) => {
  res.send('Your Payment is completed')
})

app.get('/cancel', (req, res) => {
  res.redirect('/')
})

// testing 2




// Error handling function
const handleError = (res, error, message = "Error occured") => {
  console.error(error),
    res.status(500).json({ message });
}

// Broker 

app.post('/api/brokers/create-charter', (req, res) => {

  const { broker_id, client_id, operator_id, start_location, end_location, start_time, end_time } = req.body;


  const charterQuery = `INSERT INTO charters (broker_id, client_id, operator_id, start_location, end_location, start_time, end_time, status) VALUES ( ?, ?, ?, ?, ?, ?, ?, 'scheduled')`;
  db.query(charterQuery, [broker_id, client_id, operator_id, start_location, end_location, start_time, end_time], (err, results) => {
    if (err) return handleError(res, err, 'Error creating Charter');
    res.status(201).json({ charter_id: results.insertId });
  });


});

// Client Apis

// Booking charter
app.post('/api/clients/book-charter', (req, res) => {
  const { client_id, charter_id } = req.body;
  const bookQuery = `UPDATE charters SET client_id = ? WHERE charter_id = ? AND client_id IS NULL`;
  db.query(bookQuery, [client_id, charter_id], (err, results) => {
    if (err) return handleError(res, err, 'Error Booking charter');
    if (results.affectedRows === 0) {
      return res.status(400).json({ message: 'charter is already booked' });
    }
    res.status(200).json({ message: 'CharterBooked successfully' });
  });
});


// Get Client ALready Booking charter Fetched!

app.get('/api/clients/my-bookings/:clientId', (req, res) => {
  const { clientId } = req.params;
  const bookingQuery = `SELECT * FROM charters WHERE client_id = ?`;
  db.query(bookingQuery, [clientId], (err, results) => {
    if (err) return handleError(res, err,);
    res.json(results.map(row => ({ broker_id: row.broker_id })));
  });
});

// Operator
app.put('/api/operators/update-charter/:charter_id', (req, res) => {
  const { charter_id, status } = req.body;

  const updateQuery = `UPDATE charters SET status = ? WHERE charter_id = ?`;
  db.query(updateQuery, [status, charter_id], (err, results) => {
    if (err) return handleError(res, err, 'Error Updating charter status');
    if (results.affectedRows === 0) {
      return res.status(400).json({ message: 'Charter not found' });
    }
    res.status(200).json({ message: 'Charter Status Update Succesfully.' });
  });
});


app.get('/api/operators/my-charters/:operator_id', (req, res) => {
  const { operator_id } = req.params;
  const operatorchartersquery = `SELECT *  FROM charters WHERE operator_id = ?`;
  db.query(operatorchartersquery, [operator_id], (err, results) => {
    if (err) return handleError(res, err);
    res.json(results);
  });
});

app.post('/api/create-user', (req, res) => {
  const { username, password, } = req.body;
  const userid = uuidv4();

  const addUser = `INSERT INTO users (username, password, userid) VALUES ( ?, ?, ? )`;
  if (!password || !username) {
    return handleError(res, null, `Please fill in all fields`);
  } else {
    db.query(addUser, [username, password, userid], (err, results) => {
      if (err && err.code === 'ER_DUP_ENTRY') {
        return handleError(res, err, ` userDuplicatname ${err}`);
      } else if (err) {
        return handleError(res, err, `Error creating new user`);
      } else {
        res.status(201).json({ userid });
      }

    });
  }

});
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const loginquery = `SELECT * FROM users WHERE username = ? AND password = ? `;
  db.query(loginquery, [username, password], (err, results) => {
    if (err) return handleError(res, err, 'Failed Login');
    if (results.length > 0) {
      const userid = results[0].userid;
      // Create JSON Token!
      const token = jwt.sign({
        userid,
        username,
      },
        secretKey,
        {
          expiresIn: '1h'
        }
      );

      // Set token as an Http-only Cookie
      res.cookie('token', token, {
        httpOnly: true, // Accessible only the web server
        secure: process.env.NODE_ENV === 'production', // set to true in production for Https
        maxAge: 3600000, // 1 hour in milliseconds
      });



      // Assuming 'userid' is a column in the database
      res.status(200).json({ username, userid, token }); // Send userid in the response
    } else {
      res.status(401).json({ message: 'Invalid credentials' }); // If no matching user is found
    }
  });
});

app.get('/api/details/:username', (req, res) => {
  const { username } = req.params;
  const findingquery = `SELECT * FROM users WHERE userid = ?`;

  db.query(findingquery, [username], (err, results) => {
    if (err) return handleError(res, err, `Error occured During Fetching`);
    if (results.length > 0) {
      const userid = results[0].userid;
      res.status(200).json({ userid });
    } else {
      res.status(401).json({ message: 'userNot Found' });
    }
  });

});

// Cookie Protected Login With Flutter
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer Token

  if (!token) return res.status(401).json({ message: 'No token, authorization denied' });
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      console.error("Jwt verification error:", err.message);
      return res.status(403).json({
        message: 'Token is invalid '
      });
    }
    req.user = decoded;
    next();
  });
}

app.get('/api/protected', authenticateToken, (req, res) => {
  try {
    // Simulate some operation
    res.status(200).json({ message: 'Access granted', user: req.user });
  } catch (error) {
    console.error("Error:", error.message);
    res.status(500).json({ message: 'Internal Server Error', error: error.message });
  }
});


// Web Sockets !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

// Setup Websockets

const wss = new websocket.Server({
  noServer: true
});

wss.on("connection", (ws) => {
  console.log('client connected');
  ws.send(JSON.stringify({ message: 'Welcome!' }));

  ws.on('message', (message) => {
    try {
      // Assuming data is json String
      const { userid,  content } = JSON.parse(message);
      
      // if Object is empty of message
      if (!userid || !content ) {
        ws.send(JSON.stringify({
           error: 'Missing userid or message content'
        }));
        return;
      }
      
      //check if the user exist or not
      db.query('SELECT userid FROM users WHERE userid = ?', [userid], (err, results) => {
        if(err) {
          ws.send(JSON.stringify({ error: 'Database error'}));
          return;
        }
        if(results.length === 0) {
          ws.send(JSON.stringify({ error: 'User not Found'}));
          return;
        }

        // if the user is exists, insert the message in database

        db.query('INSERT INTO messages (user_id, content) VALUES (?, ?)', [userid, content], (err) => {
          if(err) {
            ws.send(JSON.stringify({ error: 'Failed to save message'}));
            return;
          }

          ws.send(JSON.stringify({ success: "Message saved succesffully "}));
          console.log('Message Successfully Saved');
          ws.send(JSON.stringify({
            success: 'Message Saved succesfully',
            message: content //Include content of the message
          }));
      

        });

      });
    } catch(e) {
      ws.send(JSON.stringify({ error: 'Invalid message format' }));
    }
});


// Broadcast message to all clients

wss.clients.forEach((client) => {
  if (client.readyState === websocket.open) {
    client.send(message);
  }
});
ws.on('close', () => {
  console.log('CLient DIscounted');
})

});

//Creating new server for fetch old message, new message and clients connected channels connection

const wsss = new websocket.Server(
  { port: 8080}
);

wsss.on('connection', (ws) => {
  console.log("Client Connected Server Port 8080");

  // Step 1: Fetch the old message from database (SQL) when a new client connects
  db.query('SELECT * FROM messages ORDER BY timestamp DESC LIMIT 10', (err, results) => {
    if(err) {
      ws.send(JSON.stringify({ error: 'Failed to feteched the messages'}));
      return;
    }
    ws.send(JSON.stringify({type: 'oldMessages', messages: results}));

    console.log(results);
  
  });

  // Step 2 handle incoming messages and broadcast to all clients
  ws.on('message', (message) => {
    const parsedData = JSON.parse(message);
    const { user_id, content, timestamp } = parsedData;
    

    if(!user_id || !content) {
      ws.send(JSON.stringify({ error: "Missing userid or content "}));
      return;
    }

    db.query('INSERT INTO messages (user_id, content, timestamp) VALUES (?, ?, ?)', [user_id, content, timestamp], (err, results) => {
      if(err) {
        ws.send(JSON.stringify({ error: 'Failed to save message'}));
      }
      const newMessage = {
        user_id: user_id,
        content: content,
        timestamp: timestamp,
      }
      console.log(newMessage['timestamp']);
      // BroadCast the new message to all connected clients

      wsss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({ type: 'newMessages', message: newMessage}));
        }
      });
    });

  });
});


//~~~~!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Adding Image  Multer Functionilty


// Configure Multer Storage

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); //Directory where files will be saved
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({storage: storage});

// ENDPOINT to handle image upload 

app.post('/upload', upload.single('image'), (req, res ) => {
  const imagePath = req.file.path;

  // Save image path to sql database
  const sql = 'INSERT INTO images (path) VALUES (?)';
  db.query(sql, [imagePath], (err, result) => {
    if(err) {
      return res.status(500).json({message : 'Database Error'});
    }
    res.json({message: 'Image uploaded and Saved Database', imagePath});
  }); 
});







/// Retiver the Image from Backend to frontend

app.get('/image/:id', (req, res) => {
  const imageId = req.params.id;
  
  // Query to database to fetch the image
  db.query('SELECT path FROM images WHERE id = ?', [imageId] , (err, results) => {
    if(err) {
      return res.status(500).send('Database Error');
    }
    if(results.length === 0) {
      return res.status(404).send('ID not found');
    }
    const imagePath = results[0].path;
    const imageFilePath = path.join(__dirname, imagePath);

    // Check if file exists

    fs.exists(imageFilePath, (exists) => {
      if(exists) {
        res.sendFile(imageFilePath);
      } else {
        res.status(404).send('Image file not found');
      }
    });
  });
});









//////////////////////////////// END///////////////







const server = app.listen(3600, () => console.log(`Server started on port 3600`));

server.on('upgrade', (req, socket, head) => {
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});
