const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const router = express.Router();
const cors = require('cors');
const db = require('../db');
const { v4: uuidv4 } = require('uuid'); // Import UUID generator
const { decrypt } = require('dotenv');

// create a nodemailer transporter


const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    }

});

// Register User,

router.post('/auth/register', async (req, res) => {
    const {name, email, password, role, loyalty_points, miles } = req.body;
    
    //check if the user Existed!
    const [Existeduser] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);

    if(Existeduser.length > 0) {
        return res.status(400).json({message: 'Email already Register'});
    }

    // password converting in hash form
    const hashPassword = await bcrypt.hash(password,10);

    // Generate UUID
    const user_id = uuidv4();

    // insert new user into Database;

    await db.promise().query('INSERT INTO users (user_id, name, email, password, role, loyalty_points, miles) VALUES (?, ?, ?, ?, ?, ?, ?)', [user_id, name, email, hashPassword, role, loyalty_points, miles ]);

    return res.status(201).json({ message: 'User registered successfully', user_id });

});

router.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    
    // fetched user from database
    const [user] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);

    if(user.length === 0) {
        return res.status(401).json({message : "User not found"});
    }
    //compare hashed password 

    const isMatch = await bcrypt.compare(password, user[0].password);
    if(!isMatch) {
        return res.status(401).json({message: 'Invaild Credential'});
    }

    const token = jwt.sign({ id: user[0].user_id, email: user[0].email,  }, 'f69e26a1ac85976ac3edd06e060cf08aeda71c9d13b8a494acbb97393dd0306d' , { expiresIn: '1h'});
    res.status(201).json({success: true, token});
});

module.exports = router; // Export the router
