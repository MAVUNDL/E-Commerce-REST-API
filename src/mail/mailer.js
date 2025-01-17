// Import the Nodemailer library
const nodemailer = require('nodemailer');

require('dotenv').config({ path: require('find-config')('.env') });


// Create a transporter object
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_SERVER,
  port: process.env.SMTP_PORT,
  secure: false, // use false for STARTTLS; true for SSL on port 465
  auth: {
    user: process.env.SMTP_EMAIL,
    pass: process.env.SMTP_PASSWORD,
  }
});

module.exports = transporter