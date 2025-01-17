const bcrypt = require('bcrypt');
const db = require("../models/db"); 
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const transporter = require("../mail/mailer");
const { error } = require('console');

// signup user
const signUp = async (req, res) => {
    // get infor from the request body
    const {name, email, password} = req.body;

    // add user to the database
    try{
        // hash the password
        const hashPassword = await bcrypt.hash(password, 10);

        // Generate a verification token
        const verificationToken = jwt.sign(
            { email }, // Payload
            process.env.JWT_SECRET, // Secret key
            { expiresIn: "1h" } // Expiry
        );

        // check first if email exits
        const checkEmailResults = await db.query(
            'SELECT * FROM users where email = $1',
            [email]
        );

        if(checkEmailResults.rows.length !== 0){
            return res.status(400).json({error: 'Email already exists'});
        }
        
        // send query to database
        const results = await db.query(
            'INSERT INTO users (name, email, password_hash, verification_token) VALUES ($1, $2, $3, $4) RETURNING *',
             [name, email, hashPassword, verificationToken]
        );

        // using email for auth
        const verificationLink = `http://localhost:5000/api/verify-email/${verificationToken}`;
;
        // smtp syntax
        const mailOptions = {
            from: process.env.EMAIL_SENDER,
            to: email,
            subject: 'Verify Your Email Address',
            text: `Please verify your email by clicking the following link: ${verificationLink}`,
            html: `<p>Please verify your email by clicking the link below:</p><a href="${verificationLink}">${verificationLink}</a>`,
        };

        // send email
        await transporter.sendMail(mailOptions);

        // check status
        res.status(201).json({ 
            message: 'User registration successful. Please verify your email.', 
            user: results.rows[0] 
        });

    } catch(error){
        console.error(error);
        res.status(500).json({error: 'Error could not register user'});
    }
};

const verifyEmail = async (req, res) => {
    const { token } = req.params;

    try {
        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Find the user in the database
        const results = await db.query(
            'SELECT * FROM users WHERE email = $1',
            [decoded.email]
        );

        if (results.rows.length === 0) {
            return res.status(400).json({ error: 'User not found' });
        }

        // Update the user's verification status
        await db.query(
            'UPDATE users SET is_verified = $1 WHERE email = $2',
            [true, decoded.email]
        );

        res.status(200).send('Email verified');
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(400).json({ error: 'Token has expired' });
        }
        res.status(400).json({ error: 'Invalid or expired token' });
    }
};


// SignIn user
const signIn = async (req, res) => {
    const { email, password } = req.body;

    try {
        // Query the user from the database
        const results = await db.query('SELECT * FROM users WHERE email = $1', [email]);

        if (results.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const user = results.rows[0];

        // Verify the password
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);

        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Incorrect password' });
        }

        // Generate access and refresh tokens
        const accessToken = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        const refreshToken = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: '7d' } // Refresh token valid for 7 days
        );

        // Save refresh token to database
        await db.query(
            'UPDATE users SET refresh_token = $1 WHERE id = $2',
            [refreshToken, user.id]
        );

        // Send response
        res.json({
            accessToken,
            refreshToken,
            user: { id: user.id, name: user.name, email: user.email }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Could not authenticate user' });
    }
};

const checkVerification = async (req, res) => {
    // destructuring
    const { email } = req.params;
    // send query
    try{
        const response = await db.query('SELECT is_verified FROM users WHERE email = $1', [email]);
        if(response.rows.length > 0){
            res.status(200).json({verified: response.rows[0].is_verified});
        } else{
            res.status(404).json({error: 'user not found'});
        }
    } catch(error){
        res.status(500).json({error: 'Internal server error'});
    }
};

const resetPassword = async (req, res) => {
    const { email } = req.body;

    try {
        // Check if the email exists
        const checkEmailResults = await db.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (checkEmailResults.rows.length === 0) {
            return res.status(400).json({ message: 'User not registered' });
        }

        // Get user data
        const user = checkEmailResults.rows[0];

        // Generate OTP (4-digit)
        const generateOTP = () => {
            return Math.floor(1000 + Math.random() * 9000).toString(); // 4-digit OTP
        };

        // Create OTP and set the creation and expiration timestamps
        const otp = generateOTP();
        const otpExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes expiry

        // Update OTP in the database with creation and expiry times
        const response = await db.query(
            'UPDATE users SET forgot_pass_otp = $1, otp_created_at = CURRENT_TIMESTAMP, otp_expiry = $2 WHERE email = $3',
            [otp, otpExpiry, email]
        );

        // Send OTP to the user's email
        const mailOptions = {
            from: process.env.EMAIL_SENDER,
            to: email,
            subject: 'Reset Password OTP',
            text: `Here is your OTP: ${otp}`,
            html: `<p>Please submit this OTP on the App to reset your password: <b>${otp}</b>. This expires in ${otpExpiry}. </p>`,
        };

        // Send email
        await transporter.sendMail(mailOptions);

        // Response after sending OTP
        res.status(201).json({
            message: 'Password reset initiated. Please check your email.',
            user: response.rows[0],
        });

    } catch (error) {
        res.status(500).json({ message: `${error}` });
    }
};


const verifyOTP = async (req, res) => {
    const { email, forgot_pass_otp } = req.body;

    try {
        // Get the OTP, created time, and expiry time from the database
        const response = await db.query(
            'SELECT forgot_pass_otp, otp_expiry FROM users WHERE email = $1',
            [email]
        );

        if (response.rows.length === 0) {
            return res.status(400).json({ message: 'Email not found' });
        }

        const storedOtp = response.rows[0].forgot_pass_otp;
        const otpExpiry = new Date(response.rows[0].otp_expiry);

        // Check if the OTP matches
        if (storedOtp !== forgot_pass_otp) {
            return res.status(400).json({ message: 'OTP is incorrect' });
        }

        // Check if OTP has expired
        if (Date.now() > otpExpiry.getTime()) {
            return res.status(400).json({ message: 'OTP has expired' });
        }

        // OTP is valid and not expired
        res.status(200).json({ message: 'OTP is valid' });

    } catch (error) {
        res.status(500).json({ message: `${error}` });
    }
};

const set_new_password = async (req, res) => {
    const { email, password } = req.body;

    try {
         // hash the password
         const hashPassword = await bcrypt.hash(password, 10);

        // update password in database
        const response = await db.query(
            ' UPDATE users SET password_hash = $1 WHERE email = $2',
            [hashPassword, email]
        );

        // OTP is valid and not expired
        res.status(200).json({ message: 'Password reset complete' });

    } catch (error) {
        res.status(500).json({ message: `${error}` });
    }
};


const RefreshToken = async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(401).json({ error: 'Refresh token required' });
    }

    try {
        // Verify the refresh token
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        // Check if refresh token matches the one in the database
        const results = await db.query(
            'SELECT * FROM users WHERE id = $1 AND refresh_token = $2',
            [decoded.id, refreshToken]
        );

        if (results.rows.length === 0) {
            return res.status(403).json({ error: 'Invalid refresh token' });
        }

        const user = results.rows[0];

        // Generate a new access token
        const newAccessToken = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ accessToken: newAccessToken });
    } catch (error) {
        console.error(error);
        res.status(403).json({ error: 'Invalid or expired refresh token' });
    }
};

const getAllProducts = async (req, res) => {
    // send query to get all the products
    try{
        // get all and label by brand
        const query = `
        SELECT id, product_name, price, image_url, 'Dell' AS brand 
        FROM dell_products
        UNION
        SELECT id, product_name, price, image_url, 'Lenovo' AS brand
        FROM lenovo_products`;

        const response = await db.query(query);
        // return results
        res.status(200).json(response.rows);

    } catch(error){
        res.status(500).json({message: error});
    }
}

const getIndividualProduct = async (req, res) => {
    // destructuring
    const { brand, id } = req.params;
    // get the product by id but first get which brand are we referring to.
    try {
        let query;
        if (brand === 'Dell') {
            query = `
                SELECT * 
                FROM dell_products_details
                WHERE dell_product_id = $1;
            `;
        } else if (brand === 'Lenovo') {
            query = `
                SELECT * 
                FROM lenovo_product_details
                WHERE lenovo_product_id = $1;
            `;
        } else {
            return res.status(400).json({ error: 'Invalid brand' });
        }
        
        // send query
        const result = await db.query(query, [id]);
        // if the product is not found
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        // return the product details
        res.status(200).json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

module.exports = {signUp, signIn, verifyEmail, RefreshToken, checkVerification, resetPassword, verifyOTP, set_new_password, getAllProducts, getIndividualProduct};