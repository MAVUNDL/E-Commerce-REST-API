const express = require('express');
const {signUp, signIn, verifyEmail, RefreshToken, checkVerification, resetPassword, verifyOTP, set_new_password, getAllProducts, getIndividualProduct} = require('../controllers/authController');

// access the expo router
const router = express.Router();

// get endpoints
router.get("/verify-email/:token", verifyEmail);
router.get("/check-verification/:email", checkVerification);
router.get("/get-all-products", getAllProducts);
router.get("/get-product/:brand/:id", getIndividualProduct);

// post end points
router.post("/signUp", signUp);
router.post("/signIn", signIn);
router.post("/refresh-token", RefreshToken);
router.post("/resetPassword", resetPassword);
router.post("/verify-OTP", verifyOTP)
router.post("/set-new-password", set_new_password);

module.exports = router;
