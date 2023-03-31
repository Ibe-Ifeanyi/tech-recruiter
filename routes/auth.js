const express = require("express");
const {
	register,
	login,
	logout,
	verifyEmail,
	forgotPassword,
	resetPassword,
} = require("../controllers/authController");

const router = express.Router();

router.post("/", register);
router.post("/login", login);
router.get("/logout", logout);
router.put("/verify-email", verifyEmail);
router.put("/forgot-password/:email", forgotPassword);
router.put("/reset-password", resetPassword);

module.exports = router;
