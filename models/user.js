const mongoose = require("mongoose");
const Joi = require("joi");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const bcrypt = require("bcrypt");
require("dotenv").config();

const UserSchema = new mongoose.Schema({
	firstName: {
		type: String,
		trim: true,
		required: [true, "Please provide first name"],
		minlength: 3,
		maxlength: 50,
	},
	lastName: {
		type: String,
		trim: true,
		required: [true, "Please provide last name"],
		minlength: 3,
		maxlength: 50,
	},
	email: {
		type: String,
		unique: true,
		required: [true, "Please provide email"],
		validate: {
			validator: validator.isEmail,
			message: "Please provide valid email",
		},
	},
	password: {
		type: String,
		required: [true, "Please provide password"],
		minlength: 8,
		maxlength: 255,
	},
	passwordResetCode: {
		type: String,
		default: null,
	},
	role: {
		type: String,
		enum: ["admin", "user", "employer"],
		default: "user",
	},
	isVerified: {
		type: Boolean,
		default: false,
	},
	verificationString: String,
});

UserSchema.pre("save", async function () {
	if (!this.isModified("password")) return;
	const salt = await bcrypt.genSalt(10);
	this.password = await bcrypt.hash(this.password, salt);
});

UserSchema.methods.generateToken = function () {
	return jwt.sign(
		{
			_id: this._id,
			firstName: this.firstName,
			lastName: this.lastName,
			role: this.role,
		},
		process.env.JWT_SECRET,
		{ expiresIn: process.env.JWT_LIFETIME }
	);
};

UserSchema.methods.comparePassword = async function (userPassword) {
	const isMatch = await bcrypt.compare(userPassword, this.password);
	return isMatch;
};

const validateUser = (user) => {
	const schema = Joi.object({
		firstName: Joi.string().min(3).max(50).required(),
		lastName: Joi.string().min(3).max(50).required(),
		email: Joi.string().email(),
		password: Joi.string().min(8).max(255).required(),
	});

	return schema.validate(user);
};

exports.User = mongoose.model("User", UserSchema);
exports.validate = validateUser;
