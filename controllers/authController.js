const { User, validate } = require("../models/user");
const { StatusCodes } = require("http-status-codes");
const ObjectId = require("mongoose").Types.ObjectId;
const jwt = require("jsonwebtoken");
const { v4: uuid } = require("uuid");
const bcrypt = require("bcrypt");
const CustomError = require("../errors");
const { FRONTEND_URL } = process.env;
const uploader = require("../utils/uploadImage");
const getGoogleOauthUrl = require("../utils/getGoogleOauthUrl");

const {
	attachCookiesToResponse,
	createTokenUser,
	sendEmail,
} = require("../utils");

const register = async (req, res) => {
	const { email, firstName, lastName, password } = req.body;

	const { error } = validate(req.body);
	if (error) return res.status(400).send(error.details[0].message);

	const emailAlreadyExists = await User.findOne({ email });
	if (emailAlreadyExists) {
		throw new CustomError.BadRequestError("Email already exists");
	}

	// first registered user is an admin
	const isFirstAccount = (await User.countDocuments({})) === 0;
	const role = isFirstAccount ? "admin" : req.body.role;
	const verificationString = uuid();

	const user = await User.create({
		firstName,
		lastName,
		email,
		password,
		verificationString,
		role,
	});

	if (user) {
		try {
			await sendEmail({
				to: email,
				subject: "Email Verification",
				html: `<p>Hi, ${user.firstName}!</p> 
				<p>Thank you for signing up on TechRecruitr.
				Click <a href="${FRONTEND_URL}/verify-email/${verificationString}">here</a> to verify your 
				email </p> 
				<p>Kind regards,</p>
				<p>TechRecruitr team</p>`,
			});
		} catch (error) {
			console.log(error);
			res.sendStatus(500);
		}
	}

	const tokenUser = createTokenUser(user);
	const token = user.generateToken();
	attachCookiesToResponse(res, token);
	res.status(StatusCodes.CREATED).json({ user: tokenUser });
};

const login = async (req, res) => {
	const { email, password } = req.body;

	if (!email || !password) {
		throw new CustomError.BadRequestError(
			"Please provide email and password"
		);
	}
	const user = await User.findOne({ email });

	if (!user) {
		throw new CustomError.UnauthenticatedError("Invalid Credentials");
	}
	const isPasswordCorrect = await user.comparePassword(password);
	if (!isPasswordCorrect) {
		throw new CustomError.UnauthenticatedError("Invalid Credentials");
	}
	const tokenUser = createTokenUser(user);
	const token = user.generateToken();
	//attachCookiesToResponse(res, token);

	res.status(StatusCodes.OK).send({
		success: true,
		message: "Login successful!",
		user: tokenUser,
		token,
	});
};

const logout = async (req, res) => {
	res.cookie("token", "logout", {
		httpOnly: true,
		expires: new Date(Date.now() + 1000),
	});
	res.status(StatusCodes.OK).json({ msg: "User logged out!" });
};

const verifyEmail = async (req, res) => {
	const { verificationString } = req.body;

	const user = await User.findOne({ verificationString });

	if (!user)
		return res.status(401).json({ message: "Invalid verification code." });

	const { _id: id, email } = user;

	await User.updateOne({ _id: ObjectId(id) }, { $set: { isVerified: true } });

	const tokenUser = createTokenUser(user);

	jwt.sign(
		{ id, email, isVerified: true },
		process.env.JWT_SECRET,
		{ expiresIn: "2d" },
		(error, token) => {
			if (error) return res.sendStatus(500);

			res.status(200).json({ token, user: tokenUser });
		}
	);
};

const forgotPassword = async (req, res) => {
	const { email } = req.params;
	const passwordResetCode = uuid();

	const result = await User.updateOne(
		{ email },
		{
			$set: { passwordResetCode },
		},
		{ new: true }
	);

	if (result.modifiedCount > 0) {
		try {
			await sendEmail({
				to: email,
				subject: "Reset Password",
				html: `<p>Hi,</p> 
				<p>
				Click <a href="${FRONTEND_URL}/reset-password/${passwordResetCode}">here</a> to reset your 
				password. </p> 
				<p>Kind regards,</p>
				<p>TechRecruitr team</p>`,
			});
		} catch (error) {
			console.log(error);
			res.sendStatus(500);
		}
	}

	res.sendStatus(200);
};

const uploadImage = async (req, res) => {
	const { image, userId } = req.body;
	try {
		const url = await uploader(image);

		await User.updateOne(
			{ _id: ObjectId(userId) },
			{ $set: { imageUrl: url } },
			{ new: true }
		);

		res.send(url);
	} catch (err) {
		res.status(500).send(err.message);
	}
};

const resetPassword = async (req, res) => {
	const { password, passwordResetCode } = req.body;

	const user = User.findOne({ passwordResetCode });

	if (!user) return res.status(400).send("Invalid reset token");

	const salt = await bcrypt.genSalt(10);
	hashedPassword = await bcrypt.hash(password, salt);

	await User.updateOne(
		{ passwordResetCode },
		{ $set: { password: hashedPassword } }
	);

	res.sendStatus(200);
};

const getOauthUrl = async (req, res) => {
	const url = getGoogleOauthUrl();
	res.status(200).json({ url });
};

module.exports = {
	register,
	login,
	logout,
	verifyEmail,
	forgotPassword,
	resetPassword,
	uploadImage,
	getOauthUrl,
};
