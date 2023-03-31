const nodemailer = require("nodemailer");
const mailTransporter = nodemailer.createTransport({
	service: "gmail",
	auth: {
		user: process.env.EMAIL_ADDRESS,
		pass: process.env.EMAIL_PASSWORD,
	},
});

const sendEmail = ({ to, subject, text, html }) => {
	const msg = { to, from: process.env.EMAIL_ADDRESS, subject, text, html };
	return mailTransporter.sendMail(msg);
};

module.exports = sendEmail;
