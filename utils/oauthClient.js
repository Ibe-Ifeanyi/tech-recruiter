const { google } = require("googleapis");

const oauthClient = new google.auth.OAuth2(
	process.env.GOOGLE_CLIENT_ID,
	process.env.GOOGLE_CLIENT_SECRET,
	"http://localhost:8080/auth/google/callback"
);

module.exports = oauthClient;
