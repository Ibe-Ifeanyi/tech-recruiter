exports.logger = (req, res, next) => {
	console.log(req.headers);
	next();
};
