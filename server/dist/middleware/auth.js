import jwt from 'jsonwebtoken';
export const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null)
        return res.sendStatus(401);
    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, user) => {
        console.log(err, user);
        if (err || !user) {
            return res.sendStatus(403);
        }
        req.user = user;
        return next();
    });
    return;
};
