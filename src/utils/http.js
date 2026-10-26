export const fail = (res, status, message, extra = {}) => res.status(status).json({ message, ...extra });
