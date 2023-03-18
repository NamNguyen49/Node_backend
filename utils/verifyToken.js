import jwt from 'jsonwebtoken'


export const verifyToken = (req, res, next) => {
    const authHeader = req.header('Authorization')
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token not found' })
    }

    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET || 'your_secret')

        req.userId = decoded.userId
        next()
    } catch (error) {
        console.log(error)
        return res.status(403).json({ success: false, message: 'Invalid token' })
    }
}


export const verifyUser = (req, res, next) => {
    verifyToken(req, res, next, () => {
        if (req.user.id === req.params.id || req.user.role === 'admin') {
            next()
        } else {
            return res.status(401).json({ success: false, message: 'You are not authenticated' })

        }
    })
}
export const verifyAdmin = (req, res, next) => {
    verifyToken(req, res, next, () => {
        if (req.user.role === 'admin') {
            next()
        } else {
            return res.status(401).json({ success: false, message: 'You are not authorize' })

        }
    })
}