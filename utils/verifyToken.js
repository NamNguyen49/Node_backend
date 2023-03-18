import jwt from 'jsonwebtoken'


export const verifyToken = (req, res, next) => {
    const token = req.cookies.accessToken

    // if (!token) {
    //     console.log(token)
    //     return res.status(401).json({ success: false, message: 'You are not authorize' })

    // }

    // if token is exits then verify the token
    jwt.verify(token, 'your_serect', (err, user) => {
        if (err) {
            return res.status(401).json({ success: false, message: 'token is invalid' })

        }

        req.user = user
        next()
    })
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